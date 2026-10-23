//! Public Client/RelayConn contract against an owned loopback TURN service.
use async_trait::async_trait;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::net::UdpSocket;
use turn::{
    auth::{generate_auth_key, AuthHandler},
    client::{Client, ClientConfig},
    relay::relay_static::RelayAddressGeneratorStatic,
    server::{
        config::{ConnConfig, ServerConfig},
        Server,
    },
};
use util::{vnet::net::Net, Conn};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

struct OwnedAuth;
impl AuthHandler for OwnedAuth {
    fn auth_handle(&self, user: &str, realm: &str, _: SocketAddr) -> Result<Vec<u8>, turn::Error> {
        Ok(generate_auth_key(user, realm, "owned-loopback-test"))
    }
}

struct TraceSocket {
    inner: UdpSocket,
    indications: AtomicUsize,
    channels: AtomicUsize,
}

#[async_trait]
impl Conn for TraceSocket {
    async fn connect(&self, peer: SocketAddr) -> util::Result<()> {
        Ok(self.inner.connect(peer).await?)
    }
    async fn recv(&self, bytes: &mut [u8]) -> util::Result<usize> {
        Ok(self.inner.recv(bytes).await?)
    }
    async fn recv_from(&self, bytes: &mut [u8]) -> util::Result<(usize, SocketAddr)> {
        Ok(self.inner.recv_from(bytes).await?)
    }
    async fn send(&self, bytes: &[u8]) -> util::Result<usize> {
        Ok(self.inner.send(bytes).await?)
    }
    async fn send_to(&self, bytes: &[u8], peer: SocketAddr) -> util::Result<usize> {
        if bytes.starts_with(&[0x00, 0x16]) {
            self.indications.fetch_add(1, Ordering::SeqCst);
        } else if bytes
            .first()
            .is_some_and(|value| (0x40..=0x7f).contains(value))
        {
            self.channels.fetch_add(1, Ordering::SeqCst);
        }
        Ok(self.inner.send_to(bytes, peer).await?)
    }
    fn local_addr(&self) -> util::Result<SocketAddr> {
        Ok(self.inner.local_addr()?)
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr().ok()
    }
    async fn close(&self) -> util::Result<()> {
        Ok(())
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[tokio::test]
async fn public_relay_contract_payload_length_and_bidirectional_data() -> TestResult {
    tokio::time::timeout(Duration::from_secs(12), async {
        let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let server_address = server_socket.local_addr()?;
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn: server_socket,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    address: "127.0.0.1".into(),
                    net: Arc::new(Net::new(None)),
                }),
            }],
            realm: "owned-loopback-test".into(),
            auth_handler: Arc::new(OwnedAuth),
            channel_bind_timeout: Duration::from_secs(600),
            alloc_close_notify: None,
        })
        .await?;
        let socket = Arc::new(TraceSocket {
            inner: UdpSocket::bind("127.0.0.1:0").await?,
            indications: AtomicUsize::new(0),
            channels: AtomicUsize::new(0),
        });
        let client = Client::new(ClientConfig {
            stun_serv_addr: server_address.to_string(),
            turn_serv_addr: server_address.to_string(),
            username: "owned-loopback-test".into(),
            password: "owned-loopback-test".into(),
            realm: String::new(),
            software: "public-contract-regression".into(),
            rto_in_ms: 100,
            conn: socket.clone(),
            vnet: None,
        })
        .await?;
        client.listen().await?;
        let allocation = client.allocate().await?;
        let relay_address = allocation.local_addr()?;
        let peer = UdpSocket::bind("127.0.0.1:0").await?;
        let peer_address = peer.local_addr()?;
        let mut returned = Vec::new();
        let mut received = [0; 1400];
        for payload in [vec![1, 2, 3], vec![42; 1000], vec![7; 4]] {
            let before = socket.channels.load(Ordering::SeqCst);
            let sent = allocation.send_to(&payload, peer_address).await?;
            let (length, from) =
                tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut received))
                    .await??;
            assert_eq!(from, relay_address);
            assert_eq!(&received[..length], payload);
            peer.send_to(&payload, from).await?;
            let (length, from) =
                tokio::time::timeout(Duration::from_secs(2), allocation.recv_from(&mut received))
                    .await??;
            assert_eq!(from, peer_address);
            assert_eq!(&received[..length], payload);
            returned.push((
                sent,
                payload.len(),
                socket.channels.load(Ordering::SeqCst) > before,
            ));
            // Let the actual asynchronous ChannelBind response reach the client.
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        allocation.close().await?;
        client.close().await?;
        server.close().await?;
        assert!(socket.indications.load(Ordering::SeqCst) >= 1);
        assert!(socket.channels.load(Ordering::SeqCst) >= 1);
        assert!(
            returned
                .iter()
                .all(|(written, payload, _)| written == payload),
            "public RelayConn returned wire length: {returned:?}"
        );
        assert!(!returned[0].2 && returned.iter().any(|entry| entry.2));
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}
