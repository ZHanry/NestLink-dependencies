//! Contract tests for the actual TURN 0.11 path used by WebRTC ICE.
use super::*;
use std::sync::Mutex as StdMutex;

#[derive(Clone, Copy)]
enum WriteMode {
    Complete,
    Short,
    Zero,
    Overreported,
    OsError,
}

struct ContractObserver {
    mode: WriteMode,
    frames: Arc<StdMutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl RelayConnObserver for ContractObserver {
    fn turn_server_addr(&self) -> String {
        "127.0.0.1:3478".into()
    }
    fn username(&self) -> Username {
        Username::new(ATTR_USERNAME, "owned-contract-test".into())
    }
    fn realm(&self) -> Realm {
        Realm::new(ATTR_REALM, "owned-contract-test".into())
    }
    async fn write_to(&self, bytes: &[u8], _: &str) -> Result<usize, util::Error> {
        self.frames.lock().unwrap().push(bytes.to_vec());
        match self.mode {
            WriteMode::Complete => Ok(bytes.len()),
            WriteMode::Short => Ok(bytes.len() - 1),
            WriteMode::Zero => Ok(0),
            WriteMode::Overreported => Ok(bytes.len() + 1),
            WriteMode::OsError => Err(io::Error::from_raw_os_error(10054).into()),
        }
    }
    async fn perform_transaction(
        &mut self,
        _: &Message,
        _: &str,
        _: bool,
    ) -> Result<TransactionResult, Error> {
        Err(Error::ErrNoPermission)
    }
}

async fn contract_fixture(
    channel: bool,
    mode: WriteMode,
    permitted: bool,
) -> (
    RelayConn<ContractObserver>,
    Arc<StdMutex<Vec<Vec<u8>>>>,
    SocketAddr,
) {
    let frames = Arc::new(StdMutex::new(Vec::new()));
    let peer: SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let (_, read_ch_rx) = mpsc::channel(1);
    let binding_mgr = Arc::new(Mutex::new(BindingManager::new()));
    {
        let mut manager = binding_mgr.lock().await;
        manager.create(peer).unwrap();
        manager.get_by_addr(&peer).unwrap().set_state(if channel {
            BindingState::Ready
        } else {
            BindingState::Request
        });
    }
    let relay = RelayConn::new(
        Arc::new(Mutex::new(ContractObserver {
            mode,
            frames: frames.clone(),
        })),
        RelayConnConfig {
            relayed_addr: "127.0.0.1:40000".parse().unwrap(),
            integrity: MessageIntegrity::default(),
            nonce: Nonce::new(ATTR_NONCE, "owned-contract-test".into()),
            lifetime: Duration::from_secs(600),
            binding_mgr,
            read_ch_rx: Arc::new(Mutex::new(read_ch_rx)),
        },
    )
    .await;
    if permitted {
        let mut internal = relay.relay_conn.lock().await;
        let permission = Arc::new(Permission::default());
        permission.set_state(PermState::Permitted);
        internal.perm_map.insert(&peer, permission);
    }
    (relay, frames, peer)
}

fn typed_cause<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a (dyn std::error::Error + 'static)> {
    // These upstream tuple wrappers expose their causes through typed fields.
    // Follow the same fields as the production ICE classifier, never text.
    if let Some(value) = error.downcast_ref::<util::Error>() {
        match value {
            util::Error::Io(inner) => return Some(&inner.0),
            util::Error::Std(inner) => return Some(inner.0.as_ref()),
            _ => {}
        }
    }
    if let Some(value) = error.downcast_ref::<Error>() {
        match value {
            Error::Io(inner) => return Some(&inner.0),
            Error::Util(inner) => return Some(inner),
            _ => {}
        }
    }
    if let Some(inner) = error
        .downcast_ref::<io::Error>()
        .and_then(io::Error::get_ref)
    {
        return Some(inner);
    }
    error.source()
}

fn find_turn<'a>(error: &'a (dyn std::error::Error + 'static)) -> Option<&'a Error> {
    if let Some(value) = error.downcast_ref::<Error>() {
        return Some(value);
    }
    typed_cause(error).and_then(find_turn)
}

fn find_os_code(error: &(dyn std::error::Error + 'static)) -> Option<i32> {
    if let Some(value) = error.downcast_ref::<io::Error>() {
        if let Some(code) = value.raw_os_error() {
            return Some(code);
        }
    }
    typed_cause(error).and_then(find_os_code)
}

#[tokio::test]
async fn relay_contract_returns_payload_length_and_preserves_wire_payload() {
    for channel in [false, true] {
        let (relay, frames, peer) = contract_fixture(channel, WriteMode::Complete, true).await;
        for length in [0, 1, 3, 4, 111, 1000] {
            let payload = vec![0x5a; length];
            let count = relay.send_to(&payload, peer).await.unwrap();
            assert_eq!(
                count, length,
                "must report application bytes, channel={channel}"
            );
            let wire = frames.lock().unwrap().last().unwrap().clone();
            assert!(wire.len() > payload.len());
            if channel {
                let mut decoded = proto::chandata::ChannelData {
                    raw: wire,
                    ..Default::default()
                };
                decoded.decode().unwrap();
                assert_eq!(decoded.data, payload);
            } else {
                let mut decoded = Message {
                    raw: wire,
                    ..Default::default()
                };
                decoded.decode().unwrap();
                let mut data = proto::data::Data::default();
                data.get_from(&decoded).unwrap();
                assert_eq!(data.0, payload);
            }
        }
        relay.close().await.unwrap();
    }
}

#[tokio::test]
async fn relay_contract_rejects_incomplete_and_overreported_datagrams() {
    for channel in [false, true] {
        for mode in [WriteMode::Short, WriteMode::Zero, WriteMode::Overreported] {
            let (relay, _, peer) = contract_fixture(channel, mode, true).await;
            let result = relay.send_to(b"owned relay payload", peer).await;
            assert!(
                result.is_err(),
                "a malformed wire write cannot be successful payload delivery"
            );
            assert!(matches!(
                find_turn(&result.unwrap_err()),
                Some(Error::ErrShortWrite)
            ));
            relay.close().await.unwrap();
        }
    }
}

#[tokio::test]
async fn relay_contract_retains_protocol_and_os_error_causes() {
    for channel in [false, true] {
        let (relay, _, peer) = contract_fixture(channel, WriteMode::OsError, true).await;
        let error = relay
            .send_to(b"owned relay payload", peer)
            .await
            .unwrap_err();
        assert_eq!(find_os_code(&error), Some(10054));
        relay.close().await.unwrap();
    }
    let (relay, frames, peer) = contract_fixture(false, WriteMode::Complete, false).await;
    let error = relay
        .send_to(b"owned relay payload", peer)
        .await
        .unwrap_err();
    assert!(matches!(find_turn(&error), Some(Error::ErrNoPermission)));
    assert!(frames.lock().unwrap().is_empty());
    relay.close().await.unwrap();
}
