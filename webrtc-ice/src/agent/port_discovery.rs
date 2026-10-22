//! Bounded discovery for destination-dependent NAT mappings. Predictions are
//! outbound checks only, never signaled candidates or prevalidated ICE pairs.
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use stun::agent::TransactionId;
use stun::attributes::ATTR_USERNAME;
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::{Message, BINDING_REQUEST};
use stun::textattrs::Username;
use tokio::time::{Duration, Instant};

use super::agent_internal::AgentInternal;
use crate::candidate::candidate_base::CandidateBaseConfig;
use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::{Candidate, CandidateType};
use crate::control::{AttrControlled, AttrControlling};
use crate::network_type::NetworkType;
use crate::priority::PriorityAttr;
use crate::state::ConnectionState;
use crate::udp_network::ConnectivityEvent;

type IceCandidate = Arc<dyn Candidate + Send + Sync>;
const START_DELAY: Duration = Duration::from_millis(750);
const WINDOW: Duration = Duration::from_secs(7);
const BATCH_INTERVAL: Duration = Duration::from_millis(200);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_LOCAL_SOCKETS: usize = 6;
const MAX_PEER_IPS: usize = 2;
const MAX_PORTS_PER_IP: usize = 32;
const MAX_PROBES: usize = 384;
const BATCH_SIZE: usize = 12;
const PASSES: usize = 2;

#[derive(Clone)]
struct Probe {
    local: IceCandidate,
    remote: IceCandidate,
}

struct PendingProbe {
    id: TransactionId,
    local_id: String,
    destination: SocketAddr,
    sent: Instant,
}

pub(super) struct PortDiscovery {
    enabled: bool,
    running: bool,
    started: Option<Instant>,
    next_batch: Option<Instant>,
    plan: Vec<Probe>,
    sent: usize,
    pending: Vec<PendingProbe>,
}

impl PortDiscovery {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            running: false,
            started: None,
            next_batch: None,
            plan: Vec::new(),
            sent: 0,
            pending: Vec::new(),
        }
    }

    pub(super) fn reset(&mut self) {
        self.stop();
        self.running = self.enabled;
    }

    pub(super) fn stop(&mut self) {
        self.running = false;
        self.started = None;
        self.next_batch = None;
        self.plan.clear();
        self.pending.clear();
        self.sent = 0;
    }

    fn active(&self, now: Instant) -> bool {
        self.running
            && self
                .started
                .is_some_and(|start| now < start + START_DELAY + WINDOW)
    }

    fn batch(
        &mut self,
        now: Instant,
        mut locals: Vec<IceCandidate>,
        remotes: Vec<IceCandidate>,
    ) -> Vec<Probe> {
        if !self.running {
            return Vec::new();
        }
        locals.retain(|c| {
            c.network_type() == NetworkType::Udp4
                && c.candidate_type() == CandidateType::ServerReflexive
                && matches!(c.addr().ip(), std::net::IpAddr::V4(ip) if public_ipv4(ip))
                && c.get_conn().is_some()
        });
        locals.sort_by_key(|c| c.get_conn().and_then(|conn| conn.local_addr().ok()));
        locals.dedup_by_key(|c| c.get_conn().and_then(|conn| conn.local_addr().ok()));
        locals.truncate(MAX_LOCAL_SOCKETS);
        let mut peers = BTreeMap::<Ipv4Addr, Vec<u16>>::new();
        for remote in remotes {
            if remote.network_type() != NetworkType::Udp4
                || remote.candidate_type() != CandidateType::ServerReflexive
                || remote.port() < 1024
            {
                continue;
            }
            if let std::net::IpAddr::V4(ip) = remote.addr().ip() {
                if public_ipv4(ip) {
                    peers.entry(ip).or_default().push(remote.port());
                }
            }
        }
        if locals.is_empty() || peers.is_empty() {
            return Vec::new();
        }
        let started = *self.started.get_or_insert(now);
        if now < started + START_DELAY {
            return Vec::new();
        }
        if !self.active(now) {
            self.stop();
            return Vec::new();
        }
        if self.next_batch.is_some_and(|next| now < next) {
            return Vec::new();
        }
        if self.plan.is_empty() {
            for (ip, advertised) in peers.into_iter().take(MAX_PEER_IPS) {
                for port in neighbor_ports(&advertised) {
                    for local in &locals {
                        if let Some(remote) =
                            predicted_candidate(SocketAddr::new(ip.into(), port), local.component())
                        {
                            self.plan.push(Probe {
                                local: local.clone(),
                                remote,
                            });
                        }
                    }
                }
            }
        }
        self.next_batch = Some(now + BATCH_INTERVAL);
        let limit = MAX_PROBES.min(self.plan.len() * PASSES);
        let end = (self.sent + BATCH_SIZE).min(limit);
        let probes = (self.sent..end)
            .map(|i| self.plan[i % self.plan.len()].clone())
            .collect();
        self.sent = end;
        probes
    }

    fn register(&mut self, now: Instant, id: TransactionId, probe: &Probe) -> bool {
        if !self.active(now) {
            return false;
        }
        self.pending
            .retain(|request| now.duration_since(request.sent) < RESPONSE_TIMEOUT);
        self.pending.push(PendingProbe {
            id,
            local_id: probe.local.id(),
            destination: probe.remote.addr(),
            sent: now,
        });
        true
    }

    fn consume(
        &mut self,
        now: Instant,
        id: TransactionId,
        local_id: &str,
        source: SocketAddr,
    ) -> bool {
        if !self.active(now) {
            return false;
        }
        self.pending
            .retain(|request| now.duration_since(request.sent) < RESPONSE_TIMEOUT);
        if let Some(index) = self.pending.iter().position(|request| {
            request.id == id && request.local_id == local_id && request.destination == source
        }) {
            self.pending.swap_remove(index);
            true
        } else {
            false
        }
    }
}

fn neighbor_ports(advertised: &[u16]) -> Vec<u16> {
    let Some(anchor) = advertised.iter().max().copied() else {
        return Vec::new();
    };
    // Match the bounded mechanism demonstrated on the original network. No
    // wraparound, privileged ports, other IPs or relay endpoints are probed.
    (1..=28)
        .filter_map(|offset| anchor.checked_add(offset))
        .chain((1..=4).filter_map(|offset| anchor.checked_sub(offset)))
        .filter(|port| *port >= 1024 && !advertised.contains(port))
        .take(MAX_PORTS_PER_IP)
        .collect()
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0))
}

fn predicted_candidate(address: SocketAddr, component: u16) -> Option<IceCandidate> {
    CandidatePeerReflexiveConfig {
        base_config: CandidateBaseConfig {
            network: NetworkType::Udp4.to_string(),
            address: address.ip().to_string(),
            port: address.port(),
            component,
            ..Default::default()
        },
        rel_addr: String::new(),
        rel_port: 0,
    }
    .new_candidate_peer_reflexive()
    .ok()
    .map(|c| Arc::new(c) as IceCandidate)
}

impl AgentInternal {
    pub(super) async fn probe_remote_ports(&self) {
        if self.connection_state.load(Ordering::SeqCst) != ConnectionState::Checking as u8
            || self.agent_conn.get_selected_pair().is_some()
            || self.lite.load(Ordering::SeqCst)
        {
            self.port_discovery.lock().await.stop();
            return;
        }
        {
            let credentials = self.ufrag_pwd.lock().await;
            if credentials.remote_ufrag.is_empty() || credentials.remote_pwd.is_empty() {
                return;
            }
        }
        let locals = self
            .local_candidates
            .lock()
            .await
            .get(&NetworkType::Udp4)
            .cloned()
            .unwrap_or_default();
        let remotes = self
            .remote_candidates
            .lock()
            .await
            .get(&NetworkType::Udp4)
            .cloned()
            .unwrap_or_default();
        let probes = self
            .port_discovery
            .lock()
            .await
            .batch(Instant::now(), locals, remotes);
        for probe in probes {
            if self.connection_state.load(Ordering::SeqCst) != ConnectionState::Checking as u8
                || self.agent_conn.get_selected_pair().is_some()
                || self.done_tx.lock().await.is_none()
            {
                self.port_discovery.lock().await.stop();
                return;
            }
            let mut message = Message::new();
            let result = {
                let credentials = self.ufrag_pwd.lock().await;
                let role: Box<dyn stun::message::Setter> =
                    if self.is_controlling.load(Ordering::SeqCst) {
                        Box::new(AttrControlling(self.tie_breaker.load(Ordering::SeqCst)))
                    } else {
                        Box::new(AttrControlled(self.tie_breaker.load(Ordering::SeqCst)))
                    };
                message.build(&[
                    Box::new(BINDING_REQUEST),
                    Box::new(TransactionId::new()),
                    Box::new(Username::new(
                        ATTR_USERNAME,
                        format!("{}:{}", credentials.remote_ufrag, credentials.local_ufrag),
                    )),
                    role,
                    Box::new(PriorityAttr(probe.local.priority())),
                    Box::new(MessageIntegrity::new_short_term_integrity(
                        credentials.remote_pwd.clone(),
                    )),
                    Box::new(FINGERPRINT),
                ])
            };
            if result.is_ok()
                && self.port_discovery.lock().await.register(
                    Instant::now(),
                    message.transaction_id,
                    &probe,
                )
            {
                self.observe(
                    probe.local.candidate_type(),
                    ConnectivityEvent::PortDiscoveryProbe,
                );
                self.send_stun(&message, &probe.local, &probe.remote).await;
            }
        }
    }

    /// Called only after normal role and response integrity verification.
    pub(super) async fn accept_port_discovery_response(
        &self,
        message: &Message,
        local: &IceCandidate,
        source: SocketAddr,
    ) -> bool {
        if self.connection_state.load(Ordering::SeqCst) != ConnectionState::Checking as u8
            || !self.port_discovery.lock().await.consume(
                Instant::now(),
                message.transaction_id,
                &local.id(),
                source,
            )
        {
            return false;
        }
        if let Some(remote) = predicted_candidate(source, local.component()) {
            self.add_remote_candidate(&remote).await;
            self.observe(
                local.candidate_type(),
                ConnectivityEvent::PortDiscoveryAuthenticated,
            );
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::agent_config::AgentConfig;
    use crate::agent::agent_vnet_test::{build_vnet, gather_and_exchange_candidates};
    use crate::agent::Agent;
    use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
    use crate::candidate::CandidatePairState;
    use crate::mdns::MulticastDnsMode;
    use crate::udp_network::{EphemeralUDP, UDPNetwork};
    use crate::url::Url;
    use stun::message::BINDING_SUCCESS;
    use stun::xoraddr::XorMappedAddress;
    use util::vnet::nat::{EndpointDependencyType as Dependency, NatType};
    use util::Conn;

    async fn local_candidate(port: u16) -> IceCandidate {
        let conn = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        Arc::new(
            CandidateServerReflexiveConfig {
                base_config: CandidateBaseConfig {
                    network: "udp4".into(),
                    address: "27.1.1.1".into(),
                    port,
                    component: 1,
                    conn: Some(Arc::new(conn)),
                    ..Default::default()
                },
                rel_addr: "192.168.0.1".into(),
                rel_port: port,
            }
            .new_candidate_server_reflexive()
            .unwrap(),
        )
    }

    fn remote_candidate(ip: &str, port: u16) -> IceCandidate {
        Arc::new(
            CandidateServerReflexiveConfig {
                base_config: CandidateBaseConfig {
                    network: "udp4".into(),
                    address: ip.into(),
                    port,
                    component: 1,
                    ..Default::default()
                },
                rel_addr: "0.0.0.0".into(),
                rel_port: 0,
            }
            .new_candidate_server_reflexive()
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn bounded_port_discovery_limits_pacing_and_generation() {
        let mut locals = Vec::new();
        for port in 41000..41009 {
            locals.push(local_candidate(port).await);
        }
        let remotes = vec![
            remote_candidate("28.1.1.1", 14812),
            remote_candidate("29.1.1.1", 65530),
            remote_candidate("30.1.1.1", 8000),
            remote_candidate("127.0.0.1", 8000),
            remote_candidate("10.1.1.1", 8000),
            remote_candidate("100.64.0.1", 8000),
        ];
        let start = Instant::now();
        let mut disabled = PortDiscovery::new(false);
        disabled.reset();
        assert!(disabled
            .batch(start, locals.clone(), remotes.clone())
            .is_empty());
        let mut planner = PortDiscovery::new(true);
        planner.reset();
        assert!(planner
            .batch(start, locals.clone(), remotes.clone())
            .is_empty());
        assert!(planner
            .batch(
                start + START_DELAY - Duration::from_millis(1),
                locals.clone(),
                remotes.clone()
            )
            .is_empty());
        let mut sent = Vec::new();
        for tick in 0..40 {
            let now = start + START_DELAY + BATCH_INTERVAL * tick;
            let batch = planner.batch(now, locals.clone(), remotes.clone());
            assert!(batch.len() <= BATCH_SIZE);
            assert!(planner
                .batch(now, locals.clone(), remotes.clone())
                .is_empty());
            for probe in batch {
                let id = TransactionId::new();
                assert!(planner.register(now, id, &probe));
                sent.push((id, probe));
            }
        }
        assert_eq!(sent.len(), MAX_PROBES);
        let mut targets = BTreeMap::<_, std::collections::BTreeSet<_>>::new();
        let mut socket_ids = std::collections::BTreeSet::new();
        for (_, probe) in &sent {
            socket_ids.insert(probe.local.id());
            targets
                .entry(probe.remote.addr().ip())
                .or_default()
                .insert(probe.remote.port());
            assert!(probe.remote.port() >= 1024);
        }
        assert_eq!(socket_ids.len(), MAX_LOCAL_SOCKETS);
        assert_eq!(targets.len(), MAX_PEER_IPS);
        assert!(targets
            .values()
            .all(|ports| ports.len() <= MAX_PORTS_PER_IP));
        planner.reset();
        assert!(planner
            .batch(start, locals.clone(), remotes.clone())
            .is_empty());
        let batch = planner.batch(start + START_DELAY, locals.clone(), remotes.clone());
        let probe = &batch[0];
        let id = TransactionId::new();
        let now = start + START_DELAY;
        assert!(planner.register(now, id, probe));
        assert!(!planner.consume(now, id, "different-socket", probe.remote.addr()));
        assert!(!planner.consume(now, id, &probe.local.id(), "28.1.1.1:9".parse().unwrap()));
        assert!(!planner.consume(
            now,
            TransactionId::new(),
            &probe.local.id(),
            probe.remote.addr()
        ));
        assert!(planner.consume(now, id, &probe.local.id(), probe.remote.addr()));
        assert!(!planner.consume(now, id, &probe.local.id(), probe.remote.addr()));
        assert!(planner.register(now, id, probe));
        assert!(!planner.consume(
            now + RESPONSE_TIMEOUT,
            id,
            &probe.local.id(),
            probe.remote.addr()
        ));
        assert!(planner.register(now, id, probe));
        planner.stop();
        assert!(!planner.consume(now, id, &probe.local.id(), probe.remote.addr()));
        assert!(planner
            .batch(now, locals.clone(), remotes.clone())
            .is_empty());
        planner.reset();
        assert!(!planner.consume(now, id, &probe.local.id(), probe.remote.addr()));
        assert_eq!(neighbor_ports(&[65535]).len(), 4);
        assert!(neighbor_ports(&[1024]).iter().all(|port| *port >= 1024));
    }

    #[tokio::test]
    async fn bounded_port_discovery_rejects_forged_response_before_candidate_creation(
    ) -> crate::error::Result<()> {
        let agent = Agent::new(AgentConfig::default()).await?;
        agent
            .internal
            .connection_state
            .store(ConnectionState::Checking as u8, Ordering::SeqCst);
        {
            let mut credentials = agent.internal.ufrag_pwd.lock().await;
            credentials.remote_pwd = "remote-ice-secret".into();
            credentials.remote_ufrag = "remote-fragment".into();
        }
        let local = local_candidate(41000).await;
        agent.internal.add_candidate(&local).await?;
        let destination = "28.1.1.1:14813".parse().unwrap();
        let probe = Probe {
            local: local.clone(),
            remote: predicted_candidate(destination, 1).unwrap(),
        };
        let id = TransactionId::new();
        {
            let mut planner = agent.internal.port_discovery.lock().await;
            *planner = PortDiscovery::new(true);
            planner.reset();
            planner.started = Some(Instant::now());
            assert!(planner.register(Instant::now(), id, &probe));
        }
        let response = |password: &str, transaction| {
            let mut message = Message::new();
            message
                .build(&[
                    Box::new(BINDING_SUCCESS),
                    Box::new(transaction),
                    Box::new(XorMappedAddress {
                        ip: local.addr().ip(),
                        port: local.port(),
                    }),
                    Box::new(MessageIntegrity::new_short_term_integrity(password.into())),
                    Box::new(FINGERPRINT),
                ])
                .unwrap();
            message
        };
        let mut forged = response("wrong-password", id);
        agent
            .internal
            .handle_inbound(&mut forged, &local, destination)
            .await;
        let mut wrong_transaction = response("remote-ice-secret", TransactionId::new());
        agent
            .internal
            .handle_inbound(&mut wrong_transaction, &local, destination)
            .await;
        let mut valid = response("remote-ice-secret", id);
        agent
            .internal
            .handle_inbound(&mut valid, &local, "28.1.1.1:14814".parse().unwrap())
            .await;
        assert!(agent.internal.remote_candidates.lock().await.is_empty());
        agent
            .internal
            .handle_inbound(&mut valid, &local, destination)
            .await;
        assert!(agent
            .internal
            .find_remote_candidate(NetworkType::Udp4, destination)
            .await
            .is_some());
        assert!(agent.internal.agent_conn.get_selected_pair().is_none());
        // A replay after restart cannot create a candidate in the new generation.
        agent.restart(String::new(), String::new()).await?;
        agent
            .internal
            .handle_inbound(&mut valid, &local, destination)
            .await;
        assert!(agent.internal.remote_candidates.lock().await.is_empty());
        agent.close().await
    }

    #[tokio::test]
    async fn bounded_port_discovery_connects_restrictive_nat_only_when_enabled(
    ) -> crate::error::Result<()> {
        for enabled in [false, true] {
            // Two separate LANs. A's stable mapping filters by source port;
            // B's mapping depends on destination address and port.
            let vnet = build_vnet(
                NatType {
                    mapping_behavior: Dependency::EndpointIndependent,
                    filtering_behavior: Dependency::EndpointAddrPortDependent,
                    ..Default::default()
                },
                NatType {
                    mapping_behavior: Dependency::EndpointAddrPortDependent,
                    filtering_behavior: Dependency::EndpointAddrPortDependent,
                    ..Default::default()
                },
            )
            .await?;
            let mut ephemeral = EphemeralUDP::default();
            ephemeral.set_bounded_port_discovery(enabled);
            let config = |net| AgentConfig {
                urls: vec![Url::parse_url("stun:1.2.3.4:3478").unwrap()],
                network_types: vec![NetworkType::Udp4],
                multicast_dns_mode: MulticastDnsMode::Disabled,
                net: Some(net),
                ..Default::default()
            };
            let mut host_config = config(vnet.net0.clone());
            host_config.udp_network = UDPNetwork::Ephemeral(ephemeral);
            let host = Arc::new(Agent::new(host_config).await?);
            let browser = Arc::new(Agent::new(config(vnet.net1.clone())).await?);
            gather_and_exchange_candidates(&host, &browser).await?;
            let (hu, hp) = host.get_local_user_credentials().await;
            let (bu, bp) = browser.get_local_user_credentials().await;
            host.internal
                .start_connectivity_checks(false, bu, bp)
                .await?;
            browser
                .internal
                .start_connectivity_checks(true, hu, hp)
                .await?;
            let connected = tokio::time::timeout(Duration::from_secs(5), async {
                while host.internal.agent_conn.get_selected_pair().is_none()
                    || browser.internal.agent_conn.get_selected_pair().is_none()
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .is_ok();
            assert_eq!(
                connected, enabled,
                "same restrictive NAT configuration; discovery={enabled}"
            );
            if connected {
                for agent in [&host, &browser] {
                    let pair = agent.internal.agent_conn.get_selected_pair().unwrap();
                    assert_ne!(pair.local.candidate_type(), CandidateType::Relay);
                    assert_ne!(pair.remote.candidate_type(), CandidateType::Relay);
                    assert_eq!(
                        pair.state.load(Ordering::SeqCst),
                        CandidatePairState::Succeeded as u8
                    );
                }
                let mut buffer = [0; 64];
                host.internal
                    .agent_conn
                    .send(b"host-to-browser-authenticated-ICE")
                    .await?;
                let size = tokio::time::timeout(
                    Duration::from_secs(1),
                    browser.internal.agent_conn.recv(&mut buffer),
                )
                .await
                .unwrap()?;
                assert_eq!(&buffer[..size], b"host-to-browser-authenticated-ICE");
                browser
                    .internal
                    .agent_conn
                    .send(b"browser-to-host-authenticated-ICE")
                    .await?;
                let size = tokio::time::timeout(
                    Duration::from_secs(1),
                    host.internal.agent_conn.recv(&mut buffer),
                )
                .await
                .unwrap()?;
                assert_eq!(&buffer[..size], b"browser-to-host-authenticated-ICE");
            } else {
                let stats = host.get_candidate_pairs_stats().await;
                assert!(stats.iter().any(|pair| pair.requests_sent > 0));
                assert!(stats
                    .iter()
                    .all(|pair| pair.requests_received == 0 && pair.responses_received == 0));
            }
            host.close().await?;
            browser.close().await?;
            assert!(!host.internal.port_discovery.lock().await.running);
            vnet.close().await?;
        }
        Ok(())
    }
}
