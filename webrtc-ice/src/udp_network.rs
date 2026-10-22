use std::sync::Arc;

use super::udp_mux::UDPMux;
use super::Error;
use crate::candidate::CandidateType;

/// Fixed labels only. Observers never receive packets, addresses or ICE secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectivityEvent {
    Socket(SocketObservation),
    DatagramReceived,
    ReceiveError,
    StunDecodeRejected,
    BindingRequestReceived,
    BindingResponseReceived,
    RoleRejected,
    UsernameRejected,
    IntegrityRejected,
    UnknownRemoteResponse,
    SendError,
    PortDiscoveryProbe,
    PortDiscoveryAuthenticated,
}

/// Per-candidate lifecycle evidence. Ports and a local opaque key are enough
/// to correlate the OS socket table; no address or credential is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SocketObservation {
    pub candidate_key: u64,
    pub port: u16,
    pub ipv6: bool,
    pub stage: SocketStage,
    pub error: Option<SocketError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketStage {
    CandidateStarted,
    MissingConnection,
    DuplicateCandidate,
    ReceiverSpawned,
    WaitingForStart,
    StartSignalClosed,
    StartSignalLagged,
    ReceiverReady,
    ReceiverClosedBeforeStart,
    ReceiverClosed,
    ReceiverAborted,
    ReceiveError,
    DatagramReceived,
    SendAccepted,
    SendShort,
    SendError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SocketError {
    pub layer: SocketErrorLayer,
    pub code: SocketErrorCode,
    pub os_code: Option<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketErrorLayer {
    Io,
    Turn,
    Wrapped,
    Other,
    Protocol,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketErrorCode {
    Io,
    Timeout,
    Closed,
    NoPermission,
    NoAllocation,
    ChannelBinding,
    ShortWrite,
    PeerFamilyMismatch,
    Protocol,
    Other,
}

/// Inspect typed causes only; error messages can contain network secrets.
pub(crate) fn socket_error(mut error: &(dyn std::error::Error + 'static)) -> SocketError {
    for _ in 0..8 {
        if let Some(error) = error.downcast_ref::<std::io::Error>() {
            return SocketError {
                layer: SocketErrorLayer::Io,
                code: SocketErrorCode::Io,
                os_code: error.raw_os_error(),
            };
        }
        if let Some(ice) = error.downcast_ref::<Error>() {
            match ice {
                Error::Io(inner) => {
                    error = &inner.0;
                    continue;
                }
                Error::Util(inner) => {
                    error = inner;
                    continue;
                }
                Error::Turn(inner) => {
                    error = inner;
                    continue;
                }
                _ => {}
            }
        }
        if let Some(util) = error.downcast_ref::<util::Error>() {
            match util {
                util::Error::Io(inner) => {
                    error = &inner.0;
                    continue;
                }
                util::Error::Std(inner) => {
                    error = inner.0.as_ref();
                    continue;
                }
                util::Error::ErrTimeout => {
                    return SocketError {
                        layer: SocketErrorLayer::Protocol,
                        code: SocketErrorCode::Timeout,
                        os_code: None,
                    }
                }
                util::Error::ErrAlreadyClosed
                | util::Error::ErrUseClosedNetworkConn
                | util::Error::ErrClosedListener
                | util::Error::ErrBufferClosed => {
                    return SocketError {
                        layer: SocketErrorLayer::Protocol,
                        code: SocketErrorCode::Closed,
                        os_code: None,
                    }
                }
                util::Error::Other(_) => {
                    return SocketError {
                        layer: SocketErrorLayer::Other,
                        code: SocketErrorCode::Other,
                        os_code: None,
                    }
                }
                _ => {}
            }
        }
        if let Some(turn) = error.downcast_ref::<turn::Error>() {
            let code = match turn {
                turn::Error::Io(inner) => {
                    error = &inner.0;
                    continue;
                }
                turn::Error::Util(inner) => {
                    error = inner;
                    continue;
                }
                turn::Error::ErrNoPermission => SocketErrorCode::NoPermission,
                turn::Error::ErrNoAllocationFound => SocketErrorCode::NoAllocation,
                turn::Error::ErrChannelBindNotFound | turn::Error::ErrNoSuchChannelBind => {
                    SocketErrorCode::ChannelBinding
                }
                turn::Error::ErrAllRetransmissionsFailed | turn::Error::ErrMaxRetriesExceeded => {
                    SocketErrorCode::Timeout
                }
                turn::Error::ErrClosed
                | turn::Error::ErrAlreadyClosed
                | turn::Error::ErrTransactionClosed => SocketErrorCode::Closed,
                turn::Error::ErrShortWrite => SocketErrorCode::ShortWrite,
                turn::Error::ErrPeerAddressFamilyMismatch => SocketErrorCode::PeerFamilyMismatch,
                turn::Error::Other(_) => SocketErrorCode::Other,
                _ => SocketErrorCode::Protocol,
            };
            return SocketError {
                layer: SocketErrorLayer::Turn,
                code,
                os_code: None,
            };
        }
        match error.source() {
            Some(source) => error = source,
            None => {
                return SocketError {
                    layer: SocketErrorLayer::Protocol,
                    code: SocketErrorCode::Protocol,
                    os_code: None,
                }
            }
        }
    }
    SocketError {
        layer: SocketErrorLayer::Wrapped,
        code: SocketErrorCode::Other,
        os_code: None,
    }
}

pub type ConnectivityObserver = Arc<dyn Fn(CandidateType, ConnectivityEvent) + Send + Sync>;

/// Application-owned socket creation for real interface routing. The returned
/// socket is retained by its ICE candidate for STUN, checks and media traffic.
pub type UdpSocketFactory =
    Arc<dyn Fn(std::net::SocketAddr) -> std::io::Result<std::net::UdpSocket> + Send + Sync>;

#[derive(Default, Clone)]
pub struct EphemeralUDP {
    port_min: u16,
    port_max: u16,
    socket_factory: Option<UdpSocketFactory>,
    connectivity_observer: Option<ConnectivityObserver>,
    bounded_port_discovery: bool,
}

impl EphemeralUDP {
    /// Opt in only for an authorized peer's IPv4 server-reflexive candidates.
    /// This sends a small, paced set of authenticated ICE checks near the
    /// advertised ports. Guesses are never inserted into the ICE checklist.
    pub fn set_bounded_port_discovery(&mut self, enabled: bool) {
        self.bounded_port_discovery = enabled;
    }
    pub fn bounded_port_discovery(&self) -> bool {
        self.bounded_port_discovery
    }
    pub fn set_connectivity_observer(&mut self, observer: ConnectivityObserver) {
        self.connectivity_observer = Some(observer);
    }
    pub fn connectivity_observer(&self) -> Option<ConnectivityObserver> {
        self.connectivity_observer.clone()
    }
    pub fn set_socket_factory(&mut self, factory: UdpSocketFactory) {
        self.socket_factory = Some(factory);
    }
    pub fn socket_factory(&self) -> Option<UdpSocketFactory> {
        self.socket_factory.clone()
    }
    pub fn new(port_min: u16, port_max: u16) -> Result<Self, Error> {
        let mut s = Self::default();
        s.set_ports(port_min, port_max)?;

        Ok(s)
    }

    pub fn port_min(&self) -> u16 {
        self.port_min
    }

    pub fn port_max(&self) -> u16 {
        self.port_max
    }

    pub fn set_ports(&mut self, port_min: u16, port_max: u16) -> Result<(), Error> {
        if port_max < port_min {
            return Err(Error::ErrPort);
        }

        self.port_min = port_min;
        self.port_max = port_max;

        Ok(())
    }
}

/// Configuration for the underlying UDP network stack.
/// There are two ways to configure this Ephemeral and Muxed.
///
/// **Ephemeral mode**
///
/// In Ephemeral mode sockets are created and bound to random ports during ICE
/// gathering. The ports to use can be restricted by setting [`EphemeralUDP::port_min`] and
/// [`EphemeralUDP::port_max`] in which case only ports in this range will be used.
///
/// **Muxed**
///
/// In muxed mode a single UDP socket is used and all connections are muxed over this single socket.
///
#[derive(Clone)]
pub enum UDPNetwork {
    Ephemeral(EphemeralUDP),
    Muxed(Arc<dyn UDPMux + Send + Sync>),
}

impl Default for UDPNetwork {
    fn default() -> Self {
        Self::Ephemeral(Default::default())
    }
}

impl UDPNetwork {
    fn is_ephemeral(&self) -> bool {
        matches!(self, Self::Ephemeral(_))
    }

    fn is_muxed(&self) -> bool {
        matches!(self, Self::Muxed(_))
    }
}

#[cfg(test)]
mod test {
    use super::EphemeralUDP;

    #[test]
    fn typed_causes_preserve_os_codes_and_turn_failure_without_messages(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use super::{socket_error, SocketErrorCode, SocketErrorLayer};
        let turn_error: turn::Error = std::io::Error::from_raw_os_error(10054).into();
        let error = crate::Error::Util(util::Error::from_std(turn_error));
        let observation = socket_error(&error);
        assert_eq!(observation.layer, SocketErrorLayer::Io);
        assert_eq!(observation.os_code, Some(10054));
        let error = util::Error::from_std(turn::Error::ErrNoPermission);
        let observation = socket_error(&error);
        assert_eq!(observation.layer, SocketErrorLayer::Turn);
        assert_eq!(observation.code, SocketErrorCode::NoPermission);
        let secret = "TEST_PASSWORD_MUST_NOT_LEAK";
        let serialized = serde_json::to_string(&socket_error(&util::Error::from_std(
            turn::Error::Other(secret.into()),
        )))?;
        assert!(!serialized.contains(secret));
        Ok(())
    }

    #[test]
    fn test_ephemeral_udp_constructor() {
        assert!(
            EphemeralUDP::new(3000, 2999).is_err(),
            "EphemeralUDP should not allow invalid port range"
        );

        let e = EphemeralUDP::default();
        assert_eq!(e.port_min(), 0, "EphemeralUDP should default port_min to 0");
        assert_eq!(e.port_max(), 0, "EphemeralUDP should default port_max to 0");
    }

    #[test]
    fn test_ephemeral_udp_set_ports() {
        let mut e = EphemeralUDP::default();

        assert!(
            e.set_ports(3000, 2999).is_err(),
            "EphemeralUDP should not allow invalid port range"
        );

        assert!(
            e.set_ports(6000, 6001).is_ok(),
            "EphemeralUDP::set_ports should allow valid port range"
        );

        assert_eq!(
            e.port_min(),
            6000,
            "Ports set with `EphemeralUDP::set_ports` should be reflected"
        );
        assert_eq!(
            e.port_max(),
            6001,
            "Ports set with `EphemeralUDP::set_ports` should be reflected"
        );
    }
}
