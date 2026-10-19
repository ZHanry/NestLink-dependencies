//! Source-bound, expiring TURN challenges with constant server memory.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::SocketAddr;

pub(crate) struct NonceKey([u8; 32]);
impl NonceKey {
    pub(crate) fn new() -> Self {
        Self(rand::random())
    }

    fn mac(&self, peer: SocketAddr, issued: u64) -> Option<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).ok()?;
        mac.update(b"NestLink/TURN/nonce/v1\0");
        mac.update(peer.to_string().as_bytes());
        mac.update(&issued.to_be_bytes());
        Some(mac)
    }
    pub(crate) fn issue(&self, peer: SocketAddr, now: u64) -> Option<String> {
        Some(format!(
            "{now}.{}",
            URL_SAFE_NO_PAD.encode(self.mac(peer, now)?.finalize().into_bytes())
        ))
    }
    pub(crate) fn valid(&self, peer: SocketAddr, nonce: &str, now: u64) -> bool {
        let Some((issued, signature)) = nonce.split_once('.') else {
            return false;
        };
        let Ok(issued) = issued.parse::<u64>() else {
            return false;
        };
        if issued > now || now - issued >= 3600 {
            return false;
        }
        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
            return false;
        };
        self.mac(peer, issued)
            .is_some_and(|mac| mac.verify_slice(&signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_expiry_and_integrity_are_bound_without_a_nonce_table() {
        let key = NonceKey::new();
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let other: SocketAddr = "127.0.0.1:1235".parse().unwrap();
        let nonce = key.issue(peer, 1000).unwrap();
        assert!(key.valid(peer, &nonce, 1000));
        assert!(key.valid(peer, &nonce, 4599));
        assert!(!key.valid(peer, &nonce, 4600));
        assert!(!key.valid(peer, &nonce, 999));
        assert!(!key.valid(other, &nonce, 1001));
        assert!(!NonceKey::new().valid(peer, &nonce, 1001));
        assert!(!key.valid(peer, &format!("{nonce}x"), 1001));
        for now in 1000..11000 {
            assert!(key.valid(peer, &key.issue(peer, now).unwrap(), now));
        }
    }
}
