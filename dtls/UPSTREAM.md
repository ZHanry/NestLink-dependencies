# DTLS 0.13.0 provenance and security repair

This directory is the published dtls 0.13.0 crate from webrtc-rs/webrtc commit
`a1f8f1919235d8452835852e018efd654f2f8366`, path `dtls`. UPSTREAM.crate is the
unaltered crates.io archive, SHA-256
`f531dd7c181beaf3cebab3716afa4d0d41ab888be85232583f56bbaf07ca208a`.
The package version and upstream licenses are retained. UPSTREAM.json records
every original file and the exact changed or added files.

RUSTSEC-2026-0387 affects crypto-bigint 0.5.5 through the original p256/p384
0.13 family. Their requirements cannot select the fixed crypto-bigint 0.7.6.
This fork selects p256/p384 0.14 and imposes a direct crypto-bigint >=0.7.6,
<0.8 floor. P384 explicitly enables ECDH. Key generation uses the new fallible
OS-entropy Generate API; entropy failure denies key generation. SEC1 point
encoding remains uncompressed; PublicKey::from_sec1_bytes validates peer points
before ECDH. Invalid encodings now use the existing P256 error variant rather
than the legacy Sec1 variant; both remain public and failures remain errors.
Certificate signing and verification continue to use ring without changes.
X25519, protocol state machines, cipher suites and public method signatures
are unchanged. The upstream codecov upload token is removed from active config.
Cargo.toml.orig and Cargo.lock retain upstream provenance; CI updates the
standalone lock before testing, and NestLink uses its own reviewed lock.

Added regressions cover P256/P384 two-peer shared secrets and wire lengths,
fresh public keys, malformed/off-curve/infinity points, mismatched private keys,
a fully authenticated P256 DTLS handshake and application payload, rejection
of an unrelated trust root, plus valid and altered certificate signatures,
transcripts and wrong signing certificates. Existing upstream tests run too.
The GitHub DTLS security contract workflow resolves and runs these tests.
No local Cargo build, test or dependency resolution was performed during repair;
CI results and the production lock require separate review before acceptance.
