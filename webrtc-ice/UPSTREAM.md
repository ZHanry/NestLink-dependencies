# Vendored WebRTC ICE source

This directory preserves `webrtc-ice` **0.14.0**, from the exact previously locked
crates.io archive. Its SHA-256 is
`69cb13fd1a373e68addc4bba0c8ca058627518e54342583d024bdcbb8ae5d97d`.
The upstream repository is [webrtc-rs/webrtc](https://github.com/webrtc-rs/webrtc),
commit `a1f8f1919235d8452835852e018efd654f2f8366`, directory `ice`.

All 63 archive files were verified byte for byte on import. `LICENSE-MIT` and
`LICENSE-APACHE` preserve the already reviewed upstream license texts from
`packaging/notices/webrtc-rs-LICENSE-*`; upstream code remains MIT OR Apache-2.0.
The source import receipt is
`artifacts/core-verification/ice-vendor-source-20261015-attempt01.json`.

The local production repair changes one comparison in
`src/agent/agent_internal.rs::find_remote_candidate`: match the candidate's resolved
IP and its existing port. A browser mDNS candidate retains its `.local` signaling
name after `set_ip`; comparing that name to a received packet's IP could never
find the original candidate. Network-type buckets and the previous handling of
IPv6 scope/flow and IPv4-mapped addresses are preserved. Four regression tests
are appended under `cfg(test)` in that same file.

The isolated regression harness runs the real `AgentInternal` method, with
`CandidateHostConfig` and `set_ip`. Its old-comparison run fails the two mDNS cases
while both numeric-address controls pass; its repaired run passes all four. The
harness disables upstream test-module registrations and development dependencies
only in its private copies, retaining every production Rust source. All 142
resolved registry identities are already present in the workspace lock. The
source transformations, byte audit, original failures, successful log and actual
test executable identities are frozen in
`artifacts/ice-resolved-candidate-followup-20261015/`.

The workspace and browser-native fixture select this directory through their
`[patch.crates-io]` entries. Their lock changes preserve every dependency version
and replace only this package's registry source/checksum with its local source.
No registry cache source was edited. Actual browser/media verification is recorded
separately in `docs/refactor/BROWSER-NATIVE-VERIFICATION.md`.

RC source export: removed the upstream Codecov upload token from codecov.yml. Coverage upload credentials are not required to build or use this fork; runtime and license files are unchanged by this removal.

0.7 RC socket routing: `EphemeralUDP` accepts an optional application socket
factory. Host, STUN server-reflexive, mapped server-reflexive and UDP TURN
gathering retain the socket returned by that factory as the candidate's live
connection. The default factory and virtual-network behavior are unchanged.
The owning application enforces address/interface policy; this fork does not
infer VPN bypass from interface names. NestLink's `media_socket_factory`
integration test performs a real local STUN exchange and subsequent UDP
check/data exchanges through the same factory-created socket and source port.
This test does not qualify an Internet peer path or TURN TCP/TLS routing.

0.7 RC connectivity diagnostics: the candidate pair's four STUN check counters
are populated from successful socket writes and authenticated requests/responses.
Responses must also match an outstanding transaction and its destination. Failed
writes and rejected packets do not count as successful checks. The counters do
not include SDP, credentials or endpoint addresses, and do not change ICE policy.
The agent stats regression and NestLink's real UDP peer regression check that
all four counters advance before they are used in connection diagnostics.

0.7 RC ordinary-check pacing: each candidate pair retains its own next-check
deadline. New pairs are checked immediately; subsequent ordinary attempts are
spaced by 500ms, 1s, then at most 2s. Extra candidate/contact wakeups cannot
consume the retry budget before that deadline. Authenticated triggered checks,
role/integrity checks, the retry limit and agent cancellation are unchanged.
NestLink's real UDP regression drops both directions for four seconds: the old
200ms retry loop exhausts every pair and times out, while the paced loop must
connect and transfer the test payload after the temporary loss ends. This
regression does not establish real Internet/NAT/Clash acceptance.
