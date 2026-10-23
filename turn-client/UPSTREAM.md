# TURN 0.11 client contract repair

This directory retains the exact published `turn 0.11.0` crate, used by
`webrtc 0.14` and `webrtc-ice 0.14`. It is distinct from the managed service's
`turn 0.17.2` in `../turn`. The original archive, manifests, VCS attribution and
MIT/Apache-2.0 license texts are retained. `UPSTREAM.json` records the original
archive checksum, each original file, and the narrow changes.

`RelayConn::send_to` must return application payload bytes, not the larger TURN
SendIndication or ChannelData wire length. Both paths now check the complete
datagram write before returning the payload length. Zero, short and overreported
writes remain errors. Errors retain typed causes through `util::Error::from_std`
instead of exposing or flattening error messages.

Private contract tests cover both wire formats and injected write faults. A
public test uses real Client allocation, permissions and ChannelBind against
an owned loopback TURN server, verifying exact data in both directions.
NestLink additionally exercises this fork through the actual ICE observer.
These tests do not establish public-network relay reachability or direct
remote desktop acceptance.

The only other changes are an isolated workspace declaration (both TURN
versions coexist in this Git repository), test sources and removal of the
upstream coverage upload credential. Published source remains independently
attributed, and its original license declaration remains MIT OR Apache-2.0.
