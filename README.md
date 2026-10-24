# NestLink dependency forks

Reviewed upstream consumers used by NestLink, maintained on `main`.
NestLink uses ordinary versioned dependencies and `[patch.crates-io]` pointing
to this branch. Its Cargo.lock pins the exact Git commit. This repository is
a collection of independently attributed forks, not first-party code.

The package directories retain the previous reviewed patch bytes, upstream
licenses, original manifests and VCS records. The Web and Foundation forks
also retain their original crate archives and complete UPSTREAM.json hash
inventories. Read each package's UPSTREAM.md before changing it.

| Package | Upstream | Changes |
| --- | --- | --- |
| turn 0.17.2 | webrtc-rs/webrtc | Allocation policy/peer hooks, close callback, bounded stream buffer |
| turn 0.11.0 (`turn-client/`) | webrtc-rs/webrtc | Payload send lengths, complete datagram validation and typed client errors |
| dtls 0.13.0 (`dtls/`) | webrtc-rs/webrtc | P256/P384 arithmetic upgrade for RUSTSEC-2026-0387, authenticated handshake and signature regressions |
| webrtc-ice 0.14.0 | webrtc-rs/webrtc | Managed TURN TCP/TLS transport support |
| leptos_macro 0.8.19 | leptos-rs/leptos | Use existing convert_case naming predicates |
| tachys 0.2.19 | leptos-rs/leptos | Checked standard-library type erasure |
| objc2-foundation 0.2.2 | madsmtm/objc2 | Use reviewed dispatch2 dependency |

All upstream notices retain their own licenses. No upstream source or license
text is relicensed by this collection. Provenance is in upstream-sources.json
and the package-local records.
