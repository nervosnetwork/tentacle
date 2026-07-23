# QUIC Transport for Tentacle

## Overview

Tentacle's `quic` feature adds a QUIC-based transport that runs *alongside*
the classic TCP + secio + yamux pipeline. Both stacks coexist inside a
single `Service`; multiaddrs of the form `/ip4/<addr>/udp/<port>/quic-v1`
route through the QUIC stack, everything else continues through the
classic pipeline.

QUIC support is gated by the `quic` Cargo feature. The feature is in the
default feature set, so a stock `tentacle = "*"` dependency already has
QUIC compiled in. To opt out, set `default-features = false`.

```toml
[dependencies]
# QUIC enabled (default)
tentacle = "0.7"

# Explicit opt-in
tentacle = { version = "0.7", default-features = false, features = ["tokio-runtime", "tokio-timer", "quic"] }

# Disabled
tentacle = { version = "0.7", default-features = false, features = ["tokio-runtime", "tokio-timer"] }
```

## Enabling QUIC on a service

Calling `ServiceBuilder::quic_config(...)` opts the service into the QUIC
stack. The argument is a `QuicConfig` carrying transport-layer tunables
(see below). QUIC requires `HandshakeType::Secio` because the secio
identity is bound into the QUIC TLS certificate — calling
`quic_config(...)` without `Secio` produces a precise error at first use
(see *Error surface* below).

```rust
use tentacle::builder::ServiceBuilder;
use tentacle::quic::config::QuicConfig;
use tentacle::secio::SecioKeyPair;

let service = ServiceBuilder::default()
    .insert_protocol(my_protocol)
    .handshake_type(SecioKeyPair::secp256k1_generated().into())
    .quic_config(QuicConfig::default())  // ← enables QUIC
    .build(my_handle);
```

A QUIC-enabled service can still `listen` / `dial` on plain TCP, WebSocket,
TLS, or Memory addresses. The QUIC and classic pipelines are independent;
neither degrades the other.

## Address format

```
/ip{4,6}/<addr>/udp/<port>/quic-v1[/p2p/<peer_id>]
```

Examples:

| Multiaddr | Meaning |
|---|---|
| `/ip4/127.0.0.1/udp/4433/quic-v1` | dial / listen on UDP 127.0.0.1:4433, QUIC v1 |
| `/ip6/::1/udp/4433/quic-v1` | same, IPv6 loopback |
| `/ip4/192.0.2.1/udp/4433/quic-v1/p2p/QmHash...` | dial pinned to a specific PeerId |

**Not supported** in v1 (each surfaces as `QuicError(InvalidAddress(_))`):

- `/dns{4,6}/.../quic-v1` — DNS resolution of QUIC addresses is deferred
- Anything between `/ip` and `/udp` other than just the IP
- Multiple `/p2p/` components
- `/tcp/...` followed by `/quic-v1` (QUIC runs on UDP)

## Identity model

QUIC reuses the existing secio keypair (`K_secio`) as the tentacle
identity, but generates a **fresh per-service Ed25519 keypair**
(`K_tls`) for the TLS layer. The two keys are linked by a binding
signature embedded in a private X.509 extension on the self-signed leaf
certificate:

```
binding_sig = secp256k1_sign(K_secio, sha256(BINDING_DOMAIN || K_tls_SPKI_der))
```

The certificate's private extension (OID `1.3.6.1.4.1.99999.1.1`)
carries `(version, secio_pubkey, binding_sig)`. The peer's `PeerId` is
**not** stored — it is deterministically derived from `secio_pubkey` by
both sides at verification time.

When a peer connects, the verifier (custom `rustls` `ServerCertVerifier`
/ `ClientCertVerifier`) runs the following checks:

1. The chain contains exactly one leaf certificate (no intermediates).
2. The leaf is currently within its validity window.
3. The leaf has exactly one extension with the tentacle OID; molecule-decode
   it as `TentacleQuicIdentityV1` with `version == 1`.
4. The secp256k1 binding signature verifies against
   `sha256(BINDING_DOMAIN || leaf_spki_der)` under `secio_pubkey`.
5. (Client only) If the dial target multiaddr contained `/p2p/<expected>`,
   `expected == PeerId::from(secio_pubkey)`.

Standard CA / hostname checks are intentionally skipped — they don't
apply in a peer-to-peer model.

Client authentication is **mandatory** — a plain TLS client without a
tentacle-bound certificate cannot connect.

Once the handshake succeeds, the peer's `PeerId` and `PublicKey` are
exposed on `SessionContext` exactly the same way as for secio sessions,
so application code is transport-agnostic.

## Configuration tunables

`QuicConfig` (see [`tentacle/src/quic/config.rs`](../tentacle/src/quic/config.rs)):

| Field | Default | Meaning |
|---|---|---|
| `max_idle_timeout` | `30s` | Per-connection idle timeout. Each peer advertises its value; the smaller wins. |
| `keep_alive_interval` | `Some(10s)` | How often this peer sends keep-alive PINGs. `None` disables. |
| `max_concurrent_bidi_streams` | `256` | Cap on streams the **peer** may open *to us*. The peer's value caps the streams *we* may open. |

These are applied symmetrically to both the listen-side `quinn::ServerConfig`
and the per-dial `quinn::ClientConfig`.

## Coexistence with TCP / WebSocket / TLS

A QUIC-enabled service can listen on multiple transports simultaneously:

```rust
service.listen("/ip4/0.0.0.0/tcp/1337".parse()?).await?;       // TCP+secio+yamux
service.listen("/ip4/0.0.0.0/udp/4433/quic-v1".parse()?).await?; // QUIC
```

Sessions opened over either stack appear identically in
`ServiceHandle::handle_event` (`SessionOpen { session_context }`) and in
`ServiceProtocol::connected` — protocol code does not need to know which
transport carried the bytes.

`Service::dial` and `Service::control().dial(...)` route based on the
target multiaddr shape. Both honour the same in-flight duplicate-dial
check (by address and by peer-id), independent of transport.

## Error surface

| Scenario | Surfaces as |
|---|---|
| `/quic-v1` dialed by a `HandshakeType::Noop` service that didn't enable QUIC | `TransportErrorKind::NotSupported(addr)` |
| `/quic-v1` dialed by a `HandshakeType::Secio` service that didn't call `quic_config(...)` | `QuicError(NotConfigured)` |
| `quic_config(...)` set with `HandshakeType::Noop` | `QuicError(Misconfigured(_))` |
| `QuicEndpoint::new` failed at builder time (cert / signing / TLS provider error) | `QuicError(Misconfigured(_))` |
| `/dns4/.../quic-v1` and similar malformed shapes | `QuicError(InvalidAddress(_))` |
| Dial target's `/p2p/<wrong>` does not match the server's actual PeerId | `DialerError(TransportError(QuicError(Connection(_))))` (handshake aborted by client-side verifier) |
| Server-side per-connection handshake failure (bad client cert, dropped client, …) | Logged at debug level; listener keeps accepting other connections |
| Connection-level errors after handshake (idle timeout, peer reset, app-closed) | `MuxerError` event on the session |

## v1 limitations

The following are deliberately out of scope for v1 and will be revisited
in later PRs:

- **Pooled UDP-endpoint reuse across multiple dials.** Each dial opens a
  fresh `quinn::Endpoint`. A pool keyed on local listen address can be
  added later if needed.
- **Unidirectional QUIC streams.** Tentacle only uses bidi streams; uni
  is disabled in `TransportConfig`.
- **QUIC datagrams.** Datagram send / receive buffers are explicitly set
  to zero.
- **DNS-form addresses** (`/dns{4,6}/.../quic-v1`). Resolution would
  require an asynchronous DNS step before bind / dial, which the v1
  routing logic doesn't carry.
- **NAT-traversal socket injection.** No way to pass in an externally-bound
  UDP socket (`SocketSource::Provided` is reserved for v2).
- **Custom congestion control / pacing.** Whatever quinn's default is.

## Example

A minimal end-to-end example mirroring `examples/simple.rs`:
[`examples/quic_simple.rs`](../tentacle/examples/quic_simple.rs).

```bash
# Terminal A
cargo run --features quic --example quic_simple -- server

# Terminal B
cargo run --features quic --example quic_simple -- client
```

The `PHandle` / `SHandle` implementations are byte-identical with
`examples/simple.rs`. The only diffs are:

1. one extra `.quic_config(QuicConfig::default())` builder call, and
2. the listen / dial address shape (`/udp/.../quic-v1` instead of
   `/tcp/...`).

This is the intended user experience: QUIC support is a configuration
choice, not an API rewrite.
