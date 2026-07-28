# Tentacle QUIC 传输

## 概述

Tentacle 的 `quic` feature 增加了一条**与现有 TCP + secio + yamux 流水线并存**
的 QUIC 传输栈。两套栈在同一个 `Service` 内共存；形如
`/ip4/<addr>/udp/<port>/quic-v1` 的 multiaddr 走 QUIC，其余地址继续走经典栈。

QUIC 支持由 `quic` Cargo feature 控制。它已被列入默认 feature 集合，所以
直接 `tentacle = "*"` 就已经编进了 QUIC。要关掉就用 `default-features = false`。

```toml
[dependencies]
# 默认开启 QUIC
tentacle = "0.7"

# 显式启用
tentacle = { version = "0.7", default-features = false, features = ["tokio-runtime", "tokio-timer", "quic"] }

# 不要 QUIC
tentacle = { version = "0.7", default-features = false, features = ["tokio-runtime", "tokio-timer"] }
```

## 在 service 上启用 QUIC

调用 `ServiceBuilder::quic_config(...)` 即可在该 service 上启用 QUIC。参数
是 `QuicConfig`，承载传输层可调参数（见下文）。**QUIC 要求
`HandshakeType::Secio`** —— secio 身份会被绑定到 QUIC 的 TLS 证书里；如果
只调 `quic_config(...)` 没设 Secio，会在第一次使用时报一个明确错误
（见下文"错误暴露"小节）。

```rust
use tentacle::builder::ServiceBuilder;
use tentacle::quic::config::QuicConfig;
use tentacle::secio::SecioKeyPair;

let service = ServiceBuilder::default()
    .insert_protocol(my_protocol)
    .handshake_type(SecioKeyPair::secp256k1_generated().into())
    .quic_config(QuicConfig::default())  // ← 启用 QUIC
    .build(my_handle);
```

启用 QUIC 后，该 service **仍然可以** 在 TCP、WebSocket、TLS、Memory 等其他
传输上 `listen` 和 `dial`。QUIC 路径与经典路径互相独立，不会互相退化。

## 地址格式

```
/ip{4,6}/<addr>/udp/<port>/quic-v1[/p2p/<peer_id>]
```

示例：

| Multiaddr | 含义 |
|---|---|
| `/ip4/127.0.0.1/udp/4433/quic-v1` | 在 UDP 127.0.0.1:4433 上 dial / listen QUIC v1 |
| `/ip6/::1/udp/4433/quic-v1` | 同上，IPv6 |
| `/ip4/192.0.2.1/udp/4433/quic-v1/p2p/QmHash...` | 拨号时把 PeerId 钉死，验证器会校验 |

**v1 不支持**（每种都报 `QuicError(InvalidAddress(_))`）：

- `/dns{4,6}/.../quic-v1` —— QUIC 地址的 DNS 解析推迟到后续版本
- `/ip` 和 `/udp` 之间出现其他协议
- 多个 `/p2p/` 段
- `/tcp/...` 后接 `/quic-v1`（QUIC 跑在 UDP 上）

## 身份模型

QUIC 复用已有的 secio keypair (`K_secio`) 作为 tentacle 身份；针对 TLS
层**每个 service 单独生成一对 Ed25519 keypair** (`K_tls`)。两把 key 之间
通过自签证书里的一个 binding 签名挂钩：

```
binding_sig = secp256k1_sign(K_secio, sha256(BINDING_DOMAIN || K_tls_SPKI_der))
```

自签证书里有一个私有 X.509 extension（OID `1.3.6.1.4.1.99999.1.1`），里面
按 molecule 编码 `(version, secio_pubkey, binding_sig)`。**对端的 `PeerId`
不直接存进 payload** —— 双方在验证时自己从 `secio_pubkey` 派生。

收到对端连接时，自定义 `rustls` 的 `ServerCertVerifier` / `ClientCertVerifier`
会按顺序做这些检查：

1. 证书链里只有一张叶子证书，没有中间证书。
2. 叶子证书当前处于有效期之内。
3. 叶子证书有且仅有一个 tentacle OID 的 extension，能 molecule-decode 出
   `TentacleQuicIdentityV1`，且 `version == 1`。
4. `secio_pubkey` 对 `sha256(BINDING_DOMAIN || leaf_spki_der)` 的
   secp256k1 验签通过。
5. （仅客户端）如果 dial 地址含有 `/p2p/<expected>`，要求
   `expected == PeerId::from(secio_pubkey)`。

CA / hostname 等标准 TLS 检查**有意跳过** —— peer-to-peer 模型里这两个
概念都不适用。

**客户端身份验证是强制的**：没有 tentacle 绑定证书的 TLS 客户端连不进来。

握手成功后，对端的 `PeerId` 和 `PublicKey` 会以和 secio 完全相同的方式
暴露在 `SessionContext` 上 —— 应用层代码不需要知道底层走的是哪条传输。

## 可调参数

`QuicConfig`（详见 [`tentacle/src/quic/config.rs`](../tentacle/src/quic/config.rs)）：

| 字段 | 默认值 | 含义 |
|---|---|---|
| `max_idle_timeout` | `30s` | 每连接空闲超时。双方握手时各 advertise 自己的值，**取较小者**生效。 |
| `keep_alive_interval` | `Some(10s)` | 本端主动发送 PING 的间隔，用来阻止空闲被对端 / 防火墙杀掉。`None` 关闭。 |
| `max_concurrent_bidi_streams` | `256` | **本端施加给对端**的并发双向流数量上限。对端的设置反过来限制我们能开多少个流到对端。 |

这些参数会**对称地**应用到 listen 侧的 `quinn::ServerConfig` 和每次 dial
新建的 `quinn::ClientConfig`，所以两端的行为一致。

## 与 TCP / WebSocket / TLS 共存

一个启用 QUIC 的 service 可以同时 listen 多种传输：

```rust
service.listen("/ip4/0.0.0.0/tcp/1337".parse()?).await?;          // TCP+secio+yamux
service.listen("/ip4/0.0.0.0/udp/4433/quic-v1".parse()?).await?;  // QUIC
```

无论哪条栈接收的连接，最终在 `ServiceHandle::handle_event` 里都以
`SessionOpen { session_context }` 出现，在 `ServiceProtocol::connected`
里也完全等价 —— 协议层代码**不需要知道**底层是 QUIC 还是 TCP。

`Service::dial` 和 `Service::control().dial(...)` 都根据目标 multiaddr
的形态做路由。两边都遵守同一份"飞行中重复 dial"检查（按地址、按 peer_id），
与传输类型无关。

## 错误暴露

| 场景 | 实际错误 |
|---|---|
| `HandshakeType::Noop` 的 service 没开 QUIC，去 dial `/quic-v1` | `TransportErrorKind::NotSupported(addr)` |
| `HandshakeType::Secio` 的 service 没调 `quic_config(...)`，去 dial `/quic-v1` | `QuicError(NotConfigured)` |
| 调了 `quic_config(...)` 但 `HandshakeType::Noop` | `QuicError(Misconfigured(_))` |
| `QuicEndpoint::new` 在构造期失败（证书 / 签名 / TLS provider 错误） | `QuicError(Misconfigured(_))` |
| 地址形态不合法（`/dns4/...`、`/tcp/...` 后跟 `/quic-v1` 等） | `QuicError(InvalidAddress(_))` |
| Dial 地址的 `/p2p/<wrong>` 和服务端实际 PeerId 不一致 | `DialerError(TransportError(QuicError(Connection(_))))`（TLS 握手被客户端 verifier 拒绝） |
| 服务端单个连接握手失败（坏证书、客户端中途断开等） | debug 级别日志；listener 继续接受其他连接，不会因为一个坏客户端崩 |
| 握手后的连接级错误（idle 超时、对端 reset、app-closed） | 该 session 上抛 `MuxerError` 事件 |

## v1 不支持

以下能力**故意**放到后续 PR：

- **跨多次 dial 复用 UDP endpoint**：当前每次 dial 都建一个新的
  `quinn::Endpoint`。如有需要可后续加一个按 listen 地址 keyed 的 pool。
- **单向 QUIC 流**：tentacle 只用双向流；`TransportConfig` 里把 uni 流关掉了。
- **QUIC datagrams**：datagram 收 / 发缓冲区都显式置零。
- **DNS 形地址**（`/dns{4,6}/.../quic-v1`）：解析得在 bind / dial 之前异步走，
  当前路由逻辑没带这条路径。
- **NAT 穿透 socket 注入**：v1 没有传入外部绑定 UDP socket 的入口
  （`SocketSource::Provided` 为 v2 保留）。
- **自定义拥塞控制 / pacing**：用 quinn 的默认值。

## 示例

和 `examples/simple.rs` 完全平行的端到端示例：
[`examples/quic_simple.rs`](../tentacle/examples/quic_simple.rs)。

```bash
# Terminal A
cargo run --features quic --example quic_simple -- server

# Terminal B
cargo run --features quic --example quic_simple -- client
```

example 里的 `PHandle` / `SHandle` 实现和 `examples/simple.rs` 一字不差。
**唯一的差别**就是两处：

1. 多了一行 `.quic_config(QuicConfig::default())`；
2. listen / dial 的地址形态从 `/tcp/...` 改成 `/udp/.../quic-v1`。

这正是设计意图：启用 QUIC 是一次配置选择，**而不是一次 API 改写**。
