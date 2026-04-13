use data_encoding::HEXUPPER;
use std::convert::TryFrom;
use tentacle_multiaddr::{Multiaddr, Protocol};

/// Helper: parse a multiaddr string, verify hex encoding roundtrip, protocol list, and Display roundtrip.
fn ma_valid(source: &str, target: &str, protocols: Vec<Protocol<'_>>) {
    let parsed = source.parse::<Multiaddr>().unwrap();
    assert_eq!(HEXUPPER.encode(&parsed.to_vec()[..]), target);
    assert_eq!(parsed.iter().collect::<Vec<_>>(), protocols);
    assert_eq!(parsed.to_string(), source);
    assert_eq!(
        Multiaddr::try_from(HEXUPPER.decode(target.as_bytes()).unwrap()).unwrap(),
        parsed
    );
}

// ────────────────────────── String parse → Display roundtrip ──────────────────────────

#[test]
fn parse_ip4_udp_quic() {
    let addr: Multiaddr = "/ip4/127.0.0.1/udp/4433/quic".parse().unwrap();
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/4433/quic");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Ip4("127.0.0.1".parse().unwrap()),
            Protocol::Udp(4433),
            Protocol::Quic,
        ]
    );
}

#[test]
fn parse_ip6_udp_quic() {
    let addr: Multiaddr = "/ip6/::1/udp/4433/quic".parse().unwrap();
    assert_eq!(addr.to_string(), "/ip6/::1/udp/4433/quic");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Ip6("::1".parse().unwrap()),
            Protocol::Udp(4433),
            Protocol::Quic,
        ]
    );
}

#[test]
fn parse_udp_port_zero() {
    let addr: Multiaddr = "/ip4/0.0.0.0/udp/0/quic".parse().unwrap();
    assert_eq!(addr.to_string(), "/ip4/0.0.0.0/udp/0/quic");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Ip4("0.0.0.0".parse().unwrap()),
            Protocol::Udp(0),
            Protocol::Quic,
        ]
    );
}

#[test]
fn parse_udp_port_max() {
    let addr: Multiaddr = "/ip4/10.0.0.1/udp/65535/quic".parse().unwrap();
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Ip4("10.0.0.1".parse().unwrap()),
            Protocol::Udp(65535),
            Protocol::Quic,
        ]
    );
}

#[test]
fn parse_udp_alone() {
    // UDP without /quic is also a valid multiaddr
    let addr: Multiaddr = "/ip4/127.0.0.1/udp/1234".parse().unwrap();
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/1234");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Ip4("127.0.0.1".parse().unwrap()),
            Protocol::Udp(1234),
        ]
    );
}

#[test]
fn parse_quic_with_p2p_suffix() {
    // A realistic QUIC address with /p2p/<peer_id> suffix
    // Use a well-formed peer_id (sha256 multihash)
    let peer_id_b58 = "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC";
    let source = format!("/ip4/192.168.1.1/udp/4433/quic/p2p/{}", peer_id_b58);
    let addr: Multiaddr = source.parse().unwrap();
    assert_eq!(addr.to_string(), source);

    let protos: Vec<_> = addr.iter().collect();
    assert_eq!(protos.len(), 4);
    assert_eq!(protos[0], Protocol::Ip4("192.168.1.1".parse().unwrap()));
    assert_eq!(protos[1], Protocol::Udp(4433));
    assert_eq!(protos[2], Protocol::Quic);
    match &protos[3] {
        Protocol::P2P(_) => {} // ok
        other => panic!("expected P2P, got {:?}", other),
    }
}

// ────────────────────────── Binary (bytes) roundtrip ──────────────────────────

#[test]
fn bytes_roundtrip_ip4_udp_quic() {
    let addr: Multiaddr = "/ip4/127.0.0.1/udp/4433/quic".parse().unwrap();
    let bytes = addr.to_vec();
    let decoded = Multiaddr::try_from(bytes).unwrap();
    assert_eq!(decoded, addr);
}

#[test]
fn bytes_roundtrip_ip6_udp_quic() {
    let addr: Multiaddr = "/ip6/::1/udp/4433/quic".parse().unwrap();
    let bytes = addr.to_vec();
    let decoded = Multiaddr::try_from(bytes).unwrap();
    assert_eq!(decoded, addr);
}

#[test]
fn bytes_roundtrip_udp_alone() {
    let addr: Multiaddr = "/ip4/10.0.0.1/udp/8080".parse().unwrap();
    let bytes = addr.to_vec();
    let decoded = Multiaddr::try_from(bytes).unwrap();
    assert_eq!(decoded, addr);
}

// ────────────────────────── Hex encoding roundtrip (ma_valid style) ──────────────────────────

#[test]
fn hex_roundtrip_ip4_udp_quic() {
    let addr: Multiaddr = "/ip4/127.0.0.1/udp/4433/quic".parse().unwrap();
    let hex = HEXUPPER.encode(&addr.to_vec()[..]);

    ma_valid(
        "/ip4/127.0.0.1/udp/4433/quic",
        &hex,
        vec![
            Protocol::Ip4("127.0.0.1".parse().unwrap()),
            Protocol::Udp(4433),
            Protocol::Quic,
        ],
    );
}

// ────────────────────────── Protocol push / pop ──────────────────────────

#[test]
fn push_pop_quic() {
    let mut addr: Multiaddr = "/ip4/127.0.0.1/udp/4433".parse().unwrap();
    addr.push(Protocol::Quic);
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/4433/quic");

    let popped = addr.pop().unwrap();
    assert_eq!(popped, Protocol::Quic);
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/4433");
}

#[test]
fn push_pop_udp() {
    let mut addr: Multiaddr = "/ip4/127.0.0.1".parse().unwrap();
    addr.push(Protocol::Udp(9999));
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/9999");

    let popped = addr.pop().unwrap();
    assert_eq!(popped, Protocol::Udp(9999));
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1");
}

// ────────────────────────── acquire() (owned conversion) ──────────────────────────

#[test]
fn acquire_udp_quic() {
    let addr: Multiaddr = "/ip4/10.0.0.1/udp/4433/quic".parse().unwrap();
    let protos: Vec<Protocol<'static>> = addr.iter().map(|p| p.acquire()).collect();
    assert_eq!(protos.len(), 3);
    assert_eq!(protos[1], Protocol::Udp(4433));
    assert_eq!(protos[2], Protocol::Quic);
}

// ────────────────────────── DNS + QUIC (parseable at multiaddr layer) ──────────────────────────
// NOTE: DNS-based QUIC addresses are rejected by tentacle's transport layer (v1),
// but multiaddr itself should parse them fine — it's a generic address format.

#[test]
fn parse_dns4_udp_quic_is_valid_multiaddr() {
    let addr: Multiaddr = "/dns4/example.com/udp/4433/quic".parse().unwrap();
    assert_eq!(addr.to_string(), "/dns4/example.com/udp/4433/quic");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Dns4("example.com".into()),
            Protocol::Udp(4433),
            Protocol::Quic,
        ]
    );
}

#[test]
fn parse_dns6_udp_quic_is_valid_multiaddr() {
    let addr: Multiaddr = "/dns6/example.com/udp/4433/quic".parse().unwrap();
    assert_eq!(addr.to_string(), "/dns6/example.com/udp/4433/quic");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Dns6("example.com".into()),
            Protocol::Udp(4433),
            Protocol::Quic,
        ]
    );
}

// ────────────────────────── Error cases ──────────────────────────

#[test]
fn fail_udp_missing_port() {
    // "/udp" without a port number
    assert!("/udp".parse::<Multiaddr>().is_err());
}

#[test]
fn fail_udp_non_numeric_port() {
    assert!("/udp/abc".parse::<Multiaddr>().is_err());
}

#[test]
fn fail_udp_port_overflow() {
    // 65536 > u16::MAX
    assert!("/ip4/127.0.0.1/udp/65536".parse::<Multiaddr>().is_err());
}

#[test]
fn fail_udp_negative_port() {
    assert!("/ip4/127.0.0.1/udp/-1".parse::<Multiaddr>().is_err());
}

#[test]
fn fail_unknown_protocol() {
    // Make sure adding udp/quic didn't break unknown protocol detection
    assert!("/ip4/127.0.0.1/foobar/123".parse::<Multiaddr>().is_err());
}
