use std::borrow::Cow;

use parity_multiaddr::{Multiaddr as OtherMultiaddr, Protocol as OtherProtocol};
use tentacle_multiaddr::{Multiaddr, Protocol};
mod onion;
mod quic;

#[test]
fn compatibility_test() {
    let mut address: Multiaddr = "/ip4/127.0.0.1".parse().unwrap();
    address.push(Protocol::Tcp(10000));
    assert_eq!(address, "/ip4/127.0.0.1/tcp/10000".parse().unwrap());

    let _address: Multiaddr = "/ip4/127.0.0.1/tcp/20/tls/main".parse().unwrap();

    let mut address_1: Multiaddr =
        "/ip4/47.111.169.36/tcp/8111/p2p/QmNQ4jky6uVqLDrPU7snqxARuNGWNLgSrTnssbRuy3ij2W"
            .parse()
            .unwrap();

    let mut address_2: OtherMultiaddr =
        "/ip4/47.111.169.36/tcp/8111/p2p/QmNQ4jky6uVqLDrPU7snqxARuNGWNLgSrTnssbRuy3ij2W"
            .parse()
            .unwrap();

    let p_1 = address_1.pop().unwrap();
    let p_2 = address_2.pop().unwrap();

    match (p_1, p_2) {
        (Protocol::P2P(s_1), OtherProtocol::P2p(s_2)) => assert_eq!(s_1, s_2.to_bytes()),
        e => panic!("not expect protocol: {:?}", e),
    }
}

#[test]
fn empty_test() {
    let address = "/".parse::<Multiaddr>().unwrap_err();
    assert_eq!(address.to_string(), "unknown protocol string");

    let address = " ".parse::<Multiaddr>().unwrap_err();
    assert_eq!(address.to_string(), "invalid multiaddr");

    let address = "".parse::<Multiaddr>().unwrap_err();
    assert_eq!(address.to_string(), "invalid multiaddr");
}

fn invalid_p2p() -> Protocol<'static> {
    Protocol::P2P(Cow::Owned(vec![0]))
}

#[test]
#[should_panic(expected = "invalid p2p multihash bytes")]
fn invalid_p2p_protocol_rejected_by_from_protocol() {
    let _address = Multiaddr::from(invalid_p2p());
}

#[test]
#[should_panic(expected = "invalid p2p multihash bytes")]
fn invalid_p2p_protocol_rejected_by_push() {
    let mut address: Multiaddr = "/ip4/127.0.0.1/tcp/10000".parse().unwrap();
    address.push(invalid_p2p());
}

#[test]
#[should_panic(expected = "invalid p2p multihash bytes")]
fn invalid_p2p_protocol_rejected_by_from_iterator() {
    let _address: Multiaddr = vec![invalid_p2p()].into_iter().collect();
}

#[test]
fn valid_p2p_protocol_constructors_still_work() {
    let source = "/p2p/QmNQ4jky6uVqLDrPU7snqxARuNGWNLgSrTnssbRuy3ij2W";
    let mut parsed: Multiaddr = source.parse().unwrap();
    let p2p = parsed.pop().unwrap();

    assert_eq!(Multiaddr::from(p2p.clone()).to_string(), source);

    let mut pushed: Multiaddr = "/ip4/127.0.0.1/tcp/10000".parse().unwrap();
    pushed.push(p2p.clone());
    assert_eq!(
        pushed.to_string(),
        format!("/ip4/127.0.0.1/tcp/10000{}", source)
    );

    let collected: Multiaddr = vec![p2p].into_iter().collect();
    assert_eq!(collected.to_string(), source);
}
