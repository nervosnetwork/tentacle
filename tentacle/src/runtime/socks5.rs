use log::trace;
use shadowsocks::relay::socks5::{
    self, Address, Command, Error, HandshakeRequest, HandshakeResponse, Reply, TcpRequestHeader,
    TcpResponseHeader,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, ToSocketAddrs},
};

pub async fn connect<A, P>(addr: A, proxy: P) -> Result<TcpStream, Error>
where
    A: Into<Address>,
    P: ToSocketAddrs,
{
    let mut s = TcpStream::connect(proxy).await?;

    // 1. Handshake
    let hs = HandshakeRequest::new(vec![socks5::SOCKS5_AUTH_METHOD_NONE]);
    trace!("client connected, going to send handshake: {:?}", hs);

    hs.write_to(&mut s).await?;

    let hsp = HandshakeResponse::read_from(&mut s).await?;

    trace!("got handshake response: {:?}", hsp);
    assert_eq!(hsp.chosen_method, socks5::SOCKS5_AUTH_METHOD_NONE);

    // 2. Send request header
    let h = TcpRequestHeader::new(Command::TcpConnect, addr.into());
    trace!("going to connect, req: {:?}", h);
    h.write_to(&mut s).await?;

    let hp = TcpResponseHeader::read_from(&mut s).await?;

    trace!("got response: {:?}", hp);
    match hp.reply {
        Reply::Succeeded => (),
        r => return Err(Error::Reply(r)),
    }

    Ok(s)
}
