use std::io;

use log::debug;
use shadowsocks::relay::socks5::{
    self, Address, Command, Error as Socks5Error, HandshakeRequest, HandshakeResponse,
    PasswdAuthRequest, PasswdAuthResponse, Reply, TcpRequestHeader, TcpResponseHeader,
};
use tokio::net::TcpStream;

use super::super::socks5_config::Socks5Config;

pub async fn connect<A>(addr: A, socks5_config: Socks5Config) -> Result<TcpStream, Socks5Error>
where
    A: Into<Address>,
{
    debug!(
        "client connecting proxy server: config {}, with auth: {}",
        socks5_config.proxy_url,
        socks5_config.auth.is_some()
    );
    // destruct socks5_config
    let Socks5Config { auth, proxy_url } = socks5_config;

    let mut s = TcpStream::connect(proxy_url).await?;

    // 1. Handshake
    let hs = {
        if auth.is_some() {
            HandshakeRequest::new(vec![socks5::SOCKS5_AUTH_METHOD_PASSWORD])
        } else {
            HandshakeRequest::new(vec![socks5::SOCKS5_AUTH_METHOD_NONE])
        }
    };
    debug!("client connected, going to send handshake: {:?}", hs);

    hs.write_to(&mut s).await?;

    let hsp = HandshakeResponse::read_from(&mut s).await?;

    debug!("got handshake response: {:?}", hsp);
    match hsp.chosen_method {
        socks5::SOCKS5_AUTH_METHOD_NONE => (),
        socks5::SOCKS5_AUTH_METHOD_PASSWORD => {
            if let Some((uname, passwd)) = auth {
                let pr = PasswdAuthRequest::new(uname, passwd);
                pr.write_to(&mut s).await?;
                let prp = PasswdAuthResponse::read_from(&mut s).await?;
                match Reply::from_u8(prp.status) {
                    Reply::Succeeded => debug!("password auth succeeded"),
                    r => return Err(Socks5Error::Reply(r)),
                }
            } else {
                return Err(Socks5Error::PasswdAuthInvalidRequest);
            }
        }
        _ => {
            return Err(Socks5Error::IoError(io::Error::other(format!(
                "unsupported auth method: {}",
                hsp.chosen_method
            ))))
        }
    }

    // 2. Send request header
    let h = TcpRequestHeader::new(Command::TcpConnect, addr.into());
    debug!("going to connect, req: {:?}", h);
    h.write_to(&mut s).await?;

    let hp = TcpResponseHeader::read_from(&mut s).await?;

    debug!("got response: {:?}", hp);
    match hp.reply {
        Reply::Succeeded => (),
        r => return Err(Socks5Error::Reply(r)),
    }

    Ok(s)
}
