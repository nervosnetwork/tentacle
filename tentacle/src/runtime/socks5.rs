use log::{debug, trace};
use shadowsocks::relay::socks5::{
    self, Address, Command, Error as Socks5Error, HandshakeRequest, HandshakeResponse,
    PasswdAuthRequest, PasswdAuthResponse, Reply, TcpRequestHeader, TcpResponseHeader,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, ToSocketAddrs},
};

use crate::service::ProxyConfig;

pub(crate) struct Socks5Config {
    pub(crate) proxy_url: String,
    pub(crate) auth: Option<(String, String)>,
}

// parse proxy url like "socks5://username:password@localhost:1080" to Socks5Config
pub(crate) fn parse(proxy_url: &str) -> Result<Socks5Config, std::error::Error> {
    let parsed_url = url::Url::parse(proxy_url)?;
    let scheme = parsed_url.scheme();
    match scheme {
        "socks5" => {
            let auth = match parsed_url.username() {
                "" => None,
                username => Some((
                    username.to_string(),
                    parsed_url.password().unwrap_or("").to_string(),
                )),
            };
            let proxy_url = parsed_url.host_str().ok_or(Err("missing host"))?;
            Ok(Socks5Config {
                proxy_url,
                auth,
            })
        }
        _ => Err(format!("tentacle doesn't support proxy scheme: {}", scheme).into(),
    }
}

pub async fn connect<A, P>(
    addr: A,
    socks5_config: Socks5Config,
) -> Result<TcpStream, Socks5Error>
where
    A: Into<Address>,
    P: ToSocketAddrs,
{
    debug!("client connecting proxy server");
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
            let pr = PasswdAuthRequest::new(auth.0, auth.1);
            pr.write_to(&mut s).await?;
            let prp = PasswdAuthResponse::read_from(&mut s).await?;
            match Reply::from_u8(prp.status) {
                Reply::Succeeded => debug!("password auth succeeded"),
                r => return Err(Socks5Error::Reply(r)),
            }
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
