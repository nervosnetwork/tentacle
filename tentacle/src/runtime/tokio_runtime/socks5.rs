use std::io;

use log::debug;
use shadowsocks::relay::socks5::{
    self, Address, Command, Error as Socks5Error, HandshakeRequest, HandshakeResponse,
    PasswdAuthRequest, PasswdAuthResponse, Reply, TcpRequestHeader, TcpResponseHeader,
};
use tokio::net::TcpStream;

#[derive(Debug)]
pub(crate) struct Socks5Config {
    pub(crate) proxy_url: String,
    pub(crate) auth: Option<(String, String)>,
}

// parse proxy url like "socks5://username:password@localhost:1080" to Socks5Config
pub(crate) fn parse(proxy_url: &str) -> io::Result<Socks5Config> {
    let parsed_url = url::Url::parse(proxy_url).map_err(|err| io::Error::other(err))?;
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
            let port = parsed_url.port().ok_or(io::Error::other("missing port"))?;
            let proxy_url = String::new()
                + parsed_url
                    .host_str()
                    .ok_or(io::Error::other("missing host"))?
                + ":"
                + &format!("{port}");
            Ok(Socks5Config { proxy_url, auth })
        }
        _ => Err(io::Error::other(format!(
            "tentacle doesn't support proxy scheme: {}",
            scheme
        ))),
    }
}

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
