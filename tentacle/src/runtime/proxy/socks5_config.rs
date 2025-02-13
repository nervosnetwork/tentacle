use std::io;

#[derive(Debug)]
pub(crate) struct Socks5Config {
    pub(crate) proxy_url: String,
    pub(crate) auth: Option<(String, String)>,
}

// parse proxy url like "socks5://username:password@localhost:1080" to Socks5Config
pub(crate) fn parse(proxy_url: &str) -> io::Result<Socks5Config> {
    let parsed_url = url::Url::parse(proxy_url).map_err(io::Error::other)?;
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
