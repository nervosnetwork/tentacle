use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    let cert = rcgen::generate_simple_self_signed(vec![String::from("tentacle.invalid")]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let rustls_server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .unwrap();
    let quinn_server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(rustls_server_config).unwrap(),
    ));

    let server_endpoint =
        quinn::Endpoint::server(quinn_server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();
    println!("Server listening at {:?}", server_addr);
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server_endpoint.accept().await {
            let conn = incoming.await.unwrap();
            let (mut send_conn, mut recv_conn) = conn.accept_bi().await.unwrap();
            let read_data = recv_conn.read_u32_le().await.unwrap();
            if read_data == 0xdeadbeef {
                println!("Server got 0xdeadbeef, writing 0xcafebabe");
                send_conn.write_u32_le(0xcafebabe).await.unwrap();
                send_conn.finish().unwrap();
            } else {
                eprintln!("Server got unexpected value: {read_data:#x}, closing connection");
                conn.close(1u32.into(), b"unexpected request value");
                return;
            }
            // Keep conn alive until the peer closes the connection
            conn.closed().await;
        }
    });

    let rustls_client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
        .with_no_client_auth();

    let quinn_client = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    let quinn_client_conn = quinn_client
        .connect_with(
            quinn::ClientConfig::new(Arc::new(
                QuicClientConfig::try_from(rustls_client_config).unwrap(),
            )),
            server_addr,
            "tentacle.invalid",
        )
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = quinn_client_conn.open_bi().await.unwrap();
    send.write_u32_le(0xdeadbeef).await.unwrap();
    send.finish().unwrap();
    let client_read = recv.read_u32_le().await.unwrap();
    println!("Client read: {:x}, expected to be 0xcafebabe", client_read);
    assert_eq!(client_read, 0xcafebabe);

    // Clean up
    quinn_client_conn.close(0u32.into(), b"done");
    server_handle.await.unwrap();
    println!("Success!");
}

#[derive(Debug)]

struct AcceptAnyVerifier;

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
