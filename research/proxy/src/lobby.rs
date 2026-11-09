use std::io::{Error, Result};
use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use panama::Panama;
use panama::cipher::{KeyIvInit, StreamCipher};
use sha2::Sha256;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Decoder, Encoder, Framed};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
};

use crate::socket;

pub async fn proxy(addr: SocketAddr, keys: [[u8; 64]; 4]) {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe {
        InitializeUnicastIpAddressEntry(&mut row);
        row.InterfaceIndex = 1;
        row.Address = addr.into();
        row.OnLinkPrefixLength = 32;
        row.SkipAsSource = true.into();

        let _ = CreateUnicastIpAddressEntry(&row);
    };

    let listener = TcpListener::bind(addr).await.unwrap();

    tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut server = socket().connect(addr).await.unwrap();

        let hello = forward::<17>(&mut client, &mut server).await;
        assert_eq!(&hello, b"HELLO PRO CLIENT\0");

        let hello = forward::<17>(&mut server, &mut client).await;
        assert_eq!(&hello, b"HELLO PRO SERVER\0");

        let client_nonce = forward::<40>(&mut client, &mut server).await;
        let client_nonce = &client_nonce[8..];

        let server_nonce = forward::<65>(&mut server, &mut client).await;
        let server_nonce = &server_nonce[33..];

        let client_proof = forward::<40>(&mut client, &mut server).await;
        assert_eq!(
            &client_proof[8..],
            hmac_sha256(&keys[0], &[client_nonce, server_nonce]).as_slice()
        );

        let server_proof = forward::<32>(&mut server, &mut client).await;
        assert_eq!(
            &server_proof,
            hmac_sha256(&keys[1], &[server_nonce, client_nonce]).as_slice()
        );

        let c2s = hmac_sha256(&keys[3], &[server_nonce, client_nonce]);
        let s2c = hmac_sha256(&keys[2], &[client_nonce, server_nonce]);

        let client = Framed::new(
            client,
            LobbyCodec {
                encryptor: Panama::new_from_slices(&s2c, &s2c).unwrap(),
                decryptor: Panama::new_from_slices(&c2s, &c2s).unwrap(),
            },
        );

        let server = Framed::new(
            server,
            LobbyCodec {
                encryptor: Panama::new_from_slices(&c2s, &c2s).unwrap(),
                decryptor: Panama::new_from_slices(&s2c, &s2c).unwrap(),
            },
        );

        let (mut client_tx, mut client_rx) = client.split();
        let (mut server_tx, mut server_rx) = server.split();

        tokio::select! {
            _ = async {
                while let Some(bytes) = client_rx.next().await {
                    let bytes = bytes.unwrap();
                    println!("C → S: {bytes:02x?}");

                    server_tx.send(bytes).await.unwrap();
                }
            } => {},
            _ = async {
                while let Some(bytes) = server_rx.next().await {
                    let bytes = bytes.unwrap();
                    println!("S → C: {bytes:02x?}");

                    client_tx.send(bytes).await.unwrap();
                }
            } => {},
        }
    });
}

async fn forward<const N: usize>(src: &mut TcpStream, dst: &mut TcpStream) -> [u8; N] {
    let mut bytes = [0; N];
    src.read_exact(&mut bytes).await.unwrap();
    dst.write_all(&bytes).await.unwrap();
    bytes
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

pub struct LobbyCodec {
    encryptor: Panama,
    decryptor: Panama,
}

impl Encoder<Bytes> for LobbyCodec {
    type Error = Error;

    fn encode(&mut self, src: Bytes, dst: &mut BytesMut) -> Result<()> {
        let start = dst.len();

        dst.extend_from_slice(&src);
        self.encryptor.apply_keystream(&mut dst[start..]);

        Ok(())
    }
}

impl Decoder for LobbyCodec {
    type Item = Bytes;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Bytes>> {
        if src.is_empty() {
            return Ok(None);
        }

        self.decryptor.apply_keystream(src);

        Ok(Some(src.split().freeze()))
    }
}
