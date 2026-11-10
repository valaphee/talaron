use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::{Buf as _, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use panama::Panama;
use panama::cipher::{KeyIvInit, StreamCipher};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Decoder, Encoder, Framed};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
};

use crate::{C2S, S2C, jam, socket};

pub async fn proxy(addr: SocketAddr, cid: u64, keys: [[u8; 64]; 4]) {
    let protocols = jam::schema::parse(&std::fs::read_to_string("research/jam.xml").unwrap());

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
        let start = Instant::now();

        let mut server = socket().connect(addr).await.unwrap();

        let hello = forward::<17>(&mut client, &mut server).await;
        assert_eq!(&hello, b"HELLO PRO CLIENT\0");

        let hello = forward::<17>(&mut server, &mut client).await;
        assert_eq!(&hello, b"HELLO PRO SERVER\0");

        let client_challenge = forward::<40>(&mut client, &mut server).await;
        assert_eq!(
            u64::from_le_bytes(client_challenge[..8].try_into().unwrap()),
            cid
        );
        let client_nonce = &client_challenge[8..];

        let server_challenge = forward::<65>(&mut server, &mut client).await;
        let challenge = &server_challenge[..32];
        let difficulty = u32::from(server_challenge[32]);
        let server_nonce = &server_challenge[33..];

        let client_proof = forward::<40>(&mut client, &mut server).await;
        assert_eq!(
            u64::from_le_bytes(client_proof[..8].try_into().unwrap()),
            pow(challenge, difficulty)
        );
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
        let c2s_encryptor = Panama::new_from_slices(&c2s, &c2s).unwrap();
        let c2s_decryptor = Panama::new_from_slices(&c2s, &c2s).unwrap();

        let s2c = hmac_sha256(&keys[2], &[client_nonce, server_nonce]);
        let mut s2c_encryptor = Panama::new_from_slices(&s2c, &s2c).unwrap();
        let mut s2c_decryptor = Panama::new_from_slices(&s2c, &s2c).unwrap();

        let mut bytes = [0; 467];
        server.read_exact(&mut bytes).await.unwrap();
        s2c_decryptor.apply_keystream(&mut bytes);
        s2c_encryptor.apply_keystream(&mut bytes);
        client.write_all(&bytes).await.unwrap();

        let client = Framed::new(
            client,
            LobbyCodec {
                encryptor: s2c_encryptor,
                decryptor: c2s_decryptor,
                decrypted: 0,
            },
        );

        let server = Framed::new(
            server,
            LobbyCodec {
                encryptor: c2s_encryptor,
                decryptor: s2c_decryptor,
                decrypted: 0,
            },
        );

        let (mut client_tx, mut client_rx) = client.split();
        let (mut server_tx, mut server_rx) = server.split();

        let mut channels = vec![protocols.first().unwrap()];

        loop {
            let (bytes, server) = tokio::select! {
                packet = client_rx.next() => {
                    let Some(packet) = packet else { break };
                    (packet.unwrap(), false)
                }
                packet = server_rx.next() => {
                    let Some(packet) = packet else { break };
                    (packet.unwrap(), true)
                }
            };

            let mut buf = &bytes[..];

            let channel_id = buf.get_u8();
            let message_type = buf.get_u8();

            let protocol = channels[channel_id as usize];
            let message_type = &protocol.messages[message_type as usize];
            if let Ok(message) = jam::decode(&message_type, &mut buf) {
                println!(
                    "[{:9.3}] {} {} {} {:?}",
                    start.elapsed().as_secs_f64(),
                    if server {
                        format!("{S2C}S → C{S2C:#}")
                    } else {
                        format!("{C2S}C → S{C2S:#}")
                    },
                    protocol.name,
                    message_type.name,
                    message
                );

                if message_type.id == 1 {
                    for protocol_crc in message["0"].as_slice() {
                        let protocol_crc = protocol_crc.as_u32();
                        channels.push(
                            protocols
                                .iter()
                                .find(|protocol| protocol.crc == protocol_crc)
                                .unwrap(),
                        );
                    }
                }
            }

            if server {
                client_tx.send(bytes).await.unwrap();
            } else {
                server_tx.send(bytes).await.unwrap();
            }
        }
    });
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn pow(challenge: &[u8], difficulty: u32) -> u64 {
    let bytes = (difficulty / 8) as usize;
    let bits = difficulty % 8;
    let mask = ((1u16 << bits) - 1) as u8;

    let mut prefix = Sha1::new();
    prefix.update(challenge);

    for counter in 1..=u64::MAX {
        let mut hasher = prefix.clone();
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        if digest[..bytes].iter().all(|&b| b == 0) && (bits == 0 || digest[bytes] & mask == 0) {
            return counter;
        }
    }

    unreachable!()
}

pub struct LobbyCodec {
    encryptor: Panama,
    decryptor: Panama,
    decrypted: usize,
}

impl Encoder<Bytes> for LobbyCodec {
    type Error = io::Error;

    fn encode(&mut self, src: Bytes, dst: &mut BytesMut) -> io::Result<()> {
        let start = dst.len();

        dst.reserve(3 + src.len());

        dst.extend_from_slice(&(src.len() as u32).to_be_bytes()[1..]);
        dst.extend_from_slice(&src);

        self.encryptor.apply_keystream(&mut dst[start..]);

        Ok(())
    }
}

impl Decoder for LobbyCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        self.decryptor.apply_keystream(&mut src[self.decrypted..]);
        self.decrypted = src.len();

        if src.len() < 3 {
            return Ok(None);
        }

        let len = u32::from_be_bytes([0, src[0], src[1], src[2]]) as usize;

        if src.len() < 3 + len {
            return Ok(None);
        }

        src.advance(3);
        self.decrypted -= 3 + len;

        Ok(Some(src.split_to(len).freeze()))
    }
}

async fn forward<const N: usize>(src: &mut TcpStream, dst: &mut TcpStream) -> [u8; N] {
    let mut bytes = [0; N];
    src.read_exact(&mut bytes).await.unwrap();
    dst.write_all(&bytes).await.unwrap();
    bytes
}
