use std::io;
use std::net::SocketAddr;

use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes256;
use aes_gcm::{AeadInOut as _, AesGcm, KeyInit as _, Nonce};
use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use tokio::net::UdpSocket;
use tokio_util::codec::{Decoder, Encoder};
use tokio_util::udp::UdpFramed;

pub async fn proxy(
    server_addr: SocketAddr,
    c2s_key: &[u8; 32],
    c2s_salt: [u8; 8],
    s2c_key: &[u8; 32],
    s2c_salt: [u8; 8],
) -> SocketAddr {
    let client_codec = Codec::new(s2c_key, s2c_salt, c2s_key, c2s_salt);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let mut client = UdpFramed::new(client, client_codec);

    let server_codec = Codec::new(c2s_key, c2s_salt, s2c_key, s2c_salt);
    let server = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let mut server = UdpFramed::new(server, server_codec);

    tokio::spawn(async move {
        let mut client_addr = None;

        loop {
            let (packet, from_server) = tokio::select! {
                packet = client.next() => {
                    let Some(packet) = packet else { break };
                    let (packet, addr) = packet.unwrap();

                    match client_addr {
                        None => client_addr = Some(addr),
                        Some(expected) if addr != expected => continue,
                        _ => {}
                    }

                    (packet, false)
                }

                packet = server.next() => {
                    let Some(packet) = packet else { break };
                    let (packet, addr) = packet.unwrap();

                    if addr != server_addr {
                        continue;
                    }

                    (packet, true)
                }
            };

            if from_server {
                if let Some(addr) = client_addr {
                    client.send((packet, addr)).await.unwrap();
                }
            } else {
                server.send((packet, server_addr)).await.unwrap();
            }
        }
    });

    client_addr
}

const HEADER_SIZE: usize = 34;

#[derive(Debug, Clone)]
pub struct Packet {
    pub prefix:   [u8; 16],
    pub conn:     u32,
    pub kind:     u8,
    pub seq:      u32,
    pub ack:      u32,
    pub ack_bits: u64,
    pub flags:    u8,
    pub payload:  Bytes,
}

type Cipher = AesGcm<Aes256, U12, U12>;

pub struct Codec {
    encryptor:      Cipher,
    encryptor_salt: [u8; 8],
    decryptor:      Cipher,
    decryptor_salt: [u8; 8],
}

impl Codec {
    pub fn new(
        encryptor_key: &[u8; 32],
        encryptor_salt: [u8; 8],
        decryptor_key: &[u8; 32],
        decryptor_salt: [u8; 8],
    ) -> Self {
        Self {
            encryptor: Cipher::new(encryptor_key.into()),
            encryptor_salt,
            decryptor: Cipher::new(decryptor_key.into()),
            decryptor_salt,
        }
    }

    fn nonce(salt: &[u8; 8], seq: u32) -> Nonce<U12> {
        let mut nonce = Nonce::<U12>::default();
        nonce[..8].copy_from_slice(salt);
        nonce[8..].copy_from_slice(&seq.to_le_bytes());
        nonce
    }
}

impl Encoder<Packet> for Codec {
    type Error = io::Error;

    fn encode(&mut self, src: Packet, dst: &mut BytesMut) -> io::Result<()> {
        dst.reserve(16 + HEADER_SIZE + src.payload.len());
        dst.extend_from_slice(&src.prefix);

        let start = dst.len();

        dst.extend_from_slice(&[0; 12]);
        dst.put_u32_le((src.conn << 4) | u32::from(src.kind));
        dst.put_u32_le(src.seq);
        dst.put_u32_le(src.ack);
        dst.put_u64_le(src.ack_bits);
        dst.put_u8(src.flags);
        dst.put_u8(0xAD);
        dst.extend_from_slice(&src.payload);

        let (header, payload) = dst[start..].split_at_mut(HEADER_SIZE);
        let tag = self
            .encryptor
            .encrypt_inout_detached(
                &Self::nonce(&self.encryptor_salt, src.seq),
                &header[12..],
                payload.into(),
            )
            .unwrap();

        dst[start..start + 12].copy_from_slice(&tag);

        Ok(())
    }
}

impl Decoder for Codec {
    type Item = Packet;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Packet>> {
        if src.is_empty() {
            return Ok(None);
        }

        let mut payload = src.split();
        let prefix = payload.split_to(16).as_ref().try_into().unwrap();
        let header = payload.split_to(HEADER_SIZE);

        let mut buf = &header[12..];
        let word = buf.get_u32_le();
        let seq = buf.get_u32_le();
        let ack = buf.get_u32_le();
        let ack_bits = buf.get_u64_le();
        let flags = buf.get_u8();

        self.decryptor
            .decrypt_inout_detached(
                &Self::nonce(&self.decryptor_salt, seq),
                &header[12..],
                payload.as_mut().into(),
                header[..12].try_into().unwrap(),
            )
            .unwrap();

        Ok(Some(Packet {
            prefix,
            conn: word >> 4,
            kind: (word & 0xF) as u8,
            seq,
            ack,
            ack_bits,
            flags,
            payload: payload.freeze(),
        }))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> io::Result<Option<Packet>> {
        self.decode(src)
    }
}
