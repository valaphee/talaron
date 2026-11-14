use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use futures_util::{SinkExt, StreamExt};
use prost_reflect::prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, rustls};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::{accept_hdr_async, client_async_tls};

use crate::{C2S, S2C, lobby};

const HOST: &str = "eu.actual.battle.net";
const ADDR: &str = "35.204.119.70:1119";
const PROTOCOL: &str = "v1.rpc.battle.net";

pub async fn proxy() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let tls_acceptor = TlsAcceptor::from(Arc::new({
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                rustls_pemfile::certs(&mut BufReader::new(File::open("fullchain.pem").unwrap()))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                rustls_pemfile::private_key(&mut BufReader::new(
                    File::open("privkey.pem").unwrap(),
                ))
                .unwrap()
                .unwrap(),
            )
            .unwrap();

        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config
    }));

    let pool = DescriptorPool::decode(
        fs::read("research/proto/descriptors.pb")
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:1119").await.unwrap();

    loop {
        let (client, _) = listener.accept().await.unwrap();
        let start = Instant::now();

        let tls_acceptor = tls_acceptor.clone();
        let pool = pool.clone();

        tokio::spawn(async move {
            let client = tls_acceptor.accept(client).await.unwrap();
            let mut request = format!("wss://{HOST}:1119/").into_client_request().unwrap();
            request
                .headers_mut()
                .insert("Sec-WebSocket-Protocol", PROTOCOL.parse().unwrap());

            let server = TcpStream::connect(ADDR).await.unwrap();
            let (server, response) = client_async_tls(request, server).await.unwrap();
            assert_eq!(
                response
                    .headers()
                    .get("Sec-WebSocket-Protocol")
                    .and_then(|value| value.to_str().ok()),
                Some(PROTOCOL),
            );

            let client = accept_hdr_async(client, |_: &Request, mut response: Response| {
                response
                    .headers_mut()
                    .insert("Sec-WebSocket-Protocol", PROTOCOL.parse().unwrap());
                Ok(response)
            })
            .await
            .unwrap();

            let (mut client_tx, mut client_rx) = client.split();
            let (mut server_tx, mut server_rx) = server.split();

            let mut pending = HashMap::new();

            let header_type = pool.get_message_by_name("bgs.protocol.Header").unwrap();

            let service_options = pool
                .get_extension_by_name("bgs.protocol.service_options")
                .unwrap();
            let services: HashMap<_, _> = pool
                .services()
                .map(|service| {
                    let options = service.options();
                    let value = options.get_extension(&service_options);
                    let name = value
                        .as_message()
                        .unwrap()
                        .get_field_by_name("descriptor_name")
                        .unwrap();

                    (fnv1a(name.as_str().unwrap()), service)
                })
                .collect();

            let method_options = pool
                .get_extension_by_name("bgs.protocol.method_options")
                .unwrap();

            loop {
                let (mut message, server) = tokio::select! {
                    message = client_rx.next() => {
                        let Some(message) = message else { break };
                        (message.unwrap(), false)
                    }
                    message = server_rx.next() => {
                        let Some(message) = message else { break };
                        (message.unwrap(), true)
                    }
                };

                if let Message::Binary(bytes) = &message {
                    let (length, bytes) = bytes.split_first_chunk::<2>().unwrap();
                    let (header, payload) = bytes.split_at(u16::from_be_bytes(*length).into());

                    let header = DynamicMessage::decode(header_type.clone(), header).unwrap();

                    let token = header.get_field_by_name("token").unwrap().as_u32().unwrap();

                    let response = header
                        .get_field_by_name("service_id")
                        .unwrap()
                        .as_u32()
                        .unwrap()
                        == 0xFE;

                    let method = if response {
                        pending.remove(&(!server, token))
                    } else {
                        let service_hash = header
                            .get_field_by_name("service_hash")
                            .unwrap()
                            .as_u32()
                            .unwrap();

                        let method_id = header
                            .get_field_by_name("method_id")
                            .unwrap()
                            .as_u32()
                            .unwrap();

                        services.get(&service_hash).and_then(|service| {
                            service.methods().find(|method| {
                                method
                                    .options()
                                    .get_extension(&method_options)
                                    .as_message()
                                    .unwrap()
                                    .get_field_by_name("id")
                                    .unwrap()
                                    .as_u32()
                                    .unwrap()
                                    == method_id
                            })
                        })
                    };

                    if let Some(method) = method {
                        if !response {
                            pending.insert((server, token), method.clone());
                        }

                        let mut payload = DynamicMessage::decode(
                            if response {
                                method.output()
                            } else {
                                method.input()
                            },
                            payload,
                        )
                        .unwrap();

                        println!(
                            "[{:9.3}] {} {} {}",
                            start.elapsed().as_secs_f64(),
                            if server {
                                format!("{S2C}S → C{S2C:#}")
                            } else {
                                format!("{C2S}C → S{C2S:#}")
                            },
                            method.full_name(),
                            payload.to_text_format(),
                        );

                        if response
                            && method.full_name()
                                == "bgs.protocol.game_utilities.v2.client.GameUtilitiesService.ProcessTask"
                        {
                            let result = payload.get_field_by_name_mut("result").unwrap();

                            let mut keys: [Option<[u8; 64]>; 4] = [None; 4];
                            let mut cid = None;
                            let mut host: Option<SocketAddr> = None;

                            for field in result.as_list().unwrap() {
                                let field = field.as_message().unwrap();
                                let value = field.get_field_by_name("value").unwrap();
                                let value = value.as_message().unwrap();

                                match field.get_field_by_name("name").unwrap().as_str().unwrap() {
                                    name @ ("k0" | "k1" | "k2" | "k3") => {
                                        keys[usize::from(name.as_bytes()[1] - b'0')] = Some(
                                            value
                                                .get_field_by_name("blob_value")
                                                .unwrap()
                                                .as_bytes()
                                                .unwrap()
                                                .as_ref()
                                                .try_into()
                                                .unwrap(),
                                        );
                                    }
                                    "cid" => {
                                        cid = Some(
                                            value
                                                .get_field_by_name("uint_value")
                                                .unwrap()
                                                .as_u64()
                                                .unwrap(),
                                        );
                                    }
                                    "hostv4" => {
                                        host = Some(
                                            value
                                                .get_field_by_name("string_value")
                                                .unwrap()
                                                .as_str()
                                                .unwrap()
                                                .parse()
                                                .unwrap(),
                                        );
                                    }
                                    _ => {}
                                }
                            }

                            let addr =
                                lobby::proxy(host.unwrap(), cid.unwrap(), keys.map(Option::unwrap))
                                    .await;

                            for field in result.as_list_mut().unwrap() {
                                let field = field.as_message_mut().unwrap();
                                if field.get_field_by_name("name").unwrap().as_str()
                                    == Some("hostv4")
                                {
                                    field
                                        .get_field_by_name_mut("value")
                                        .unwrap()
                                        .as_message_mut()
                                        .unwrap()
                                        .set_field_by_name(
                                            "string_value",
                                            Value::String(addr.to_string()),
                                        );
                                }
                            }

                            let header = header.encode_to_vec();
                            let mut bytes =
                                u16::try_from(header.len()).unwrap().to_be_bytes().to_vec();
                            bytes.extend_from_slice(&header);
                            bytes.extend_from_slice(&payload.encode_to_vec());
                            message = Message::Binary(bytes.into());
                        }
                    }
                }

                if matches!(&message, Message::Ping(_) | Message::Pong(_)) {
                    continue;
                }

                let closing = message.is_close();

                if server {
                    client_tx.send(message).await.unwrap();
                } else {
                    server_tx.send(message).await.unwrap();
                }

                if closing {
                    break;
                }
            }
        });
    }
}

fn fnv1a(name: &str) -> u32 {
    name.bytes().fold(0x811C9DC5u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x01000193)
    })
}
