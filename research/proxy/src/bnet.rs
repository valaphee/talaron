use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use prost_reflect::{DescriptorPool, DynamicMessage, MethodDescriptor};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, rustls};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::{Error as WsError, Message as WsMessage};
use tokio_tungstenite::{accept_hdr_async, client_async_tls};

use crate::lobby;

const HOST: &str = "eu.actual.battle.net";
const ADDR: &str = "35.204.119.70:1119";
const PROTOCOL: &str = "v1.rpc.battle.net";

type Pending = Arc<Mutex<HashMap<(bool, u32), MethodDescriptor>>>;

fn service_hash(name: &str) -> u32 {
    name.bytes().fold(0x811C9DC5u32, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x01000193)
    })
}

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
        std::fs::read("research/proto/descriptors.pb")
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:1119").await.unwrap();
    loop {
        let (client, _) = listener.accept().await.unwrap();

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
                    .and_then(|v| v.to_str().ok()),
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

            let (client_tx, client_rx) = client.split();
            let (server_tx, server_rx) = server.split();

            let pending = Pending::default();

            tokio::select! {
                _ = proxy_direction(&pool, client_rx, server_tx, false, pending.clone()) => {},
                _ = proxy_direction(&pool, server_rx, client_tx, true, pending.clone()) => {},
            }
        });
    }
}

async fn proxy_direction<S, D>(
    pool: &DescriptorPool,
    mut src: S,
    mut dst: D,
    server: bool,
    pending: Pending,
) where
    S: Stream<Item = Result<WsMessage, WsError>> + Unpin,
    D: Sink<WsMessage, Error = WsError> + Unpin,
{
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

            (service_hash(name.as_str().unwrap()), service)
        })
        .collect();

    let method_options = pool
        .get_extension_by_name("bgs.protocol.method_options")
        .unwrap();

    while let Some(message) = src.next().await {
        let message = message.unwrap();

        if let WsMessage::Binary(bytes) = &message {
            let mut bytes = bytes.as_ref();

            let header_len = bytes.read_be::<u16>().unwrap() as usize;
            let (header, body) = bytes.split_at(header_len);

            let header = DynamicMessage::decode(header_type.clone(), header).unwrap();

            let token = header.get_field_by_name("token").unwrap().as_u32().unwrap();
            let response = header
                .get_field_by_name("service_id")
                .unwrap()
                .as_u32()
                .unwrap()
                == 0xFE;

            let method = if response {
                pending.lock().unwrap().remove(&(!server, token))
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
                    pending
                        .lock()
                        .unwrap()
                        .insert((server, token), method.clone());
                }

                let message = DynamicMessage::decode(
                    if response {
                        method.output()
                    } else {
                        method.input()
                    },
                    body,
                )
                .unwrap();

                println!(
                    "{} {} {}",
                    if server { "S → C" } else { "C → S" },
                    method.full_name(),
                    message.to_text_format()
                );

                if response
                    && method.full_name()
                        == "bgs.protocol.game_utilities.v2.client.GameUtilitiesService.ProcessTask"
                {
                    let result = message.get_field_by_name("result").unwrap();
                    let fields: HashMap<String, DynamicMessage> = result
                        .as_list()
                        .unwrap()
                        .iter()
                        .map(|field| {
                            let field = field.as_message().unwrap();

                            (
                                field
                                    .get_field_by_name("name")
                                    .unwrap()
                                    .as_str()
                                    .unwrap()
                                    .to_owned(),
                                field
                                    .get_field_by_name("value")
                                    .unwrap()
                                    .as_message()
                                    .unwrap()
                                    .clone(),
                            )
                        })
                        .collect();

                    let keys: [[u8; 64]; 4] = ["k0", "k1", "k2", "k3"].map(|name| {
                        fields[name]
                            .get_field_by_name("blob_value")
                            .unwrap()
                            .as_bytes()
                            .unwrap()
                            .as_ref()
                            .try_into()
                            .unwrap()
                    });

                    let cid: u64 = fields["cid"]
                        .get_field_by_name("uint_value")
                        .unwrap()
                        .as_u64()
                        .unwrap();

                    let host: SocketAddr = fields["hostv4"]
                        .get_field_by_name("string_value")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .parse()
                        .unwrap();

                    lobby::proxy(host, cid, keys).await;
                }
            }
        }

        if matches!(&message, WsMessage::Ping(_) | WsMessage::Pong(_)) {
            continue;
        }

        let closing = message.is_close();
        dst.send(message).await.unwrap();

        if closing {
            break;
        }
    }
}
