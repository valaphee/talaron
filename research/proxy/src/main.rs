#![feature(read_le)]

use std::os::windows::io::AsRawSocket as _;

use tokio::net::TcpSocket;
use windows::Win32::Networking::WinSock::{IP_UNICAST_IF, IPPROTO_IP, SOCKET, setsockopt};

mod bnet;
mod jam;
mod lobby;

const NET_IF: u32 = 5;

#[tokio::main]
async fn main() {
    bnet::proxy().await;
}

pub fn socket() -> TcpSocket {
    let socket = TcpSocket::new_v4().unwrap();
    unsafe {
        assert_eq!(
            setsockopt(
                SOCKET(socket.as_raw_socket() as usize),
                IPPROTO_IP.0,
                IP_UNICAST_IF,
                Some(&NET_IF.to_be_bytes()),
            ),
            0
        );
    }

    socket
}

fn hexdump(bytes: &[u8]) {
    for (row, chunk) in bytes.chunks(16).enumerate() {
        print!("{:08x}  ", row * 16);

        for i in 0..16 {
            if let Some(byte) = chunk.get(i) {
                print!("{byte:02x} ");
            } else {
                print!("   ");
            }
        }

        print!(" |");
        for &byte in chunk {
            print!(
                "{}",
                if byte.is_ascii_graphic() || byte == b' ' {
                    byte as char
                } else {
                    '.'
                }
            );
        }
        println!("|");
    }
}
