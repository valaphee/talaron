#![feature(read_le)]

use std::os::windows::io::AsRawSocket as _;

use tokio::net::TcpSocket;
use windows::Win32::Networking::WinSock::{IP_UNICAST_IF, IPPROTO_IP, SOCKET, setsockopt};

mod bgs;
mod lobby;

const IF: u32 = 6;

#[tokio::main]
async fn main() {
    bgs::proxy().await;
}

pub fn socket() -> TcpSocket {
    let socket = TcpSocket::new_v4().unwrap();
    unsafe {
        assert_eq!(
            setsockopt(
                SOCKET(socket.as_raw_socket() as usize),
                IPPROTO_IP.0,
                IP_UNICAST_IF,
                Some(&IF.to_be_bytes()),
            ),
            0
        );
    }

    socket
}
