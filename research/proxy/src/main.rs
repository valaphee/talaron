use std::os::windows::io::AsRawSocket as _;

use anstyle::{AnsiColor, Color, Style};
use tokio::net::TcpSocket;
use windows::Win32::Networking::WinSock::{IP_UNICAST_IF, IPPROTO_IP, SOCKET, setsockopt};

mod bnet;
mod game;
mod jam;
mod lobby;

const NET_IF: u32 = 5;

pub const FIELD: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightMagenta)));
pub const C2S: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightGreen)));
pub const S2C: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightRed)));

#[tokio::main]
async fn main() {
    bnet::proxy().await;
}

fn socket() -> TcpSocket {
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
