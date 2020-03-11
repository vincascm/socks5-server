/// a simplify socks protocol just for forward tcp connect.

use std::{
    net::SocketAddr,
};

use tokio::{
    io::{self, copy, AsyncWriteExt},
    net::{
        lookup_host,
        TcpListener, TcpStream,
    },
};

use crate::socks5::{Address, Replies};

type E = Box<dyn std::error::Error + Send + Sync>;
type R<T> = Result<T, E>;

pub struct SocksLite {
    tcp: TcpStream,
}

impl SocksLite {
    async fn get_addr(&mut self) -> R<SocketAddr> {
        let addr = Address::read_from(&mut self.tcp).await?;
        Ok(addr.to_socket_addrs().await?)
    }

    async fn reply(&mut self, reply: Replies, addr: SocketAddr) -> R<()> {
        let header = reply.into_response(addr.into());
        self.tcp.write_buf(&mut header.to_bytes().as_ref()).await?;
        Ok(())
    }

    async fn forward(&mut self) -> R<()> {
        let addr = self.get_addr().await?;
        let mut host_stream = match TcpStream::connect(addr).await {
            Ok(s) => {
                self.reply(Replies::Succeeded, addr).await?;
                s
            }
            Err(e) => {
                let error_desc = format!("connect error: {}", e);
                self.reply(e.into(), addr).await?;
                return Err(error_desc.into());
            }
        };
        let (mut r, mut w) = self.tcp.split();
        let (mut host_r, mut host_w) = host_stream.split();
        futures::future::select(copy(&mut r, &mut host_w), copy(&mut host_r, &mut w)).await;
        Ok(())
    }
}

impl From<TcpStream> for SocksLite {
    fn from(tcp: TcpStream) -> SocksLite {
        SocksLite {
            tcp,
        }
    }
}

pub async fn run(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = match lookup_host(addr).await?.next() {
        Some(addr) => addr,
        None => {
            let e: io::Error = io::ErrorKind::AddrNotAvailable.into();
            return Err(e.into());
        },
    };
    let mut listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut socks_lite: SocksLite = stream.into();
            if let Err(e) = socks_lite.forward().await {
                println!("err: {}", e);
            }
        });
    }
}

