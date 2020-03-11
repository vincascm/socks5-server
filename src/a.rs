use std::net::SocketAddr;

use tokio::{
    io::{self, copy, AsyncWriteExt},
    net::{
        lookup_host,
        TcpListener, TcpStream,
    },
};

use crate::socks5::{
    AuthenticationRequest, AuthenticationResponse,
    TcpRequestHeader,
    Method, Command, Replies,
};

async fn handle(mut stream: TcpStream, socks_b_addr: SocketAddr) -> io::Result<()> {
    let client_addr = stream.peer_addr()?;
    let (mut r, mut w) = stream.split();

    // authentication
    let authentication_request = AuthenticationRequest::read_from(&mut r).await?;
    let authentication_response: AuthenticationResponse =
        if authentication_request.required_authentication() {
            Method::NotAcceptable.into()
        } else {
            Method::None.into()
        };
    w.write_all(&authentication_response.to_bytes()).await?;

    // requests
    let header = match TcpRequestHeader::read_from(&mut r).await {
        Ok(h) => h,
        Err(e) => {
            let rh = e.clone().reply.into_response(client_addr.into());
            w.write_all(&rh.to_bytes()).await?;
            return Err(e.into());
        }
    };
    let addr = header.address;
    match header.command {
        Command::Connect => {
            let mut host_stream = TcpStream::connect(socks_b_addr).await?;
            let (mut host_r, mut host_w) = host_stream.split();
            host_w.write_all(&addr.to_bytes()).await?;
            futures::future::select(copy(&mut r, &mut host_w), copy(&mut host_r, &mut w)).await;
        },
        // Bind and UdpAssociate, is not supported
        _ => {
            let rh = Replies::CommandNotSupported.into_response(addr);
            w.write_all(&rh.to_bytes()).await?;
        }
    }
    Ok(())
}

pub async fn run(addr: &str, socks_b_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = match lookup_host(addr).await?.next() {
        Some(addr) => addr,
        None => {
            let e: io::Error = io::ErrorKind::AddrNotAvailable.into();
            return Err(e.into());
        },
    };

    let socks_b_addr = match lookup_host(socks_b_addr).await?.next() {
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
            if let Err(e) = handle(stream, socks_b_addr).await {
                if let Ok(log_level) = std::env::var("LOG_LEVEL") {
                    if log_level == "error" {
                        println!("error: {}", e);
                    }
                }
            }
        });
    }
}
