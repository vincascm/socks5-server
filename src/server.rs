use tokio::{
    io::{self, copy, AsyncWriteExt},
    net::{
        lookup_host,
        tcp::{ReadHalf, WriteHalf},
        TcpListener, TcpStream,
    },
};

use crate::socks5::{
    AuthenticationRequest, AuthenticationResponse,
    TcpRequestHeader,
    Method, Command, Replies, Address,
};

async fn handle_client(mut stream: TcpStream, allow_ipv6: bool) -> io::Result<()> {
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
        Command::Connect => handle_connect((r, w), addr, allow_ipv6).await,
        // Bind and UdpAssociate, is not supported
        _ => {
            let rh = Replies::CommandNotSupported.into_response(addr);
            w.write_all(&rh.to_bytes()).await?;
            Ok(())
        }
    }
}

async fn handle_connect<'a>((mut r, mut w): (ReadHalf<'a>, WriteHalf<'a>), addr: Address, allow_ipv6: bool) -> io::Result<()> {
    use io::ErrorKind;

    if !allow_ipv6 && addr.is_ipv6() {
        let resp = Replies::NetworkUnreachable.into_response(addr);
        w.write_all(&resp.to_bytes()).await?;
        return Err(ErrorKind::AddrNotAvailable.into())
    }

    let tcp_addr = match addr.to_socket_addrs().await {
        Ok(addr) => addr,
        Err(e) => {
            let resp = Replies::HostUnreachable.into_response(addr);
            w.write_all(&resp.to_bytes()).await?;
            return Err(e);
        }
    };

    let mut host_stream = match TcpStream::connect(tcp_addr).await {
        Ok(s) => {
            let header = Replies::Succeeded.into_response(tcp_addr.into());
            w.write_buf(&mut header.to_bytes().as_ref()).await?;
            s
        }
        Err(e) => {
            let reply = match e.kind() {
                ErrorKind::ConnectionRefused => Replies::ConnectionRefused,
                ErrorKind::ConnectionAborted => Replies::HostUnreachable,
                _ => Replies::NetworkUnreachable,
            };

            let header = reply.into_response(tcp_addr.into());
            w.write_all(&header.to_bytes()).await?;
            return Err(e);
        }
    };
    let (mut host_r, mut host_w) = host_stream.split();
    futures::future::select(copy(&mut r, &mut host_w), copy(&mut host_r, &mut w)).await;
    Ok(())
}

pub async fn run(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = match lookup_host(addr).await?.next() {
        Some(addr) => addr,
        None => {
            let e: io::Error = io::ErrorKind::AddrNotAvailable.into();
            return Err(e.into());
        },
    };
    let allow_ipv6 = addr.is_ipv6();
    let mut listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, allow_ipv6).await {
                if let Ok(log_level) = std::env::var("LOG_LEVEL") {
                    if log_level == "error" {
                        println!("error: {}", e);
                    }
                }
            }
        });
    }
}
