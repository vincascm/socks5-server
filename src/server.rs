use tokio::{
    io::{self, copy, AsyncWriteExt},
    net::{
        lookup_host,
        tcp::{ReadHalf, WriteHalf},
        TcpListener, TcpStream,
    },
};

use futures::future::select;

use crate::socks5::{
    Address, AuthenticationRequest, AuthenticationResponse, Command, Method, Replies,
    TcpRequestHeader,
};

async fn handle_client(mut stream: TcpStream) -> io::Result<()> {
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
    w.flush().await?;

    // requests
    let header = match TcpRequestHeader::read_from(&mut r).await {
        Ok(h) => h,
        Err(e) => {
            let rh = e.clone().reply.into_response(Address::SocketAddress(client_addr));
            w.write_all(&rh.to_bytes()).await?;
            w.flush().await?;
            return Err(e.into());
        }
    };
    let addr = header.address;
    match header.command {
        Command::Connect => handle_connect((r, w), addr).await,
        // Bind and UdpAssociate, is not supported
        _ => {
            let rh = Replies::CommandNotSupported.into_response(addr);
            w.write_all(&rh.to_bytes()).await?;
            w.flush().await?;
            Ok(())
        }
    }
}

async fn handle_connect<'a>((mut r, mut w): (ReadHalf<'a>, WriteHalf<'a>), addr: Address) -> io::Result<()> {
    use io::ErrorKind;

    let tcp_addr = match addr {
        Address::SocketAddress(addr) => addr,
        Address::DomainNameAddress(domain, port) => {
            match lookup_host((domain.as_str(), port)).await?.next() {
                Some(addr) => addr,
                None => {
                    let header =
                        Replies::HostUnreachable.into_response((domain.as_str(), port).into());
                    w.write_all(&header.to_bytes()).await?;
                    w.flush().await?;
                    return Err(ErrorKind::AddrNotAvailable.into());
                }
            }
        }
    };

    let mut host_stream = match TcpStream::connect(tcp_addr).await {
        Ok(s) => {
            let header = Replies::Succeeded.into_response(tcp_addr.into());
            w.write_buf(&mut header.to_bytes()).await?;
            w.flush().await?;
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
            w.flush().await?;
            return Err(e);
        }
    };
    let (mut host_r, mut host_w) = host_stream.split();
    select(copy(&mut r, &mut host_w), copy(&mut host_r, &mut w)).await;
    Ok(())
}

pub async fn run(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                error!("handle client error: {}", e);
            }
        });
    }
}
