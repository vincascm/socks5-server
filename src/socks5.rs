//! Socks5 protocol definition (RFC1928)
//!
//! Implements [SOCKS Protocol Version 5](https://www.ietf.org/rfc/rfc1928.txt) proxy protocol
//! some copy from
//! <https://github.com/shadowsocks/shadowsocks-rust/blob/master/src/relay/socks5.rs>

use std::{
    fmt::{self, Debug, Formatter},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use bytes::BufMut;
use tokio::{
    net::lookup_host,
    io::{self, AsyncRead, AsyncReadExt},
};

const VERSION: u8 = 0x05;

#[derive(PartialEq)]
pub enum Method {
    None,
    GssApi,
    Password,
    NotAcceptable,
    InvalidMethod(u8),
}

impl Method {
    pub fn from_u8(code: u8) -> Method {
        match code {
            0x00 => Method::None,
            0x01 => Method::GssApi,
            0x02 => Method::Password,
            0xff => Method::NotAcceptable,
            c => Method::InvalidMethod(c),
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            Method::None => 0x00,
            Method::GssApi => 0x01,
            Method::Password => 0x02,
            Method::NotAcceptable => 0xff,
            Method::InvalidMethod(c) => *c,
        }
    }

    pub fn is_invalid_method(&self) -> bool {
        match self {
            Method::InvalidMethod(_) => true,
            _ => false,
        }
    }
}

pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl Command {
    fn from_u8(code: u8) -> Option<Command> {
        match code {
            0x01 => Some(Command::Connect),
            0x02 => Some(Command::Bind),
            0x03 => Some(Command::UdpAssociate),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub enum Replies {
    Succeeded,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,

    OtherReply(u8),
}

impl Replies {
    fn as_u8(&self) -> u8 {
        match self {
            Replies::Succeeded => 0x00,
            Replies::GeneralFailure => 0x01,
            Replies::ConnectionNotAllowed => 0x02,
            Replies::NetworkUnreachable => 0x03,
            Replies::HostUnreachable => 0x04,
            Replies::ConnectionRefused => 0x05,
            Replies::TtlExpired => 0x06,
            Replies::CommandNotSupported => 0x07,
            Replies::AddressTypeNotSupported => 0x08,
            Replies::OtherReply(c) => *c,
        }
    }

    pub fn into_response(self, address: Address) -> TcpResponseHeader {
        TcpResponseHeader::new(self, address)
    }
}

/// SOCKS5 authentication request packet
///
/// ```plain
/// +----+----------+----------+
/// |VER | NMETHODS | METHODS  |
/// +----+----------+----------+
/// | 5  |    1     | 1 to 255 |
/// +----+----------+----------|
/// ```
pub struct AuthenticationRequest {
    methods: Vec<Method>,
}

impl AuthenticationRequest {
    pub async fn read_from<R>(r: &mut R) -> io::Result<AuthenticationRequest>
    where
        R: AsyncRead + Unpin,
    {
        let ver = r.read_u8().await?;
        if ver != VERSION {
            use std::io::{Error, ErrorKind};
            let err = Error::new(
                ErrorKind::InvalidData,
                format!("unsupported socks version {:#x}", ver),
            );
            return Err(err);
        }

        let n = r.read_u8().await?;
        let mut methods = vec![0; n as usize];
        r.read_exact(&mut methods).await?;
        let methods = methods
            .iter()
            .map(|m| Method::from_u8(*m))
            .filter(|m| !m.is_invalid_method())
            .collect();

        Ok(AuthenticationRequest { methods })
    }

    pub fn required_authentication(&self) -> bool {
        !self.methods.contains(&Method::None)
    }
}

/// SOCKS5 authentication response packet
///
/// ```plain
/// +----+--------+
/// |VER | METHOD |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
/// ```
pub struct AuthenticationResponse {
    method: Method,
}

impl AuthenticationResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.put_u8(VERSION);
        buffer.put_u8(self.method.as_u8());
        buffer
    }
}

impl From<Method> for AuthenticationResponse {
    fn from(method: Method) -> AuthenticationResponse {
        AuthenticationResponse { method }
    }
}


/// TCP request header after authentication
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
pub struct TcpRequestHeader {
    /// SOCKS5 command
    pub command: Command,
    /// Remote address
    pub address: Address,
}

impl TcpRequestHeader {
    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> Result<TcpRequestHeader, Error>
    where
        R: AsyncRead + Unpin,
    {
        let ver = r.read_u8().await?;
        if ver != VERSION {
            return Err(Error::new(
                Replies::ConnectionRefused,
                format!("unsupported socks version {:#x}", ver),
            ));
        }

        let command = r.read_u8().await?;
        let command = match Command::from_u8(command) {
            Some(c) => c,
            None => {
                return Err(Error::new(
                    Replies::CommandNotSupported,
                    format!("unsupported command {:#x}", command),
                ));
            }
        };
        // skip RSV field
        r.read_u8().await?;

        let address = Address::read_from(r).await?;
        Ok(TcpRequestHeader { command, address })
    }
}

/// TCP response header
///
/// ```plain
/// +----+-----+-------+------+----------+----------+
/// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
/// ```
pub struct TcpResponseHeader {
    /// SOCKS5 reply
    pub reply: Replies,
    /// Reply address
    pub address: Address,
}

impl TcpResponseHeader {
    /// Creates a response header
    pub fn new(reply: Replies, address: Address) -> TcpResponseHeader {
        TcpResponseHeader {
            reply,
            address,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(3 + self.address.len());
        buffer.put_u8(VERSION);
        buffer.put_u8(self.reply.as_u8());
        buffer.put_u8(0);
        buffer.put_slice(&self.address.to_bytes());
        buffer
    }
}


/// SOCKS5 address type
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address
    DomainNameAddress(String, u16),
}

impl Address {
    pub fn is_ipv6(&self) -> bool {
        match self {
            Address::SocketAddress(addr) => addr.is_ipv6(),
            Address::DomainNameAddress(..) => false,
        }
    }

    pub async fn read_from<R>(stream: &mut R) -> Result<Address, Error>
    where
        R: AsyncRead + Unpin,
    {
        let addr_type = stream.read_u8().await?;
        let addr_type = match AddressType::from_u8(addr_type) {
            Some(addr) => addr,
            None => {
                return Err(Error::new(
                    Replies::AddressTypeNotSupported,
                    format!("not supported address type {:#x}", addr_type),
                ))
            },
        };
        match addr_type {
            AddressType::Ipv4 => {
                let v4addr = Ipv4Addr::new(
                    stream.read_u8().await?,
                    stream.read_u8().await?,
                    stream.read_u8().await?,
                    stream.read_u8().await?,
                );
                let port = stream.read_u16().await?;
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    v4addr, port,
                ))))
            }
            AddressType::Ipv6 => {
                let v6addr = Ipv6Addr::new(
                    stream.read_u16().await?,
                    stream.read_u16().await?,
                    stream.read_u16().await?,
                    stream.read_u16().await?,
                    stream.read_u16().await?,
                    stream.read_u16().await?,
                    stream.read_u16().await?,
                    stream.read_u16().await?,
                );
                let port = stream.read_u16().await?;

                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    v6addr, port, 0, 0,
                ))))
            }
            AddressType::DomainName => {
                let domain_len = stream.read_u8().await?;
                let mut domain = vec!(0; domain_len as usize);
                stream.read_exact(&mut domain).await?;
                let domain = match String::from_utf8(domain.to_vec()) {
                    Ok(domain) => domain,
                    Err(_) => {
                        return Err(Error::new(
                            Replies::GeneralFailure,
                            "invalid address encoding",
                        ))
                    }
                };
                let port = stream.read_u16().await?;
                Ok(Address::DomainNameAddress(domain, port))
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.len());
        write_address(self, &mut buffer);
        buffer
    }

    pub fn len(&self) -> usize {
        match self {
            // VER + addr len + port len
            Address::SocketAddress(SocketAddr::V4(..)) => 1 + 4 + 2,
            // VER + addr len + port len
            Address::SocketAddress(SocketAddr::V6(..)) => 1 + 8 * 2 + 2,
            // VER + domain len + domain self len + port len
            Address::DomainNameAddress(ref d, _) => 1 + 1 + d.len() + 2,
        }
    }

    pub async fn to_socket_addrs(&self) -> io::Result<SocketAddr> {
        match self {
            Address::SocketAddress(addr) => Ok(addr.clone()),
            Address::DomainNameAddress(addr, port) => match lookup_host((addr.as_str(), *port)).await?.next() {
                Some(addr) => Ok(addr),
                None => Err(io::ErrorKind::AddrNotAvailable.into())
            },
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        Address::SocketAddress(s)
    }
}

#[derive(Copy, Clone)]
enum AddressType {
    Ipv4       = 1,
    DomainName = 3,
    Ipv6       = 4,
}

impl AddressType {
    pub fn from_u8(code: u8) -> Option<AddressType> {
        match code {
            1 => Some(AddressType::Ipv4),
            3 => Some(AddressType::DomainName),
            4 => Some(AddressType::Ipv6),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

fn write_ipv4_address<B: BufMut>(addr: &SocketAddrV4, buf: &mut B) {
    buf.put_u8(AddressType::Ipv4.as_u8());
    buf.put_slice(&addr.ip().octets());
    buf.put_u16(addr.port());
}

fn write_ipv6_address<B: BufMut>(addr: &SocketAddrV6, buf: &mut B) {
    buf.put_u8(AddressType::Ipv6.as_u8());
    for seg in &addr.ip().segments() {
        buf.put_u16(*seg);
    }
    buf.put_u16(addr.port());
}

fn write_domain_name_address<B: BufMut>(dnaddr: &str, port: u16, buf: &mut B) {
    buf.put_u8(AddressType::DomainName.as_u8());
    buf.put_u8(dnaddr.len() as u8);
    buf.put_slice(dnaddr[..].as_bytes());
    buf.put_u16(port);
}

fn write_socket_address<B: BufMut>(addr: &SocketAddr, buf: &mut B) {
    match *addr {
        SocketAddr::V4(ref addr) => write_ipv4_address(addr, buf),
        SocketAddr::V6(ref addr) => write_ipv6_address(addr, buf),
    }
}

fn write_address<B: BufMut>(addr: &Address, buf: &mut B) {
    match *addr {
        Address::SocketAddress(ref addr) => write_socket_address(addr, buf),
        Address::DomainNameAddress(ref dnaddr, ref port) => {
            write_domain_name_address(dnaddr, *port, buf)
        }
    }
}

#[derive(Clone)]
pub struct Error {
    /// Reply code
    pub reply: Replies,
    /// Error message
    message: String,
}

impl Error {
    pub fn new<S>(reply: Replies, message: S) -> Error
    where
        S: Into<String>,
    {
        Error {
            reply,
            message: message.into(),
        }
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::new(Replies::GeneralFailure, err.to_string())
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::new(io::ErrorKind::Other, err.message)
    }
}

