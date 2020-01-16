//! Socks5 protocol definition (RFC1928)
//!
//! Implements [SOCKS Protocol Version 5](https://www.ietf.org/rfc/rfc1928.txt) proxy protocol
//! some copy from
//! <https://github.com/shadowsocks/shadowsocks-rust/blob/master/src/relay/socks5.rs>

use std::{
    convert::From,
    error,
    fmt::{self, Debug, Formatter},
    io::{self, Cursor},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
    str::FromStr,
    u8, vec,
};

use bytes::{buf::BufExt, Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

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

    pub fn is_invalid_method(&self) -> bool {
        match self {
            Method::InvalidMethod(_) => true,
            _ => false,
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

    fn from_u8(code: u8) -> Replies {
        match code {
            0x00 => Replies::Succeeded,
            0x01 => Replies::GeneralFailure,
            0x02 => Replies::ConnectionNotAllowed,
            0x03 => Replies::NetworkUnreachable,
            0x04 => Replies::HostUnreachable,
            0x05 => Replies::ConnectionRefused,
            0x06 => Replies::TtlExpired,
            0x07 => Replies::CommandNotSupported,
            0x08 => Replies::AddressTypeNotSupported,
            _ => Replies::OtherReply(code),
        }
    }

    pub fn into_response(self, address: Address) -> TcpResponseHeader {
        TcpResponseHeader::new(self, address)
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

impl error::Error for Error {}

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

/// SOCKS5 address type
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address
    DomainNameAddress(String, u16),
}

impl Address {
    pub async fn read_from<R>(stream: &mut R) -> Result<Address, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut addr_type_buf = [0u8; 1];
        stream.read_exact(&mut addr_type_buf).await?;

        let addr_type = addr_type_buf[0];
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
                let mut buf = BytesMut::with_capacity(6);
                buf.resize(6, 0);
                stream.read_exact(&mut buf).await?;

                let mut cursor = buf.to_bytes();
                let v4addr = Ipv4Addr::new(
                    cursor.get_u8(),
                    cursor.get_u8(),
                    cursor.get_u8(),
                    cursor.get_u8(),
                );
                let port = cursor.get_u16();
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(
                    v4addr, port,
                ))))
            }
            AddressType::Ipv6 => {
                let mut buf = [0u8; 18];
                stream.read_exact(&mut buf).await?;

                let mut cursor = Cursor::new(&buf);
                let v6addr = Ipv6Addr::new(
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                );
                let port = cursor.get_u16();

                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(
                    v6addr, port, 0, 0,
                ))))
            }
            AddressType::DomainName => {
                let mut length_buf = [0u8; 1];
                stream.read_exact(&mut length_buf).await?;
                let length = length_buf[0] as usize;

                // Len(Domain) + Len(Port)
                let buf_length = length + 2;
                let mut buf = BytesMut::with_capacity(buf_length);
                buf.resize(buf_length, 0);
                stream.read_exact(&mut buf).await?;

                let mut cursor = buf.to_bytes();
                let mut raw_addr = Vec::with_capacity(length);
                raw_addr.put(&mut BufExt::take(&mut cursor, length));
                let addr = match String::from_utf8(raw_addr) {
                    Ok(addr) => addr,
                    Err(..) => {
                        return Err(Error::new(
                            Replies::GeneralFailure,
                            "invalid address encoding",
                        ))
                    }
                };
                let port = cursor.get_u16();

                Ok(Address::DomainNameAddress(addr, port))
            }
        }
    }

    pub fn to_bytes(&self) -> BytesMut {
        let mut buffer = BytesMut::with_capacity(self.len());
        write_address(self, &mut buffer);
        buffer
    }

    pub fn len(&self) -> usize {
        match self {
            Address::SocketAddress(SocketAddr::V4(..)) => 1 + 4 + 2,
            Address::SocketAddress(SocketAddr::V6(..)) => 1 + 8 * 2 + 2,
            Address::DomainNameAddress(ref dmname, _) => 1 + 1 + dmname.len() + 2,
        }
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port),
        }
    }
}

impl ToSocketAddrs for Address {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<vec::IntoIter<SocketAddr>> {
        match self.clone() {
            Address::SocketAddress(addr) => Ok(vec![addr].into_iter()),
            Address::DomainNameAddress(addr, port) => (&addr[..], port).to_socket_addrs(),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        Address::SocketAddress(s)
    }
}

impl From<(String, u16)> for Address {
    fn from((dn, port): (String, u16)) -> Address {
        Address::DomainNameAddress(dn, port)
    }
}

impl From<(&str, u16)> for Address {
    fn from((dn, port): (&str, u16)) -> Address {
        Address::DomainNameAddress(dn.to_string(), port)
    }
}

pub struct AddressError;

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Address, AddressError> {
        match s.parse::<SocketAddr>() {
            Ok(addr) => Ok(Address::SocketAddress(addr)),
            Err(..) => {
                let mut sp = s.split(':');
                match (sp.next(), sp.next()) {
                    (Some(dn), Some(port)) => match port.parse::<u16>() {
                        Ok(port) => Ok(Address::DomainNameAddress(dn.to_owned(), port)),
                        Err(..) => Err(AddressError),
                    },
                    (Some(dn), None) => {
                        // Assume it is 80 (http's default port)
                        Ok(Address::DomainNameAddress(dn.to_owned(), 80))
                    }
                    _ => Err(AddressError),
                }
            }
        }
    }
}

#[inline]
fn write_ipv4_address<B: BufMut>(addr: &SocketAddrV4, buf: &mut B) {
    buf.put_u8(AddressType::Ipv4.as_u8()); // Address type
    buf.put_slice(&addr.ip().octets()); // Ipv4 bytes
    buf.put_u16(addr.port()); // Port
}

#[inline]
fn write_ipv6_address<B: BufMut>(addr: &SocketAddrV6, buf: &mut B) {
    buf.put_u8(AddressType::Ipv6.as_u8()); // Address type
    for seg in &addr.ip().segments() {
        buf.put_u16(*seg); // Ipv6 bytes
    }
    buf.put_u16(addr.port()); // Port
}

#[inline]
fn write_domain_name_address<B: BufMut>(dnaddr: &str, port: u16, buf: &mut B) {
    assert!(dnaddr.len() <= u8::max_value() as usize);

    buf.put_u8(AddressType::DomainName.as_u8());
    buf.put_u8(dnaddr.len() as u8);
    buf.put_slice(dnaddr[..].as_bytes());
    buf.put_u16(port);
}

#[inline]
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

/// TCP request header after handshake
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
        let mut buf = [0u8; 3];
        r.read_exact(&mut buf).await?;

        let ver = buf[0];
        if ver != VERSION {
            return Err(Error::new(
                Replies::ConnectionRefused,
                format!("unsupported socks version {:#x}", ver),
            ));
        }

        let cmd = buf[1];
        let command = match Command::from_u8(cmd) {
            Some(c) => c,
            None => {
                return Err(Error::new(
                    Replies::CommandNotSupported,
                    format!("unsupported command {:#x}", cmd),
                ));
            }
        };

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

    /// Read from a reader
    pub async fn read_from<R>(r: &mut R) -> Result<TcpResponseHeader, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 3];
        r.read_exact(&mut buf).await?;

        let ver = buf[0];
        let reply_code = buf[1];

        if ver != VERSION {
            return Err(Error::new(
                Replies::ConnectionRefused,
                format!("unsupported socks version {:#x}", ver),
            ));
        }

        let address = Address::read_from(r).await?;

        Ok(TcpResponseHeader {
            reply: Replies::from_u8(reply_code),
            address,
        })
    }

    pub fn to_bytes(&self) -> BytesMut {
        let mut buffer = BytesMut::with_capacity(self.address.len() + 3);
        buffer.put_u8(VERSION);
        buffer.put_u8(self.reply.as_u8());
        buffer.put_u8(0);
        buffer.put(self.address.to_bytes());
        buffer
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
        let mut buf = [0u8; 2];
        r.read_exact(&mut buf).await?;

        let ver = buf[0];
        let nmet = buf[1];

        if ver != VERSION {
            use std::io::{Error, ErrorKind};
            let err = Error::new(
                ErrorKind::InvalidData,
                format!("unsupported socks version {:#x}", ver),
            );
            return Err(err);
        }

        let mut methods = vec![0u8; nmet as usize];
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

/// SOCKS5 handshake response packet
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
    pub fn to_bytes(&self) -> BytesMut {
        let mut buffer = BytesMut::with_capacity(2);
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

/// UDP ASSOCIATE request header
///
/// ```plain
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
#[allow(dead_code)]
pub struct UdpAssociateHeader {
    /// Fragment
    pub frag: u8,
    /// Remote address
    pub address: Address,
}
