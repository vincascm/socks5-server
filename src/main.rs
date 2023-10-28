use std::net::{TcpListener, ToSocketAddrs};

use anyhow::{anyhow, Result};
use async_executor::Executor;
use async_io::{block_on, Async};

use socks5::proxy;

macro_rules! help {
    () => {
        r#"
options:
    -h  show help
    -l <address> assgin a listen address
    -V  show version
"#
    };
}

fn run(addr: &str) -> Result<()> {
    let addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("invalid listen address"))?;
    let executor = Executor::new();
    block_on(executor.run(async {
        let listener = Async::<TcpListener>::bind(addr)?;
        loop {
            let (mut stream, src) = listener.accept().await?;
            executor
                .spawn(async move {
                    if let Err(e) = proxy(&mut stream, src).await {
                        println!("error: {}", e);
                    }
                })
                .detach();
        }
    }))
}

fn main() {
    let mut args = std::env::args();
    args.next(); // skip app's name
    let listen = match args.next() {
        Some(opts) => match opts.as_str() {
            "-h" => Err(concat!(env!("CARGO_PKG_NAME"), "\n", help!())),
            "-l" => match args.next() {
                Some(listen) => Ok(listen),
                None => Err("invalid listen argument, required a value."),
            },
            "-V" => Err(env!("CARGO_PKG_VERSION")),
            _ => Err(r#"invalid options, use "-h" to show help"#),
        },
        None => Ok("127.0.0.1:1080".to_owned()),
    };
    let listen = match listen {
        Ok(listen) => listen,
        Err(e) => return println!("{}", e),
    };
    if let Err(e) = run(&listen) {
        println!("startup error: {}", e)
    }
}
