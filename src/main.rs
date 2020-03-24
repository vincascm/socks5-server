mod server;

macro_rules! help {
    () => {
        r#"
options:
    -h  show help
    -l <address> assgin a listen address
    -V  show version
"#;
    };
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
    let mut rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return println!("tokio runtime init error: {}", e),
    };
    if let Err(e) = rt.block_on(server::Server::run(&listen)) {
        println!("startup error: {}", e)
    }
}
