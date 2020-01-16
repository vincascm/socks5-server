#[macro_use]
extern crate log;

mod server;
mod socks5;

const HELP: &str = r#"
options:
    -h  show help
    -l <address> assgin a listen address
    -V  show version
"#;


fn main() {
    let mut args = std::env::args();
    args.next(); // skip app's name
    let listen = match args.next() {
        Some(opts) => match opts.as_str() {
            "-h" => return println!(concat!(env!("CARGO_PKG_NAME"), "\n{}"), &HELP),
            "-l" => match args.next() {
                Some(listen) => listen,
                None => return println!("invalid listen argument, required a value."),
            },
            "-V" => return println!(env!("CARGO_PKG_VERSION")),
            _    => return println!(r#"invalid options, use "-h" to show help"#),
        },
        None => "127.0.0.1:1080".to_owned(),
    };
    let mut rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return println!("tokio runtime init error: {}", e),
    };
    if let Err(e) = rt.block_on(server::run(&listen)) {
        println!("startup error: {}", e)
    }
}
