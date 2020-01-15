#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;

mod server;
mod socks5;

fn main() {
    let matches = clap::app_from_crate!()
	.arg(
	    clap::Arg::with_name("listen")
	    .short("l")
	    .long("listen")
	    .takes_value(true)
	    .help("listen address"),
	    )
	.get_matches();
    let listen = matches.value_of("listen").unwrap_or("127.0.0.1:1080");
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(server::run(listen)).unwrap();
}
