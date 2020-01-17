# socks5-server

a socks5 server implementation using async crate `tokio`.

```text
socks5-server

options:
    -h  show help
    -l <address> assgin a listen address
    -V  show version
```

# usage

just run:

```shell
socks5-server 
```

will listen at `127.0.0.1:1080`, or assgin a listen address:

```shell
socks5-server -l :::10800
```

if your socks5 client forwards ipv6 address, make ensure the `socks5-server` is listening on ipv6 as well.

set environment variable `LOG_LEVEL=error` will print the error message.

# install

download static linked build [here](https://github.com/vincascm/socks5-server/releases).

