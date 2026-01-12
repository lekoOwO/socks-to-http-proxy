# socks-to-http-proxy ![Rust](https://github.com/lekoOwO/socks-to-http-proxy/workflows/Rust/badge.svg) ![release](https://img.shields.io/github/v/release/lekoOwO/socks-to-http-proxy?include_prereleases)

An executable to convert SOCKS5 proxy into HTTP proxy

## About

`sthp` purpose is to create HTTP proxy on top of the Socks 5 Proxy

## How it works

It uses hyper library HTTP proxy [example](https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs) and adds functionality to connect via Socks5

## Compiling

Follow these instructions to compile

1.  Ensure you have current version of `cargo` and [Rust](https://www.rust-lang.org) installed
2.  Clone the project `$ git clone https://github.com/lekoOwO/socks-to-http-proxy.git && cd socks-to-http-proxy`
3.  Build the project `$ cargo build --release`
4.  Once complete, the binary will be located at `target/release/sthp`

## Usage

```bash
sthp -p 8080 -s 127.0.0.1:1080
```

This will create proxy server on 8080 and use localhost:1080 as a Socks5 Proxy

```bash
sthp -p 8080 -s example.com:8080
```

This will create proxy server on 8080 and use example:1080 as a Socks5 Proxy

> [!NOTE]  
> The --socks-address (-s) flag does not support adding a schema at the start (e.g., socks:// or socks5h://). Currently, it only supports socks5h, which means DNS resolution will be done on the SOCKS server.

> [!WARNING]
> After v5, Changed default listening IP from `0.0.0.0` to `127.0.0.1`. This change restricts the application access to the local machine only.

### Options

There are a few options for using `sthp`.

```text
Usage: sthp [OPTIONS]

Options:
  -p, --port <PORT>                        port where Http proxy should listen [default: 8080]
      --listen-ip <LISTEN_IP>              [default: 127.0.0.1]
  -u, --username <USERNAME>                Socks5 username
  -P, --password <PASSWORD>                Socks5 password
  -s, --socks-address <SOCKS_ADDRESS>      Socks5 proxy address [default: 127.0.0.1:1080]
      --allowed-domains <ALLOWED_DOMAINS>  Comma-separated list of allowed domains
      --http-basic <HTTP_BASIC>            HTTP Basic Auth credentials in the format "user:passwd" (only enforced when --no-forward-basic-auth is provided)
      --no-forward-basic-auth              Disable forwarding Proxy-Authorization credentials to the SOCKS5 proxy (enabled by default; falls back to static credentials before prompting clients)
  -d, --detached                           Run process in background (Only for Unix based systems)
  -h, --help                               Print help
  -V, --version                            Print version
```

## Docker

A dedicated GitHub Actions workflow builds multi-architecture container images and publishes them to the GitHub Container Registry (GHCR). Pull the latest build with:

```bash
docker pull ghcr.io/lekoowo/socks-to-http-proxy:latest
```

Run it just like the CLI, exposing the HTTP proxy port you need. Containers should listen on `0.0.0.0` so traffic from other hosts reaches the proxy:

```bash
docker run --rm -p 8080:8080 ghcr.io/lekoowo/socks-to-http-proxy:latest \
  --listen-ip 0.0.0.0 --socks-address 127.0.0.1:1080 --allowed-domains example.com
```

Replace `latest` with any published tag if you want an immutable build.

### Docker Compose

Compose lets you keep the same CLI flags while managing the container alongside other services. Use the `command` array to forward any `sthp` arguments:

```yaml
services:
  sthp:
    image: ghcr.io/lekoowo/socks-to-http-proxy:${STHP_TAG:-latest}
    command:
      - --listen-ip
      - 0.0.0.0
      - --socks-address
      - socks-proxy:1080
      - --allowed-domains
      - example.com
      - --no-forward-basic-auth
    ports:
      - "8080:8080"
```

Any flag listed under `command` maps 1:1 to the binary arguments, so you can inject secrets with Compose env vars (for example `command: ["--http-basic", "$HTTP_BASIC"]`). Start it with `docker compose up -d` once your proxy settings look right.
