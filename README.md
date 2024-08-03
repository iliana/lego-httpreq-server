# lego-httpreq-server

This is a simple DNS server that implements the HTTP API used by [lego's HTTP request provider](https://go-acme.github.io/lego/dns/httpreq/). And I mean really simple &mdash; no persistent storage, no authentication, just a particular HTTP interface glued to a very limited DNS server.

> [!WARNING]
> Anyone who can POST to the HTTP server can get a valid (wildcard) certificate from any ACME provider for hosts that are delegated to this DNS server. Be careful!

```
Options:
      --debug                  Print all tracing events [env: HTTPREQ_DEBUG=]
      --dns-addr <DNS_ADDR>    Address to serve DNS on [env: HTTPREQ_DNS_ADDR=] [default: [::]:53]
      --http-addr <HTTP_ADDR>  Address to serve the httpreq API on [env: HTTPREQ_HTTP_ADDR=] [default: localhost:80]
  -h, --help                   Print help
```

While writing this I decided to challenge myself to write it in as few lines of (non-comment, non-blank, rustfmt-formatted) Rust as possible. I make some questionable decisions. Enjoy!
