# lego-httpreq-server

This is a simple DNS server that implements the HTTP API used by [lego's HTTP request provider](https://go-acme.github.io/lego/dns/httpreq/). And I mean really simple &mdash; no persistent storage, no authentication, just a particular HTTP interface glued to a very limited DNS server.

> [!WARNING]
> Anyone who can POST to the HTTP server can get a valid (wildcard) certificate from any ACME provider for hosts that are delegated to this DNS server. Be careful!

```
Usage:  [ns_name] [--debug] [--dns-addr <dns_addr>] [--http-addr <http_addr>] [-h]
Arguments:
  [ns_name]            Name to return in responses to NS queries for our zones.

Options:
  --debug              Print all tracing events.
  --dns-addr <dns_addr> Address to serve DNS on. [default: [::]:53]
  --http-addr <http_addr> Address to serve the httpreq API on. [default: localhost:80]
  -h, --help           Prints help
```

While writing this I decided to challenge myself to write it in as few lines of (non-comment, non-blank, rustfmt-formatted) Rust as possible. I make some questionable decisions. Enjoy!
