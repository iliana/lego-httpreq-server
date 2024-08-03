use std::{collections::hash_map::Entry, collections::HashMap, sync::Arc};

use axum::{extract::State, routing::post, Json, Router};
use hickory_proto::op::ResponseCode::{NXDomain, NoError, NotImp, Refused};
use hickory_proto::op::{Header, LowerQuery, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{rdata, DNSClass, LowerName, Name, Record, RecordData, RecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use tracing::{debug, error, info, instrument, warn, Level};
use tracing_subscriber::{filter::filter_fn, prelude::*};

const USAGE: &str = "Options:
      --debug, --no-debug      Print all tracing events (or don't) [env: HTTPREQ_DEBUG] [default: false]
      --dns-addr <DNS_ADDR>    Address to serve DNS on [env: HTTPREQ_DNS_ADDR] [default: [::]:53]
      --http-addr <HTTP_ADDR>  Address to serve the httpreq API on [env: HTTPREQ_HTTP_ADDR] [default: localhost:80]
  -h, --help                   Print help";

#[tokio::main]
async fn main() {
    // Hell yeah let's do a hand-rolled arg parser with environment variables.
    // (I think a Clap derive implementation is fewer LOC, but the binary bloat
    // isn't worth it...)

    // This variable is called `dbg` because if you call it `debug`, the tracing
    // macro becomes upset.
    let mut dbg = option_env("HTTPREQ_DEBUG")
        .is_some_and(|x| x.parse().expect("could not parse HTTPREQ_DEBUG as bool"));
    let mut dns_addr = option_env("HTTPREQ_DNS_ADDR").unwrap_or_else(|| "[::]:53".into());
    let mut http_addr = option_env("HTTPREQ_HTTP_ADDR").unwrap_or_else(|| "localhost:80".into());
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return println!("{USAGE}"),
            s @ ("--debug" | "--no-debug") => dbg = s == "--debug",
            "--dns-addr" => dns_addr = args.next().expect("--dns-addr requires an argument"),
            "--http-addr" => http_addr = args.next().expect("--http-addr requires an argument"),
            s => panic!("unrecognized option {s}"),
        }
    }
    let layer = tracing_subscriber::fmt::layer().with_filter(filter_fn(move |meta| {
        dbg || (meta.module_path() == Some(module_path!()) && *meta.level() <= Level::INFO)
    }));
    tracing_subscriber::registry().with(layer).init();
    debug!(dbg, dns_addr, http_addr, "starting");

    let database = Database::default();

    let mut dns_server = hickory_server::ServerFuture::new(database.clone());
    // load-bearing parentheses for rustfmt
    let dns_tcp = (tokio::net::TcpListener::bind(&dns_addr).await)
        .unwrap_or_else(|e| panic!("cannot bind to {dns_addr}/tcp: {e}"));
    dns_server.register_listener(dns_tcp, std::time::Duration::from_secs(5));
    let dns_udp = (tokio::net::UdpSocket::bind(&dns_addr).await)
        .unwrap_or_else(|e| panic!("cannot bind to {dns_addr}/udp: {e}"));
    dns_server.register_socket(dns_udp);

    let http_tcp = (tokio::net::TcpListener::bind(&http_addr).await)
        .unwrap_or_else(|e| panic!("cannot bind to {http_addr}/tcp: {e}"));
    let app = Router::new().route("/present", post(present));
    let app = app.route("/cleanup", post(cleanup)).with_state(database);

    let server = axum::serve(http_tcp, app).with_graceful_shutdown(async move {
        tokio::select! {
            result = dns_server.block_until_done() => result.expect("DNS server failed"),
            result = tokio::signal::ctrl_c() => result.expect("waiting for ctrl_c failed"),
        };
        (dns_server.shutdown_gracefully().await).expect("graceful shutdown failed");
    });
    server.await.expect("HTTP server failed");
}

fn option_env(key: &str) -> Option<String> {
    let f = |s| panic!("{key} is not valid unicode: {s:?}");
    Some(std::env::var_os(key)?.into_string().unwrap_or_else(f))
}

// The Database is a set of zones, each of which is a single SOA record and a
// Vec of TXT records.
//
// `[T; 1]` is a terrible type, but I can pass it around by reference as a slice
// like I can with the Vec<T> for `txt`, which simplifies things quite a bit.
#[derive(Debug, Clone, Default)]
struct Database(Arc<tokio::sync::RwLock<HashMap<LowerName, ([Record; 1], Vec<Record>)>>>);

// It's kind of amazing that this next line works at all. This aliases
// `RwLockReadGuard` to the much shorter `Guard`, both for the type references
// below (where it defaults to T = [Record]), but also for `RwLockReadGuard`'s
// associated functions _for any T_, just to make some of these match arms fit
// on a single line.
type Guard<'a, T = [Record]> = tokio::sync::RwLockReadGuard<'a, T>;

// The response type for the `query` function, below. The `Result` is a slice of
// `Record`s kept in an `RwLockReadGuard`; `Ok` means the records belong in the
// answer section, and `Err` means the records belong in the authority section.
type Response<'a> = (ResponseCode, Result<Guard<'a>, Guard<'a>>);

// This is separate from `Database::handle_request` (below) so that it can be
// tested. (It's not possible to construct a `Request` without decoding it from
// the wire, surprisingly!)
async fn query<'a>(database: &'a Database, header: &Header, query: &LowerQuery) -> Response<'a> {
    // Everything is destructured via `RwLockReadGuard::map` and `try_map` so
    // that we can return references of data behind the `RwLock` without needing
    // to clone anything.
    //
    // `try_map` is interesting; if the closure returns None, `try_map` returns
    // an `Err` with the original guard you started with.

    let zones = database.0.read().await;

    // Filter out obviously-invalid messages.
    match (header.message_type(), header.op_code(), query.query_class()) {
        (MessageType::Query, OpCode::Query, DNSClass::IN) => {}
        _ => return (NotImp, Err(Guard::map(zones, |_| &[][..]))),
    }

    match Guard::try_map(zones, |zones| zones.get(query.name())) {
        Ok(zone) => match query.query_type() {
            // Note `zone.0` is the SOA, and `zone.1` is the Vec of TXT records.
            RecordType::SOA => (NoError, Ok(Guard::map(zone, |zone| &zone.0[..]))),
            RecordType::TXT => (NoError, Ok(Guard::map(zone, |zone| &zone.1[..]))),
            _ => (NoError, Err(Guard::map(zone, |zone| &zone.0[..]))),
        },
        Err(mut zones) => {
            // We won't have any answers, but we need to search to see if there
            // is an authority below this query name so we can return its SOA
            // record with the negative TTL.
            let f = |name: &LowerName| Some(name.base_name()).filter(|name| !name.is_root());
            for name in std::iter::successors(Some(query.name().base_name()), f) {
                match Guard::try_map(zones, |zones| zones.get(&name)) {
                    Ok(zone) => {
                        // We have an authority, but no records.
                        return (NXDomain, Err(Guard::map(zone, |zone| &zone.0[..])));
                    }
                    Err(locked_zones) => zones = locked_zones,
                }
            }
            // We have no authority.
            (Refused, Err(Guard::map(zones, |_| &[][..])))
        }
    }
}

// This splits the `Result` from `Response` into two slices. We add three LOC
// by defining this function separately instead of inlining it into its two call
// locations, but I _really_ want to unit test this, because... come on, look
// at it.
fn split_result<'a>(r: &'a Result<Guard<'a>, Guard<'a>>) -> [&'a [Record]; 2] {
    // [alarms blaring] [dramatic zoom to `map_or_else`] GOOD CODE DETECTED
    r.as_ref().map_or_else(|s| [&[], &**s], |s| [&**s, &[]])
}

#[async_trait::async_trait]
impl RequestHandler for Database {
    #[instrument(skip_all, fields(
        src = %req.src(),
        protocol = %req.protocol(),
        query = %req.query().original(),
    ))]
    async fn handle_request<R: ResponseHandler>(&self, req: &Request, mut h: R) -> ResponseInfo {
        let (rcode, result) = query(self, req.header(), req.query()).await;
        let [answers, soa] = split_result(&result);
        info!(?rcode, answers = answers.len(), soa = soa.len());
        let builder = MessageResponseBuilder::from_message_request(req);
        let mut header = Header::response_from_request(req.header());
        header.set_response_code(rcode);
        let response = builder.build(header, answers, [], soa, []);
        h.send_response(response).await.unwrap_or_else(|err| {
            error!(%err);
            let mut header = Header::response_from_request(req.header());
            header.set_response_code(ResponseCode::ServFail);
            header.into()
        })
    }
}

#[derive(Debug, serde::Deserialize)]
struct Body {
    fqdn: LowerName,
    value: String,
}

#[instrument(skip(database))]
async fn present(State(database): State<Database>, Json(Body { fqdn, value }): Json<Body>) {
    let mut zones = database.0.write().await;
    let (_, txts) = zones.entry(fqdn.clone()).or_insert_with(|| {
        // Nearly none of the SOA record matters in practice:
        // 1. `mname` is used to know which server to send zone updates to; we
        //    don't accept updates.
        // 2. `rname` is an email address for the DNS administrator; given how
        //    likely this is to actually reach an administrator for any given
        //    zone, this may as well say `santa.northpole.int.` It's certainly
        //    not worth us plumbing through a configuration knob here.
        // 3. `serial` matters if we support AXFR, which we don't;
        // 4. ditto for `refresh`,
        // 5. `retry`,
        // 6. and `expire`.
        //
        // The one field that _does_ matter is `minimum`, which has since been
        // redefined by RFC 2308 to be the negative caching TTL.
        let soa = rdata::SOA::new(Name::root(), Name::root(), 1312, 3600, 3600, 3600, 5);
        let soa = Record::from_rdata(fqdn.clone().into(), 5, soa);
        ([soa.into_record_of_rdata()], Vec::with_capacity(1))
    });
    let txt = Record::from_rdata(fqdn.into(), 5, rdata::TXT::new(vec![value]).into_rdata());
    let Err(idx) = txts.binary_search(&txt) else {
        return warn!(records = txts.len(), "record already exists");
    };
    txts.insert(idx, txt);
    info!(records = txts.len());
}

#[instrument(skip(database))]
async fn cleanup(State(database): State<Database>, Json(Body { fqdn, value }): Json<Body>) {
    if let Entry::Occupied(mut zone) = database.0.write().await.entry(fqdn.clone()) {
        let txt = Record::from_rdata(fqdn.into(), 5, rdata::TXT::new(vec![value]).into_rdata());
        if let Ok(index) = zone.get().1.binary_search(&txt) {
            zone.get_mut().1.remove(index);
            info!(records = zone.get().1.len());
            zone.get().1.is_empty().then(|| zone.remove());
        }
    }
    warn!("no such record");
}

#[cfg(test)]
#[tokio::test]
async fn test() {
    let name = "_acme-challenge.meow.";
    let database = Database::default();

    macro_rules! call {
        ($f:expr, $fqdn:expr, $value:expr) => {{
            let (fqdn, value) = ($fqdn.parse().unwrap(), $value.into());
            $f(State(database.clone()), Json(Body { fqdn, value }))
        }};
    }
    macro_rules! check_query {
        ($name:expr, $type:ident, $rcode:ident, $answers:expr, $soa:expr) => {{
            let q = hickory_proto::op::Query::query($name.parse().unwrap(), RecordType::$type);
            let (rcode, result) = query(&database, &Header::new(), &q.into()).await;
            let [answers, soa] = split_result(&result);
            assert_eq!(rcode, ResponseCode::$rcode, "rcode mismatch");
            assert_eq!(answers.len(), $answers, "answers mismatch");
            assert_eq!(soa.len(), usize::from($soa), "soa mismatch");
        }};
    }

    assert_eq!(database.0.read().await.len(), 0);
    check_query!(name, SOA, Refused, 0, false);

    // Add a record
    let value_1 = "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM";
    for _ in 0..2 {
        call!(present, name, value_1).await;
        check_query!(name, SOA, NoError, 1, false);
        check_query!(name, TXT, NoError, 1, false);
        check_query!(name, AAAA, NoError, 0, true);
        check_query!(format!("subdomain.{name}"), SOA, NXDomain, 0, true);
    }

    // Add another record with the same FDQN, this time without the root label
    // (it should be canonicalized)
    let value_2 = "XaG3ZYfMMh2r9jvX961Z2nHDKcxXJm65_kLxolgb08k";
    for _ in 0..2 {
        call!(present, name.trim_end_matches('.'), value_2).await;
        // Ensure there is only one zone in the database
        assert_eq!(database.0.read().await.len(), 1);
        // Two records are returned for the TXT query
        check_query!(name, SOA, NoError, 1, false);
        check_query!(name, TXT, NoError, 2, false);
    }

    // Clean up the latter record
    for _ in 0..2 {
        call!(cleanup, name, value_2).await;
        // The zone is still present
        assert_eq!(database.0.read().await.len(), 1);
        check_query!(name, SOA, NoError, 1, false);
        check_query!(name, TXT, NoError, 1, false);
    }

    // Clean up the original record
    for _ in 0..2 {
        call!(cleanup, name, value_1).await;
        // The zone is deleted
        assert_eq!(database.0.read().await.len(), 0);
        check_query!(name, SOA, Refused, 0, false);
    }
}
