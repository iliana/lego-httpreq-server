use std::{collections::hash_map::Entry, collections::HashMap, sync::Arc};

use axum::{extract::State, routing::post, Json, Router};
use hickory_proto::op::{self, Header, LowerQuery, ResponseCode as RC};
use hickory_proto::rr::{self, rdata, LowerName, Name, RData, Record, RecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use tracing::{debug, error, info, instrument, warn, Level};
use tracing_subscriber::{filter::filter_fn, prelude::*};

static N: std::sync::OnceLock<RData> = std::sync::OnceLock::new();

#[tokio::main]
async fn main() {
    let args = xflags::parse_or_exit! {
        /// Print all tracing events.
        optional --debug
        /// Address to serve DNS on. [default: [::]:53]
        optional --dns-addr dns_addr: String
        /// Address to serve the httpreq API on. [default: localhost:80]
        optional --http-addr http_addr: String
        /// Name to return in responses to NS queries for our zones.
        optional ns_name: Name
    };
    let dns_addr = args.dns_addr.unwrap_or_else(|| "[::]:53".to_owned());
    let http_addr = args.http_addr.unwrap_or_else(|| "localhost:80".to_owned());
    if let Some(mut ns_name) = args.ns_name {
        ns_name.set_fqdn(true);
        N.set(RData::NS(rdata::NS(ns_name))).unwrap();
    }

    let layer = tracing_subscriber::fmt::layer().with_filter(filter_fn(move |meta| {
        args.debug || (meta.module_path() == Some(module_path!()) && *meta.level() <= Level::INFO)
    }));
    tracing_subscriber::registry().with(layer).init();
    debug!(dns_addr, http_addr, name = N.get().map(|s| s.to_string()));

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

// The Database is a set of zones. The first Vec in the zone array is the set of
// TXT records; the second is the SOA record followed by an optional NS record.
#[derive(Debug, Clone, Default)]
struct Database(Arc<tokio::sync::RwLock<HashMap<LowerName, [Vec<Record>; 2]>>>);

// It's kind of amazing that this next line works at all. This aliases
// `RwLockReadGuard` to the much shorter `Guard`, both for the type references
// below (where it defaults to T = [Record]), but also for `RwLockReadGuard`'s
// associated functions _for any T_, just to make some of these match arms fit
// on a single line.
type Guard<'a, T = [Record]> = tokio::sync::RwLockReadGuard<'a, T>;

// The response type for the `query` function, below. The `Result` is a slice of
// `Record`s kept in an `RwLockReadGuard`; `Ok` means the records belong in the
// answer section, and `Err` means the records belong in the authority section.
type Response<'a> = (RC, Result<Guard<'a>, Guard<'a>>);

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
        (op::MessageType::Query, op::OpCode::Query, rr::DNSClass::IN) => {}
        _ => return (RC::NotImp, Err(Guard::map(zones, |_| &[][..]))),
    }

    match Guard::try_map(zones, |zones| zones.get(query.name())) {
        Ok(z) => match query.query_type() {
            RecordType::TXT => (RC::NoError, Ok(Guard::map(z, |z| &z[0][..]))),
            RecordType::SOA => (RC::NoError, Ok(Guard::map(z, |z| &z[1][..1]))),
            RecordType::NS if N.get().is_some() => (RC::NoError, Ok(Guard::map(z, |z| &z[1][1..]))),
            _ => (RC::NoError, Err(Guard::map(z, |z| &z[1][..1]))),
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
                        return (RC::NXDomain, Err(Guard::map(zone, |z| &z[1][..1])));
                    }
                    Err(locked_zones) => zones = locked_zones,
                }
            }
            // We have no authority.
            (RC::Refused, Err(Guard::map(zones, |_| &[][..])))
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
            header.set_response_code(RC::ServFail);
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
    let [txts, _] = zones.entry(fqdn.clone()).or_insert_with(|| {
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
        let mut vec = vec![Record::from_rdata(fqdn.clone().into(), 5, RData::SOA(soa))];
        // Add the NS record, if one is set.
        vec.extend((N.get().cloned()).map(|n| Record::from_rdata(fqdn.clone().into(), 5, n)));
        [Vec::with_capacity(1), vec]
    });
    let txt = Record::from_rdata(fqdn.into(), 5, RData::TXT(rdata::TXT::new(vec![value])));
    let _ = txts.binary_search(&txt).map_err(|i| txts.insert(i, txt));
    info!(len = txts.len());
}

#[instrument(skip(database))]
async fn cleanup(State(database): State<Database>, Json(Body { fqdn, value }): Json<Body>) {
    if let Entry::Occupied(mut zone) = database.0.write().await.entry(fqdn.clone()) {
        let txt = Record::from_rdata(fqdn.into(), 5, RData::TXT(rdata::TXT::new(vec![value])));
        let _ = (zone.get()[0].binary_search(&txt)).map(|index| zone.get_mut()[0].remove(index));
        info!(len = zone.get()[0].len());
        zone.get()[0].is_empty().then(|| zone.remove());
    }
    warn!("no such record");
}

#[cfg(test)]
#[tokio::test]
async fn test() {
    static DATABASE: std::sync::LazyLock<Database> = std::sync::LazyLock::new(Database::default);

    fn b(fqdn: &str, value: &str) -> Json<Body> {
        let (fqdn, value) = (fqdn.parse().unwrap(), value.to_owned());
        Json(Body { fqdn, value })
    }

    async fn check(name: &str, ty: RecordType) -> (RC, usize, usize) {
        let q = op::Query::query(name.parse().unwrap(), ty);
        let (rcode, result) = query(&DATABASE, &Header::new(), &q.into()).await;
        let [answers, soa] = split_result(&result);
        (rcode, answers.len(), soa.len())
    }

    let (n, s) = ("_acme-challenge.meow.", "subdomain._acme-challenge.meow.");

    for i in 0..2 {
        assert_eq!(DATABASE.0.read().await.len(), 0);
        assert_eq!(check(n, RecordType::SOA).await, (RC::Refused, 0, 0));

        // Add a record
        let value_1 = "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM";
        for _ in 0..2 {
            present(State(DATABASE.clone()), b(n, value_1)).await;
            assert_eq!(check(n, RecordType::TXT).await, (RC::NoError, 1, 0));
            assert_eq!(check(n, RecordType::SOA).await, (RC::NoError, 1, 0));
            assert_eq!(check(n, RecordType::NS).await, (RC::NoError, i, i ^ 1));
            assert_eq!(check(n, RecordType::AAAA).await, (RC::NoError, 0, 1));
            assert_eq!(check(s, RecordType::SOA).await, (RC::NXDomain, 0, 1));
        }

        // Add another record with the same FDQN, this time without the root label
        // (it should be canonicalized)
        let value_2 = "XaG3ZYfMMh2r9jvX961Z2nHDKcxXJm65_kLxolgb08k";
        for _ in 0..2 {
            present(State(DATABASE.clone()), b(n.trim_end_matches('.'), value_2)).await;
            // Ensure there is only one zone in the database
            assert_eq!(DATABASE.0.read().await.len(), 1);
            // Two records are returned for the TXT query
            assert_eq!(check(n, RecordType::TXT).await, (RC::NoError, 2, 0));
            assert_eq!(check(n, RecordType::SOA).await, (RC::NoError, 1, 0));
        }

        // Clean up the latter record
        for _ in 0..2 {
            cleanup(State(DATABASE.clone()), b(n, value_2)).await;
            // The zone is still present
            assert_eq!(DATABASE.0.read().await.len(), 1);
            assert_eq!(check(n, RecordType::TXT).await, (RC::NoError, 1, 0));
            assert_eq!(check(n, RecordType::SOA).await, (RC::NoError, 1, 0));
        }

        // Clean up the original record
        for _ in 0..2 {
            cleanup(State(DATABASE.clone()), b(n, value_1)).await;
        }

        // Before we run the second time, set `NS`
        (N.set(RData::NS(rdata::NS("ns1.meow.".parse().unwrap())))).ok();
    }
}
