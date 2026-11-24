//! The reverse DNS lookups of a run (`dns_name_lookup`).
//!
//! The translations of the hypervisor sources are pure: the names are looked
//! up here first, then handed to them as a table. One [`ReverseLookups`]
//! serves the whole run:
//!
//! - an address is asked once, whatever the number of sources that report it
//!   (per list of resolvers: two sources that name different resolvers may be
//!   given different names);
//! - lookups run at once, a bounded number of them in flight, each within a
//!   time limit, and the lookups of one source within a budget: a resolver
//!   that no longer answers costs that budget, not a timeout per address;
//! - nothing here fails a source. A lookup that fails gives no name, so the
//!   address reports none and NetBox keeps the one it has; the failures of the
//!   run are counted and told in one warning.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures::future::{BoxFuture, join_all};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use omnisync_core::inventory::dns::preferred;
use tokio::sync::{OnceCell, Semaphore};
use tokio::time::Instant;

/// How many times the resolver sends a query again before giving up: once,
/// for a datagram lost.
const RETRIES: usize = 1;

/// How much of the reason of a failure is shown.
const SHOWN_REASON: usize = 120;

/// How the lookups of a run are bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How many lookups are in flight at once, all sources together.
    pub in_flight: usize,
    /// The time a resolver is given to answer one query; a query is sent twice.
    pub attempt_timeout: Duration,
    /// The time one lookup may take, whatever happens inside the resolver.
    pub lookup_timeout: Duration,
    /// The time the lookups of one source may take: once it is spent, the
    /// lookups that did not start are not attempted.
    pub budget: Duration,
}

impl Default for Limits {
    /// Fifty lookups in flight; three seconds a lookup (netbox-ssot gave two,
    /// one address after the other); fifteen seconds a source, so that a
    /// resolver that died costs fifteen seconds, eighteen with the lookups
    /// then in flight, whatever the number of addresses.
    fn default() -> Self {
        Limits {
            in_flight: 50,
            attempt_timeout: Duration::from_secs(1),
            lookup_timeout: Duration::from_secs(3),
            budget: Duration::from_secs(15),
        }
    }
}

/// Why a lookup gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtrError {
    TimedOut,
    /// Anything else, in a few words.
    Failed(String),
}

/// Something that answers PTR queries: the real resolver, or a fake one.
pub trait Ptr: Send + Sync {
    /// The names the address resolves to, as the DNS has them; none when the
    /// address has no PTR record, which is an answer and not a failure.
    fn names(&self, address: IpAddr) -> BoxFuture<'_, Result<Vec<String>, PtrError>>;
}

/// Builds the resolver that asks these servers, or the ones of the system
/// when the list is empty. A failure is its reason, in a few words.
pub type Connect = dyn Fn(&[SocketAddr], &Limits) -> Result<Arc<dyn Ptr>, String> + Send + Sync;

/// The first line of an error, cut: an error of the resolver may quote a
/// whole query or a system message.
fn brief(error: &dyn Display) -> String {
    let text = error.to_string();
    let line = text.lines().next().unwrap_or_default().trim();
    let cut: String = line.chars().take(SHOWN_REASON).collect();
    if cut.len() < line.len() { format!("{cut}...") } else { cut }
}

/// What one list of resolvers answered so far, and the resolver that asks them.
struct Group {
    /// Built when the first address is asked; its failure is kept, and is
    /// the failure of every lookup.
    resolver: Result<Arc<dyn Ptr>, String>,
    /// One cell per address: the lookup of an address runs once, and whoever
    /// reports the same address waits for it.
    answers: HashMap<IpAddr, Arc<OnceCell<Option<String>>>>,
}

/// The lookups of the run that failed.
#[derive(Default)]
struct Tally {
    asked: usize,
    timed_out: usize,
    not_attempted: usize,
    in_error: usize,
    /// The error of the lowest address: the one shown, whatever finished first.
    first_error: Option<(IpAddr, String)>,
}

/// The lookups of a run: see the module.
pub struct ReverseLookups {
    connect: Box<Connect>,
    limits: Limits,
    in_flight: Semaphore,
    groups: Mutex<BTreeMap<Vec<SocketAddr>, Group>>,
    tally: Mutex<Tally>,
}

impl std::fmt::Debug for ReverseLookups {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ReverseLookups").field("limits", &self.limits).finish_non_exhaustive()
    }
}

/// A resolver and the cell of an address it is asked for.
type Pending = (IpAddr, Arc<OnceCell<Option<String>>>);

impl ReverseLookups {
    /// The lookups of a real run: asked to the resolvers a source names, or
    /// to the ones of the system.
    pub fn system() -> Self {
        Self::with(Box::new(hickory), Limits::default())
    }

    /// Lookups answered by what `connect` builds, within these limits.
    pub fn with(connect: Box<Connect>, limits: Limits) -> Self {
        ReverseLookups {
            connect,
            limits,
            in_flight: Semaphore::new(limits.in_flight),
            groups: Mutex::new(BTreeMap::new()),
            tally: Mutex::new(Tally::default()),
        }
    }

    /// The names of these addresses, asked to these resolvers (the ones of
    /// the system when there is none). An address that is not in the answer
    /// has no known name: no record, or a lookup that failed.
    pub async fn resolve(&self, servers: &[SocketAddr], addresses: &BTreeSet<IpAddr>) -> BTreeMap<IpAddr, String> {
        if addresses.is_empty() {
            return BTreeMap::new();
        }
        let (resolver, pending) = self.pending(servers, addresses);
        let deadline = Instant::now() + self.limits.budget;
        let answers = join_all(pending.into_iter().map(|(address, cell)| {
            let resolver = &resolver;
            async move {
                let name = cell.get_or_init(|| self.ask(resolver, address, deadline)).await.clone();
                name.map(|name| (address, name))
            }
        }));
        answers.await.into_iter().flatten().collect()
    }

    /// The resolver of these servers, and the cell of each address.
    fn pending(
        &self,
        servers: &[SocketAddr],
        addresses: &BTreeSet<IpAddr>,
    ) -> (Result<Arc<dyn Ptr>, String>, Vec<Pending>) {
        let known = self.groups.lock().unwrap_or_else(PoisonError::into_inner).contains_key(servers);
        // Built out of the lock: building reads /etc/resolv.conf, and the other
        // sources need the lock meanwhile. Two sources building at once keep the first.
        let built =
            (!known).then(|| (self.connect)(servers, &self.limits).map_err(|reason| format!("no resolver: {reason}")));
        let mut groups = self.groups.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(resolver) = built {
            groups.entry(servers.to_vec()).or_insert_with(|| Group { resolver, answers: HashMap::new() });
        }
        let group = groups.get_mut(servers).expect("inserted above, or known");
        let cells = addresses.iter().map(|address| (*address, Arc::clone(group.answers.entry(*address).or_default())));
        (group.resolver.clone(), cells.collect())
    }

    /// One lookup: its name, or `None` with the failure counted.
    async fn ask(&self, resolver: &Result<Arc<dyn Ptr>, String>, address: IpAddr, deadline: Instant) -> Option<String> {
        let outcome = self.attempt(resolver, address, deadline).await;
        let mut tally = self.tally.lock().unwrap_or_else(PoisonError::into_inner);
        tally.asked += 1;
        match outcome {
            Ok(names) => return preferred(names),
            Err(None) => tally.not_attempted += 1,
            Err(Some(PtrError::TimedOut)) => tally.timed_out += 1,
            Err(Some(PtrError::Failed(reason))) => {
                tally.in_error += 1;
                if tally.first_error.as_ref().is_none_or(|(lowest, _)| address < *lowest) {
                    tally.first_error = Some((address, reason));
                }
            }
        }
        None
    }

    /// The names of an address; `Err(None)` when the budget was spent before
    /// the lookup could start.
    async fn attempt(
        &self,
        resolver: &Result<Arc<dyn Ptr>, String>,
        address: IpAddr,
        deadline: Instant,
    ) -> Result<Vec<String>, Option<PtrError>> {
        let resolver = resolver.as_ref().map_err(|reason| Some(PtrError::Failed(reason.clone())))?;
        // A place among the lookups in flight, waited for no longer than the budget lasts.
        let place = tokio::time::timeout_at(deadline, self.in_flight.acquire()).await;
        let Ok(Ok(_place)) = place else {
            return Err(None);
        };
        if Instant::now() >= deadline {
            return Err(None);
        }
        match tokio::time::timeout(self.limits.lookup_timeout, resolver.names(address)).await {
            Ok(answer) => answer.map_err(Some),
            Err(_) => Err(Some(PtrError::TimedOut)),
        }
    }

    /// One warning for every lookup of the run that failed, `None` when none
    /// did: the tool runs every few minutes, and a resolver that is down
    /// would otherwise warn once per address.
    pub fn warning(&self) -> Option<String> {
        let tally = self.tally.lock().unwrap_or_else(PoisonError::into_inner);
        let failed = tally.timed_out + tally.not_attempted + tally.in_error;
        if failed == 0 {
            return None;
        }
        let mut causes = Vec::new();
        if tally.timed_out > 0 {
            causes.push(format!("{} timed out", tally.timed_out));
        }
        if tally.not_attempted > 0 {
            let budget = self.limits.budget.as_secs();
            causes.push(format!("{} not attempted: more than {budget} s spent", tally.not_attempted));
        }
        if let Some((address, reason)) = &tally.first_error {
            causes.push(format!("{} in error, the first one {address}: {}", tally.in_error, brief(reason)));
        }
        Some(format!(
            "reverse DNS: {failed} of {} lookups failed ({}); the DNS names NetBox holds for these addresses are kept",
            tally.asked,
            causes.join(", ")
        ))
    }
}

/// The real resolver: hickory, asked over UDP then TCP.
struct Hickory(TokioResolver);

impl Ptr for Hickory {
    fn names(&self, address: IpAddr) -> BoxFuture<'_, Result<Vec<String>, PtrError>> {
        Box::pin(async move {
            match self.0.reverse_lookup(address).await {
                Ok(lookup) => Ok(lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::PTR(name) => Some(name.0.to_string()),
                        _ => None,
                    })
                    .collect()),
                // No PTR record, or no such name: an answer.
                Err(error) if error.is_no_records_found() => Ok(Vec::new()),
                Err(NetError::Timeout) => Err(PtrError::TimedOut),
                Err(error) => Err(PtrError::Failed(brief(&error))),
            }
        })
    }
}

/// Builds the real resolver: the servers given, or the ones of the system
/// (`/etc/resolv.conf`) with its hosts file, as the tools before this one.
fn hickory(servers: &[SocketAddr], limits: &Limits) -> Result<Arc<dyn Ptr>, String> {
    let mut builder = if servers.is_empty() {
        TokioResolver::builder_tokio().map_err(|error| brief(&error))?
    } else {
        let server = |server: &SocketAddr| {
            let (mut udp, mut tcp) = (ConnectionConfig::udp(), ConnectionConfig::tcp());
            udp.port = server.port();
            tcp.port = server.port();
            NameServerConfig::new(server.ip(), true, vec![udp, tcp])
        };
        let config = ResolverConfig::from_name_servers(servers.iter().map(server).collect());
        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
    };
    let options = builder.options_mut();
    options.timeout = limits.attempt_timeout;
    options.attempts = RETRIES;
    // Every lookup in flight may be waiting on the same connection.
    options.max_active_requests = options.max_active_requests.max(limits.in_flight);
    if !servers.is_empty() {
        // The servers that were named are the ones asked, not the hosts file.
        options.use_hosts_file = ResolveHosts::Never;
    }
    let resolver = builder.build().map_err(|error| brief(&error))?;
    Ok(Arc::new(Hickory(resolver)))
}

/// A fake DNS server for the tests of the lookups, here and end to end.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use hickory_resolver::proto::op::{Message, ResponseCode};
    use hickory_resolver::proto::rr::rdata::PTR;
    use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
    use tokio::net::UdpSocket;

    use std::net::IpAddr;

    use futures::future::BoxFuture;

    use super::{Limits, Ptr, PtrError, ReverseLookups};

    /// A resolver that answers from a table, or fails every lookup, and
    /// counts what it is asked: for the tests that need no network at all.
    #[derive(Default)]
    pub(crate) struct Scripted {
        pub(crate) names: BTreeMap<IpAddr, &'static str>,
        /// Every lookup fails with this reason.
        pub(crate) failing: Option<&'static str>,
        /// How many times each address was asked.
        pub(crate) asked: Mutex<BTreeMap<IpAddr, usize>>,
        /// How many resolvers were built.
        pub(crate) built: Mutex<usize>,
    }

    impl Scripted {
        pub(crate) fn answering<const N: usize>(names: [(&str, &'static str); N]) -> Arc<Self> {
            let names = names.into_iter().map(|(address, name)| (address.parse().unwrap(), name)).collect();
            Arc::new(Scripted { names, ..Scripted::default() })
        }

        pub(crate) fn failing(reason: &'static str) -> Arc<Self> {
            Arc::new(Scripted { failing: Some(reason), ..Scripted::default() })
        }

        /// The lookups of one run, answered by this resolver.
        pub(crate) fn lookups(self: &Arc<Self>) -> ReverseLookups {
            let resolver = Arc::clone(self);
            let connect = move |_: &[SocketAddr], _: &Limits| {
                *resolver.built.lock().unwrap() += 1;
                Ok(Arc::clone(&resolver) as Arc<dyn Ptr>)
            };
            ReverseLookups::with(Box::new(connect), Limits::default())
        }
    }

    impl Ptr for Scripted {
        fn names(&self, address: IpAddr) -> BoxFuture<'_, Result<Vec<String>, PtrError>> {
            *self.asked.lock().unwrap().entry(address).or_insert(0) += 1;
            let answer = match self.failing {
                Some(reason) => Err(PtrError::Failed(reason.to_owned())),
                None => Ok(self.names.get(&address).map(|name| (*name).to_owned()).into_iter().collect()),
            };
            Box::pin(std::future::ready(answer))
        }
    }

    /// What the server does of a PTR query.
    #[derive(Debug, Clone)]
    pub(crate) enum Reply {
        /// These names, in this order.
        Names(Vec<&'static str>),
        /// The server fails (`SERVFAIL`).
        Failure,
        /// Nothing is ever sent back.
        Silence,
    }

    /// A DNS server on a local UDP port: it answers the PTR queries of its
    /// table, and `NXDOMAIN` to every other query.
    pub(crate) struct FakeDns {
        pub(crate) address: SocketAddr,
        /// The names that were asked, in the order the queries arrived.
        asked: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for FakeDns {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl FakeDns {
        /// `table` is keyed by the name asked, as it is on the wire:
        /// `36.0.18.198.in-addr.arpa.` for 198.18.0.36.
        pub(crate) async fn serving<const N: usize>(table: [(&'static str, Reply); N]) -> Self {
            let table: BTreeMap<String, Reply> =
                table.into_iter().map(|(name, reply)| (name.to_owned(), reply)).collect();
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a local UDP port");
            let address = socket.local_addr().expect("its address");
            let asked = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&asked);
            let task = tokio::spawn(async move {
                let mut buffer = [0_u8; 1500];
                loop {
                    let Ok((length, from)) = socket.recv_from(&mut buffer).await else {
                        return;
                    };
                    let Ok(request) = Message::from_vec(&buffer[..length]) else {
                        continue;
                    };
                    let Some(query) = request.queries.first().cloned() else {
                        continue;
                    };
                    let name = query.name.to_string().to_ascii_lowercase();
                    seen.lock().unwrap().push(name.clone());
                    let reply = if query.query_type == RecordType::PTR { table.get(&name) } else { None };
                    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
                    response.metadata.recursion_desired = request.metadata.recursion_desired;
                    response.metadata.recursion_available = true;
                    response.add_query(query.clone());
                    match reply {
                        Some(Reply::Silence) => continue,
                        Some(Reply::Failure) => response.metadata.response_code = ResponseCode::ServFail,
                        Some(Reply::Names(names)) => {
                            for target in names {
                                let target = Name::from_ascii(target).expect("a name");
                                response.add_answer(Record::from_rdata(
                                    query.name.clone(),
                                    300,
                                    RData::PTR(PTR(target)),
                                ));
                            }
                        }
                        None => response.metadata.response_code = ResponseCode::NXDomain,
                    }
                    let Ok(bytes) = response.to_vec() else {
                        continue;
                    };
                    let _ = socket.send_to(&bytes, from).await;
                }
            });
            FakeDns { address, asked, task }
        }

        /// How many times each name was asked.
        pub(crate) fn asked(&self) -> BTreeMap<String, usize> {
            let mut counts = BTreeMap::new();
            for name in self.asked.lock().unwrap().iter() {
                *counts.entry(name.clone()).or_insert(0) += 1;
            }
            counts
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::testing::{FakeDns, Reply};
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn set<const N: usize>(addresses: [&str; N]) -> BTreeSet<IpAddr> {
        addresses.into_iter().map(ip).collect()
    }

    fn table<const N: usize>(names: [(&str, &str); N]) -> BTreeMap<IpAddr, String> {
        names.into_iter().map(|(address, name)| (ip(address), name.to_owned())).collect()
    }

    /// What a fake resolver does of an address.
    #[derive(Clone)]
    enum Does {
        Answer(Vec<&'static str>),
        Fail(&'static str),
        /// Never answers.
        Hang,
    }

    /// A resolver that answers from a rule after a delay, and counts.
    struct Fake {
        rule: Box<dyn Fn(IpAddr) -> Does + Send + Sync>,
        delay: Duration,
        asked: Mutex<BTreeMap<IpAddr, usize>>,
        in_flight: AtomicUsize,
        most_in_flight: AtomicUsize,
    }

    impl Fake {
        fn new(delay: Duration, rule: impl Fn(IpAddr) -> Does + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Fake {
                rule: Box::new(rule),
                delay,
                asked: Mutex::new(BTreeMap::new()),
                in_flight: AtomicUsize::new(0),
                most_in_flight: AtomicUsize::new(0),
            })
        }

        fn asked(&self) -> BTreeMap<IpAddr, usize> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Ptr for Fake {
        fn names(&self, address: IpAddr) -> BoxFuture<'_, Result<Vec<String>, PtrError>> {
            Box::pin(async move {
                *self.asked.lock().unwrap().entry(address).or_insert(0) += 1;
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.most_in_flight.fetch_max(now, Ordering::SeqCst);
                let does = (self.rule)(address);
                if matches!(does, Does::Hang) {
                    // The count is left as it is: a lookup given up on is cancelled, which frees nothing here.
                    std::future::pending::<()>().await;
                }
                tokio::time::sleep(self.delay).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                match does {
                    Does::Answer(names) => Ok(names.into_iter().map(str::to_owned).collect()),
                    Does::Fail(reason) => Err(PtrError::Failed(reason.to_owned())),
                    Does::Hang => unreachable!(),
                }
            })
        }
    }

    /// Lookups answered by `fake` whatever the resolvers asked for, which are remembered.
    fn lookups(fake: &Arc<Fake>, limits: Limits) -> (ReverseLookups, Arc<Mutex<Vec<Vec<SocketAddr>>>>) {
        let built = Arc::new(Mutex::new(Vec::new()));
        let (fake, seen) = (Arc::clone(fake), Arc::clone(&built));
        let connect = move |servers: &[SocketAddr], _: &Limits| {
            seen.lock().unwrap().push(servers.to_vec());
            Ok(Arc::clone(&fake) as Arc<dyn Ptr>)
        };
        (ReverseLookups::with(Box::new(connect), limits), built)
    }

    /// `10.0.<n / 250>.<n % 250 + 1>` for each `n` below `count`.
    fn many(count: usize) -> BTreeSet<IpAddr> {
        (0..count).map(|n| ip(&format!("10.0.{}.{}", n / 250, n % 250 + 1))).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn the_name_of_each_address_is_the_answer_of_the_resolver() {
        let fake = Fake::new(Duration::from_millis(5), |address| match address.to_string().as_str() {
            "10.0.0.5" => Does::Answer(vec!["web01.lab.example."]),
            "2001:db8::5" => Does::Answer(vec!["web01.v6.example."]),
            _ => Does::Answer(vec![]),
        });
        let (lookups, _) = lookups(&fake, Limits::default());
        let names = lookups.resolve(&[], &set(["10.0.0.5", "10.0.0.6", "2001:db8::5"])).await;
        // The name is given as the DNS has it: the translation removes the dot and lowers the case.
        assert_eq!(names, table([("10.0.0.5", "web01.lab.example."), ("2001:db8::5", "web01.v6.example.")]));
        // An address without record is an answer: nothing failed.
        assert_eq!(lookups.warning(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn among_several_records_the_same_one_is_kept_whatever_their_order() {
        let fake = Fake::new(Duration::ZERO, |address| match address.to_string().as_str() {
            "10.0.0.5" => Does::Answer(vec!["web01.example.", "app01.example."]),
            _ => Does::Answer(vec!["app01.example.", "web01.example."]),
        });
        let (lookups, _) = lookups(&fake, Limits::default());
        let names = lookups.resolve(&[], &set(["10.0.0.5", "10.0.0.6"])).await;
        assert_eq!(names, table([("10.0.0.5", "app01.example."), ("10.0.0.6", "app01.example.")]));
    }

    #[tokio::test(start_paused = true)]
    async fn an_address_two_sources_report_is_asked_once() {
        let fake = Fake::new(Duration::from_millis(20), |address| {
            Does::Answer(if address == ip("10.0.0.5") { vec!["web01.lab.example."] } else { vec![] })
        });
        let (lookups, built) = lookups(&fake, Limits::default());
        // Two sources read at once, then a third one later.
        let (one, other) = (set(["10.0.0.5", "10.0.0.6"]), set(["10.0.0.5", "10.0.0.7"]));
        let (first, second) = tokio::join!(lookups.resolve(&[], &one), lookups.resolve(&[], &other));
        let third = lookups.resolve(&[], &set(["10.0.0.5", "10.0.0.6", "10.0.0.7"])).await;
        let expected = table([("10.0.0.5", "web01.lab.example.")]);
        assert_eq!((first, second, third), (expected.clone(), expected.clone(), expected));
        assert_eq!(fake.asked(), BTreeMap::from([(ip("10.0.0.5"), 1), (ip("10.0.0.6"), 1), (ip("10.0.0.7"), 1)]));
        // And one resolver was built for the three of them.
        assert_eq!(*built.lock().unwrap(), [Vec::<SocketAddr>::new()]);
    }

    #[tokio::test(start_paused = true)]
    async fn sources_that_name_different_resolvers_do_not_share_their_answers() {
        let fake = Fake::new(Duration::ZERO, |_| Does::Answer(vec!["web01.lab.example."]));
        let (lookups, built) = lookups(&fake, Limits::default());
        let inside: Vec<SocketAddr> = vec!["192.0.2.53:53".parse().unwrap()];
        lookups.resolve(&[], &set(["10.0.0.5"])).await;
        lookups.resolve(&inside, &set(["10.0.0.5"])).await;
        lookups.resolve(&inside, &set(["10.0.0.5"])).await;
        assert_eq!(fake.asked(), BTreeMap::from([(ip("10.0.0.5"), 2)]));
        assert_eq!(*built.lock().unwrap(), [Vec::new(), inside]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_thousand_lookups_run_fifty_at_a_time_and_take_twenty_times_one() {
        let fake = Fake::new(Duration::from_millis(20), |_| Does::Answer(vec!["host.lab.example."]));
        let (lookups, _) = lookups(&fake, Limits::default());
        let addresses = many(1000);
        let started = Instant::now();
        let names = lookups.resolve(&[], &addresses).await;
        // 1000 lookups of 20 ms, 50 at a time: 20 waves, 400 ms. One after the other they would take 20 s.
        assert_eq!(started.elapsed(), Duration::from_millis(400));
        assert_eq!(fake.most_in_flight.load(Ordering::SeqCst), 50);
        assert_eq!(names.len(), 1000);
        assert_eq!(fake.asked().values().copied().collect::<BTreeSet<usize>>(), BTreeSet::from([1]));
        assert_eq!(lookups.warning(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn the_bound_is_shared_by_the_sources_read_at_once() {
        let fake = Fake::new(Duration::from_millis(20), |_| Does::Answer(vec![]));
        let (lookups, _) = lookups(&fake, Limits::default());
        let (low, high): (BTreeSet<IpAddr>, BTreeSet<IpAddr>) =
            many(400).into_iter().partition(|address| *address < ip("10.0.0.201"));
        assert_eq!((low.len(), high.len()), (200, 200));
        tokio::join!(lookups.resolve(&[], &low), lookups.resolve(&[], &high));
        assert_eq!(fake.most_in_flight.load(Ordering::SeqCst), 50);
    }

    #[tokio::test(start_paused = true)]
    async fn a_resolver_that_never_answers_costs_the_budget_and_one_warning() {
        let fake = Fake::new(Duration::ZERO, |_| Does::Hang);
        let (lookups, _) = lookups(&fake, Limits::default());
        let started = Instant::now();
        let names = lookups.resolve(&[], &many(1000)).await;
        // Waves of 50 lookups given up after 3 s start at 0, 3, 6, 9 and 12 s; at 15 s the budget is
        // spent and the 750 others are not attempted.
        assert_eq!(started.elapsed(), Duration::from_secs(15));
        assert_eq!(names, BTreeMap::new());
        assert_eq!(fake.asked().len(), 250);
        assert_eq!(
            lookups.warning().as_deref(),
            Some(
                "reverse DNS: 1000 of 1000 lookups failed (250 timed out, 750 not attempted: more than 15 s spent); \
                 the DNS names NetBox holds for these addresses are kept"
            )
        );
        // The addresses given up on are not asked again by the next source.
        let again = Instant::now();
        lookups.resolve(&[], &many(1000)).await;
        assert_eq!(again.elapsed(), Duration::ZERO);
        assert_eq!(fake.asked().len(), 250);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_times_out_does_not_hold_the_others() {
        let fake = Fake::new(Duration::from_millis(5), |address| {
            if address == ip("10.0.0.6") { Does::Hang } else { Does::Answer(vec!["web01.lab.example."]) }
        });
        let (lookups, _) = lookups(&fake, Limits::default());
        let started = Instant::now();
        let names = lookups.resolve(&[], &set(["10.0.0.5", "10.0.0.6"])).await;
        assert_eq!(started.elapsed(), Duration::from_secs(3));
        assert_eq!(names, table([("10.0.0.5", "web01.lab.example.")]));
        assert_eq!(
            lookups.warning().as_deref(),
            Some(
                "reverse DNS: 1 of 2 lookups failed (1 timed out); \
                 the DNS names NetBox holds for these addresses are kept"
            )
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_failures_of_a_run_are_one_warning_whose_reason_is_cut() {
        let fake = Fake::new(Duration::ZERO, |address| match address.to_string().as_str() {
            "10.0.0.5" => Does::Answer(vec!["web01.lab.example."]),
            "10.0.0.6" => Does::Fail("server failure"),
            _ => Does::Fail("another reason, never shown"),
        });
        let (lookups, _) = lookups(&fake, Limits::default());
        let (one, other) = (set(["10.0.0.5", "10.0.0.6", "10.0.0.7"]), set(["10.0.0.6", "10.0.0.8"]));
        let (first, second) = tokio::join!(lookups.resolve(&[], &one), lookups.resolve(&[], &other));
        assert_eq!(first, table([("10.0.0.5", "web01.lab.example.")]));
        assert_eq!(second, BTreeMap::new());
        // Each address counts once; the reason shown is the one of the lowest address.
        assert_eq!(
            lookups.warning().as_deref(),
            Some(
                "reverse DNS: 3 of 4 lookups failed (3 in error, the first one 10.0.0.6: server failure); \
                 the DNS names NetBox holds for these addresses are kept"
            )
        );
    }

    #[test]
    fn the_reason_of_a_failure_is_its_first_line_cut() {
        assert_eq!(brief(&"server failure"), "server failure");
        assert_eq!(brief(&"  io error: refused\n  at resolver.rs:12\n  at pool.rs:40"), "io error: refused");
        let long = "x".repeat(500);
        assert_eq!(brief(&long), format!("{}...", "x".repeat(120)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_resolver_that_cannot_be_built_fails_no_source_and_is_one_warning() {
        let connect = |_: &[SocketAddr], _: &Limits| Err("cannot read /etc/resolv.conf".to_owned());
        let lookups = ReverseLookups::with(Box::new(connect), Limits::default());
        let names = lookups.resolve(&[], &set(["10.0.0.5", "10.0.0.6"])).await;
        assert_eq!(names, BTreeMap::new());
        assert_eq!(
            lookups.warning().as_deref(),
            Some(
                "reverse DNS: 2 of 2 lookups failed (2 in error, the first one 10.0.0.5: no resolver: \
                 cannot read /etc/resolv.conf); the DNS names NetBox holds for these addresses are kept"
            )
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_address_asks_nothing_and_builds_no_resolver() {
        let fake = Fake::new(Duration::ZERO, |_| Does::Answer(vec![]));
        let (lookups, built) = lookups(&fake, Limits::default());
        assert_eq!(lookups.resolve(&[], &BTreeSet::new()).await, BTreeMap::new());
        assert_eq!(*built.lock().unwrap(), Vec::<Vec<SocketAddr>>::new());
    }

    /// Limits short enough for a test against a server that stays silent.
    fn short() -> Limits {
        Limits {
            attempt_timeout: Duration::from_millis(150),
            lookup_timeout: Duration::from_millis(500),
            ..Limits::default()
        }
    }

    #[tokio::test]
    async fn the_real_resolver_asks_the_servers_it_is_given() {
        let server = FakeDns::serving([
            // 198.18.0.36
            ("36.0.18.198.in-addr.arpa.", Reply::Names(vec!["ESX04.Lab.Example."])),
            // 2001:db8::5
            (
                "5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
                Reply::Names(vec!["web01.v6.example."]),
            ),
            // 198.18.0.37: two records, as a round robin would give them.
            ("37.0.18.198.in-addr.arpa.", Reply::Names(vec!["web01.example.", "app01.example."])),
            // 198.18.0.38
            ("38.0.18.198.in-addr.arpa.", Reply::Failure),
            // 198.18.0.39
            ("39.0.18.198.in-addr.arpa.", Reply::Silence),
        ])
        .await;
        let lookups = ReverseLookups::with(Box::new(hickory), short());
        let addresses = set(["198.18.0.36", "198.18.0.37", "198.18.0.38", "198.18.0.39", "198.18.0.40", "2001:db8::5"]);
        let started = std::time::Instant::now();
        let names = lookups.resolve(&[server.address], &addresses).await;
        let elapsed = started.elapsed();
        assert_eq!(
            names,
            table([
                ("198.18.0.36", "ESX04.Lab.Example."),
                ("198.18.0.37", "app01.example."),
                ("2001:db8::5", "web01.v6.example."),
            ])
        );
        // 198.18.0.40 has no record (NXDOMAIN): an answer. The failure and the silence are the two failures.
        let warning = lookups.warning().expect("a warning");
        assert!(
            warning.starts_with(
                "reverse DNS: 2 of 6 lookups failed (1 timed out, 1 in error, the first one 198.18.0.38: "
            ),
            "{warning}"
        );
        assert!(warning.len() < 320, "{warning}");
        // The silent server held nothing but its own lookup, and for no longer than a lookup may take.
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        // Each address was asked, the silent one twice (a query is sent twice), the others once.
        let asked = server.asked();
        assert_eq!(asked["36.0.18.198.in-addr.arpa."], 1);
        assert_eq!(asked["40.0.18.198.in-addr.arpa."], 1);
        assert_eq!(asked["39.0.18.198.in-addr.arpa."], 2);

        // A second source reporting the same addresses asks nothing again.
        lookups.resolve(&[server.address], &addresses).await;
        assert_eq!(server.asked(), asked);
    }

    #[tokio::test]
    async fn a_server_that_is_not_there_fails_the_lookups_not_the_run() {
        // A local port nothing listens on.
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let nowhere = socket.local_addr().unwrap();
        drop(socket);
        let lookups = ReverseLookups::with(Box::new(hickory), short());
        let started = std::time::Instant::now();
        let names = lookups.resolve(&[nowhere], &many(200)).await;
        assert_eq!(names, BTreeMap::new());
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        let warning = lookups.warning().expect("a warning");
        assert!(warning.starts_with("reverse DNS: 200 of 200 lookups failed ("), "{warning}");
        assert!(warning.len() < 320, "{warning}");
    }
}
