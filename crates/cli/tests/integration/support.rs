//! The disposable NetBox of the tests: how it is reached, emptied and read.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use omnisync_core::gateway::filters;
use omnisync_core::{Gateway, Row};
use omnisync_netbox::NetboxClient;
use serde_json::{Value, json};
use tokio::process::Command;
use tokio::sync::{Mutex, MutexGuard, OnceCell};

/// The variable `mise run dev:test-integration` gives the address of NetBox in.
const URL_VARIABLE: &str = "NETBOX_INTEGRATION_URL";

/// Where the stack of this run publishes NetBox: a port of the loopback Docker
/// chose, so that two checkouts run their tests at the same time. The task
/// reads it once the stack is up, and names the Compose project after the
/// checkout (`COMPOSE_PROJECT_NAME`, which the `docker compose` run here
/// inherits).
pub fn url() -> &'static str {
    static URL: OnceLock<String> = OnceLock::new();
    URL.get_or_init(|| {
        std::env::var(URL_VARIABLE)
            .unwrap_or_else(|_| panic!("{URL_VARIABLE} is not set: run the tests with `mise run dev:test-integration`"))
    })
}

/// The superuser of `docker-compose.yml`: throwaway values of the stack.
const SUPERUSER: &str = "admin";
const SUPERUSER_PASSWORD: &str = "admin-integration";

/// How long NetBox may take to answer after the stack is up.
const READY_TIMEOUT: Duration = Duration::from_secs(600);

/// The tests share one NetBox and each starts from an empty one: one at a time.
static NETBOX: Mutex<()> = Mutex::const_new(());

/// The API token of the superuser, provisioned once for the whole run.
static TOKEN: OnceCell<String> = OnceCell::const_new();

/// Everything the tests may leave behind, a dependent before what it depends on.
const ENDPOINTS: [&str; 23] = [
    "dcim.cables",
    "dcim.virtual_chassis",
    "virtualization.virtual_machines",
    "dcim.devices",
    "ipam.ip_addresses",
    "dcim.mac_addresses",
    "virtualization.virtual_disks",
    "virtualization.interfaces",
    "dcim.interfaces",
    "virtualization.clusters",
    "virtualization.cluster_types",
    "virtualization.cluster_groups",
    "ipam.prefixes",
    "ipam.vlans",
    "ipam.vlan_groups",
    "ipam.vrfs",
    "dcim.device_types",
    "dcim.manufacturers",
    "dcim.platforms",
    "dcim.device_roles",
    "dcim.sites",
    "tenancy.tenants",
    "extras.tags",
];

fn compose_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/integration/docker-compose.yml")
}

async fn wait_ready(http: &reqwest::Client) {
    let deadline = Instant::now() + READY_TIMEOUT;
    while Instant::now() < deadline {
        // 403: the API is up and wants a token.
        if let Ok(answer) = http.get(format!("{}/api/status/", url())).send().await
            && matches!(answer.status().as_u16(), 200 | 403)
        {
            return;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    panic!("NetBox did not start at {}: run the tests with `mise run dev:test-integration`", url());
}

/// Builds the OpenAPI schema once, before any client asks for it. NetBox caches
/// it for a day per release (`cache_page` on `api/schema/`), but a fresh stack
/// builds it on the first request (2 s for 4.5.10 and 4.7.5, Docker on a
/// laptop, 2026-11-24, longer on a busy CI runner): that time is kept out of
/// the timeout of the first test.
async fn warm_schema(token: &str) {
    let client = NetboxClient::builder(url(), token).timeout(READY_TIMEOUT).build().expect("a NetBox client");
    client
        .check_write(omnisync_core::Write::Create, "extras.tags", &["name".to_owned()])
        .await
        .expect("NetBox builds its schema");
}

async fn provision_token() -> String {
    let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().expect("an HTTP client");
    wait_ready(&http).await;
    // Fails harmlessly when the user already exists.
    let _ = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_file())
        .args(["exec", "-T", "netbox", "/opt/netbox/venv/bin/python", "/opt/netbox/netbox/manage.py"])
        .args(["createsuperuser", "--noinput"])
        .output()
        .await;
    let answer = http
        .post(format!("{}/api/users/tokens/provision/", url()))
        .json(&json!({"username": SUPERUSER, "password": SUPERUSER_PASSWORD}))
        .send()
        .await
        .expect("NetBox answers the token request");
    let status = answer.status();
    let body: Value = answer.json().await.expect("a JSON answer to the token request");
    // NetBox provisions a v2 token (`users/models/tokens.py:38`, 4.5 to 4.7),
    // `nbt_<key>.<token>`: its identifier and its secret come apart.
    let field = |name: &str| body.get(name).and_then(Value::as_str);
    let token = match (body.get("version").and_then(Value::as_u64), field("key"), field("token")) {
        (Some(2), Some(key), Some(token)) => format!("nbt_{key}.{token}"),
        _ => panic!("NetBox gave no v2 token ({status}): {body}"),
    };
    warm_schema(&token).await;
    token
}

/// The custom fields netbox-ssot defined on the NetBox it ran on: what the
/// old tool left behind, on more object types than this tool fills them on,
/// and `arp_entry` with its default. A run creates the ones a NetBox lacks
/// (`Netbox::without_custom_fields`); here it finds them all.
async fn ensure_custom_fields(client: &NetboxClient) {
    let source_types = [
        "dcim.device",
        "dcim.devicerole",
        "dcim.devicetype",
        "dcim.interface",
        "dcim.location",
        "dcim.manufacturer",
        "dcim.platform",
        "dcim.region",
        "dcim.site",
        "dcim.virtualdevicecontext",
        "ipam.ipaddress",
        "ipam.vlangroup",
        "ipam.vlan",
        "ipam.prefix",
        "ipam.vrf",
        "tenancy.tenantgroup",
        "tenancy.tenant",
        "tenancy.contact",
        "tenancy.contactassignment",
        "tenancy.contactgroup",
        "tenancy.contactrole",
        "virtualization.cluster",
        "virtualization.clustergroup",
        "virtualization.clustertype",
        "virtualization.virtualmachine",
        "virtualization.vminterface",
        "virtualization.virtualdisk",
    ];
    let mut with_wireless = source_types.to_vec();
    with_wireless.extend(["wireless.wirelesslan", "wireless.wirelesslangroup"]);
    let fields = [
        json!({"name": "source", "label": "Source", "type": "text", "object_types": with_wireless,
               "description": "Name of the source from which the object was collected"}),
        json!({"name": "source_id", "label": "Source ID", "type": "text", "object_types": source_types,
               "description": "ID of the object on the source API"}),
        json!({"name": "host_cpu_cores", "label": "Host CPU cores", "type": "text", "object_types": ["dcim.device"],
               "description": "Number of CPU cores on the host"}),
        json!({"name": "host_memory", "label": "Host memory", "type": "text", "object_types": ["dcim.device"],
               "description": "Amount of memory on the host"}),
        json!({"name": "arp_entry", "label": "Arp Entry", "type": "boolean", "default": false,
               "object_types": ["ipam.ipaddress"], "description": "Was this IP collected from ARP table"}),
    ];
    let held = client.list("extras.custom_fields", &Vec::new()).await.expect("the custom fields are listed");
    let held: BTreeSet<&str> = held.iter().filter_map(|field| field.get("name")?.as_str()).collect();
    for field in fields {
        if !held.contains(field["name"].as_str().expect("a name")) {
            let payload = field.as_object().expect("an object");
            client.create("extras.custom_fields", payload).await.expect("the custom field is created");
        }
    }
}

/// The NetBox of one test: emptied, and held until the test ends.
pub struct Netbox {
    pub client: NetboxClient,
    token: &'static str,
    _alone: MutexGuard<'static, ()>,
}

impl Netbox {
    /// Waits for its turn, then for NetBox, and deletes what the previous test
    /// left, its custom fields included: a test may have left one as no other
    /// expects it. The custom fields of netbox-ssot are then defined.
    pub async fn empty() -> Self {
        let netbox = Netbox::without_custom_fields().await;
        ensure_custom_fields(&netbox.client).await;
        netbox
    }

    /// The same, on a NetBox netbox-ssot never ran on: no custom field is defined.
    pub async fn without_custom_fields() -> Self {
        let mut endpoints = ENDPOINTS.to_vec();
        endpoints.push("extras.custom_fields");
        Netbox::emptied(&endpoints).await
    }

    async fn emptied(endpoints: &[&str]) -> Self {
        let alone = NETBOX.lock().await;
        let token = TOKEN.get_or_init(provision_token).await.as_str();
        let client = NetboxClient::new(url(), token).expect("a NetBox client");
        for endpoint in endpoints {
            let rows = client.list(endpoint, &Vec::new()).await.unwrap_or_else(|error| panic!("{endpoint}: {error}"));
            for row in rows {
                let id = row["id"].as_u64().expect("an id");
                client.delete(endpoint, id).await.unwrap_or_else(|error| panic!("{endpoint} {id}: {error}"));
            }
        }
        Netbox { client, token, _alone: alone }
    }

    /// A second client on the same NetBox, which refuses every write.
    pub fn dry_run(&self) -> NetboxClient {
        NetboxClient::builder(url(), self.token).dry_run(true).build().expect("a NetBox client")
    }

    /// Creates an object as an operator, or an old tool, would have; returns its id.
    pub async fn create(&self, endpoint: &str, payload: Value) -> u64 {
        let payload = payload.as_object().expect("an object");
        let created =
            self.client.create(endpoint, payload).await.unwrap_or_else(|error| panic!("seeding {endpoint}: {error}"));
        created["id"].as_u64().expect("an id")
    }

    pub async fn update(&self, endpoint: &str, id: u64, payload: Value) {
        let payload = payload.as_object().expect("an object");
        self.client.update(endpoint, id, payload).await.unwrap_or_else(|error| panic!("seeding {endpoint}: {error}"));
    }

    /// The objects of `endpoint` that match `query`, as the API renders them.
    pub async fn list<const N: usize>(&self, endpoint: &str, query: [(&str, &str); N]) -> Vec<Value> {
        let rows: Vec<Row> =
            self.client.list(endpoint, &filters(query)).await.unwrap_or_else(|error| panic!("{endpoint}: {error}"));
        rows.into_iter().map(Value::Object).collect()
    }

    /// The only object of `endpoint` that matches `query`.
    pub async fn one<const N: usize>(&self, endpoint: &str, query: [(&str, &str); N]) -> Value {
        let mut rows = self.list(endpoint, query).await;
        assert_eq!(rows.len(), 1, "{endpoint} {query:?} matches {} objects: {rows:?}", rows.len());
        rows.remove(0)
    }

    /// The names of the objects of `endpoint` that match `query`, sorted.
    pub async fn names<const N: usize>(&self, endpoint: &str, query: [(&str, &str); N]) -> Vec<String> {
        let rows = self.list(endpoint, query).await;
        let mut names: Vec<String> = rows.iter().map(|row| text(row, "/name").to_owned()).collect();
        names.sort();
        names
    }
}

/// The text at `pointer` (`/cluster/name`) in a rendered object.
pub fn text<'v>(object: &'v Value, pointer: &str) -> &'v str {
    object.pointer(pointer).and_then(Value::as_str).unwrap_or_else(|| panic!("no text at {pointer} in {object}"))
}

/// The slugs of the tags of a rendered object, sorted.
pub fn tag_slugs(object: &Value) -> Vec<String> {
    let tags = object["tags"].as_array().unwrap_or_else(|| panic!("no tags in {object}"));
    let mut slugs: Vec<String> = tags.iter().map(|tag| text(tag, "/slug").to_owned()).collect();
    slugs.sort();
    slugs
}
