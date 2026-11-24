# Contributing

How to work on netbox-omnisync: the checks a change must pass, how the tests
and their fixtures are organised, how to add a version of a source, and how to
add a source. The design is in [docs/design.md](docs/design.md).

## Setup and checks

The Rust toolchain is pinned in `rust-toolchain.toml`. With
[mise](https://mise.jdx.dev/), `mise install` provides it, with the tools the
tasks use (cargo-about, cargo-deny).

```sh
mise run dev:lint   # cargo fmt --check, clippy -D warnings, cargo doc, cargo deny check licenses, typos, shellcheck, actionlint, zizmor
mise run dev:test   # cargo test --workspace --locked
mise run dev:coverage   # the same tests with their coverage (cargo-llvm-cov): summary, report in target/llvm-cov/html
cargo deny check    # advisories, bans, licences and sources
```

A change is ready when the three pass. The tests need no network, no NetBox
and no equipment.

`dev:coverage` gives two figures. The first is llvm-cov's, over every line of
the source files, unit tests included; the second is the production code
alone (`scripts/coverage-production.py`, which leaves out what follows the
`#[cfg(test)]` of a file) with the files that are not at 100 %. Neither is a
gate: a line that ran is not a line that was checked.

What tells whether the tests would see a defect is mutation testing:
[cargo-mutants](https://mutants.rs/) changes the code and expects a test to
fail. It is not a tool of `mise.toml` (no binary is published for Apple
silicon, and compiling it on every `mise install` would cost minutes); install
it with `cargo install --locked cargo-mutants`, then run it on the files a
change touches:

```sh
cargo mutants -j 4 -f crates/redfish/src/collect.rs
```

A mutant listed as missed is a behaviour no test pins: write the test, and see
it fail on that mutant. It runs in a copy of the tree, where the `cargo` of
mise is not trusted: put the toolchain of rustup first on the `PATH` and set
`RUSTUP_TOOLCHAIN` to the version of `rust-toolchain.toml`.

A change to what is written to NetBox, or to how its answers are read, also
runs the integration tests, which the three above leave out (they are
`#[ignore]`d):

```sh
mise run dev:test-integration   # needs docker; 8 to 13 minutes on a CI runner
```

CI runs them every Monday and on demand (`workflow_dispatch`), with
`cargo deny check` against the advisories of the week. Such a run takes about
13 minutes from end to end: the three releases run side by side, and NetBox
4.5 is the slowest. Measured on a GitHub runner (`ubuntu-24.04`, run
44816003566, 2026-11-20), from the start of the task to the end of the tests:

| NetBox | Build and stack ready | Tests | Job |
|---|---|---|---|
| 4.5.10 | 6 min 20 | 6 min 27 | 13 min 02 |
| 4.6.10 | 4 min 19 | 3 min 53 | 8 min 38 |
| 4.7.5 | 5 min 03 | 4 min 05 | 9 min 33 |

The same run without them (a push) takes about 11 minutes, the macOS
universal binary being the longest job.

They run the real client and both runs against a disposable NetBox
(`crates/cli/tests/integration`, with its `docker-compose.yml`), of the
release `NETBOX_VERSION` names (`v4.5.10` when it is not set; CI runs each
supported release: `NETBOX_VERSION=v4.7.5 mise run dev:test-integration`
does one of them): a first run
creates, a second one writes nothing, what the old tools left is adopted by
its tags alone, what a source stops reporting is deleted, a renamed host or
machine is renamed in place. Every family writes there through the real
client, whose fields are checked against the schema of the release: a
scripted Proxmox, the recorded vCenter 6.7 and iDRAC 8 (served by the fakes
of their crates), the recorded NX-OS switch with its cables to a neighbour,
the recorded IOS stack through its virtual chassis, and the recorded
FortiGate cluster. The task starts the stack and destroys it whatever ends
it.

## Rules

- **Read-only towards the sources.** A source is read with a closed list of
  commands or API calls. A new call is added to that list, never sent beside
  it, and never anything that writes. No command containing `transceiver` is
  ever sent to a switch.
- **Unknown is not empty.** A value the source did not report stays `None`
  (or absent from a `Desired`), so that NetBox keeps what it has. Report an
  empty value only when the source says the value is empty.
- **Expected values are written by hand** from the raw fixture or from the
  requirement, never copied from what the code returns. Quote the line read in
  the fixture above the assertion, as `crates/proxmox/tests/collection.rs`
  does.
- **A bug is reproduced by a failing test first**, then fixed.
- **A defect of a reference tool is fixed, not ported.** Add a row to
  [docs/reference-defects.md](docs/reference-defects.md) naming the test that
  pins the fix.
- **No secret in a message, a log or a fixture.**

`CLAUDE.md` lists the tests that guard the rules of the code.

## Fixtures

A fixture is the output of real equipment, recorded as it was answered, then
anonymised: host names, addresses, serials and anything that identifies the
site are replaced, the structure is left untouched. A fixture is never
written by hand to fit a parser.

Fixtures are stored per source, and per version where the answers of the
versions were recorded:

| Source | Where | Layout |
|---|---|---|
| Proxmox VE | `crates/proxmox/tests/fixtures/<release>/api.json` (`8.4`, `9.2`) | One JSON object: API path (what follows `/api2/json`) to `{"status": <HTTP status>, "body": <answer>}`. Loaded by `fixture("<release>")` in `crates/proxmox/tests/common/mod.rs`, which serves it from a mock API |
| Cisco NX-OS | `crates/cisco/tests/fixtures/nxos_i2/`, `nxos_i4/` (two NX-OS trains) | One file per command, named after the command with every non-alphanumeric character replaced by `_`, then `.txt` (`show vlan brief \| json` is `show_vlan_brief___json.txt`). Loaded by `fixture_text(<directory>, <command>)` in `crates/cisco/src/parsers/mod.rs` |
| Cisco IOS | `crates/cisco/tests/fixtures/ios/` | Same as NX-OS |
| Nipper | `crates/cisco/tests/fixtures/nipper/<switch>.html` | One report excerpt per switch, loaded by `nipper_report(<switch>)` |
| FortiOS | `crates/fortios/tests/fixtures/<version>/` (`7.4.13`) | One file per API call, named like the Cisco ones, loaded by `fixture_text(<version>, <call>)` in `crates/fortios/src/parser.rs` |
| Redfish (BMC) | `crates/redfish/tests/fixtures/<family>/api.json` (iDRAC 7, 8 and 9, iLO 4; one directory per BMC family and firmware) | One JSON object: request path to `{"status": <HTTP status>, "body": <answer>}`, an empty body being `""`. Loaded by `fixture("<family>")` in `crates/redfish/tests/common/mod.rs`, which serves it from a mock BMC. `crates/redfish/tests/fixtures/README.md` says what each one is and what was never observed |

## Adding a version of a source

The example is Proxmox VE; the layout above gives the equivalent for the
other sources.

### A new release of a major already supported

Proxmox VE 8 and 9 are supported (`SUPPORTED_MAJORS` in
`crates/proxmox/src/collect.rs`). A new release of one of them, say 9.3,
needs no change to the collection unless its answers differ.

1. **Record the answers.** Create
   `crates/proxmox/tests/fixtures/9.3/api.json` with the answer to every path
   the collection reads: `/version`, `/cluster/status`, `/nodes`, then for
   each node `/nodes/<node>/status`, `/network`, `/qemu` and `/lxc`, for each
   virtual machine `/nodes/<node>/qemu/<vmid>/config` and, when it runs,
   `/agent/network-get-interfaces` and `/agent/get-osinfo`, and for each
   running container `/nodes/<node>/lxc/<vmid>/interfaces`. Keep the failed
   answers too (the 8.4 fixture holds four answers of status 500): they are
   part of what the version says. Anonymise the file.
2. **Check that the file loads and is collected.** Add to
   `crates/proxmox/tests/collection.rs`, next to
   `the_9_2_cluster_is_collected_whole`, a test that collects the new fixture
   and asserts what you read in the file, each value quoted from it:

   ```rust
   #[tokio::test]
   async fn the_9_3_cluster_is_collected_whole() {
       let cluster = collected(fixture("9.3")).await;

       // "/version": "data": { "release": "9.3", "version": "9.3.1" }
       assert_eq!(cluster.version.version, "9.3.1");
       assert_eq!(cluster.version.release, "9.3");
       assert_eq!(cluster.version.major(), Some(9));
       // "/cluster/status": { "id": "cluster", "name": "pve-cluster-b", … }
       assert_eq!(cluster.name, "pve-cluster-b");
   }
   ```

   Go on with the nodes, the guests and their interfaces, as the tests of 8.4
   and 9.2 do.
3. **Count its requests.** Add the release to
   `the_collection_only_ever_reads`, with the number of GETs computed from the
   file (the comment above each line of that test shows how): the test fails
   if the collection asks for a path that is not in the fixture, asks twice,
   or sends anything but GETs after the login.
4. **Translate it.** Add to `crates/proxmox/tests/translation.rs` the
   `…_is_created_once_and_a_second_run_writes_nothing` test of the release
   (`created_once_then_nothing`), with the number of late references counted
   in the file.
5. **Run** `cargo test -p omnisync-proxmox`, then the checks above.

If a test of step 2 to 4 fails because the release answers differently, the
difference goes into the version seam described below, not around it.

### A new major

Everything that depends on the version of Proxmox VE is in one place: the
private type `Dialect` of `crates/proxmox/src/collect.rs`, between the two
`VERSION SEAM` banners. A major outside `SUPPORTED_MAJORS` is refused before
anything else is read. After the five steps above:

1. add the major to `SUPPORTED_MAJORS` and a variant to `Dialect`, picked in
   `Dialect::of`;
2. where the major needs another call, `match self` in the method that gives
   the path, or add a method for a new choice (as `asks_guest`);
3. where a field changed its name or its type, say it on the field of the
   `Wire…` struct (`#[serde(alias = …)]`, or a lenient reader): those structs
   are the only code that names JSON fields;
4. update
   `a_version_the_collection_was_not_written_for_is_refused_before_reading_anything_else`
   in `crates/proxmox/tests/collection.rs`: it names the supported majors in
   the message it expects, and uses `10.0.1` as a version that is refused.

### Cisco and FortiOS

A new NX-OS train or IOS release is a new directory under
`crates/cisco/tests/fixtures/`, holding the output of every command of
`NXOS_COMMANDS` or `IOS_COMMANDS` (`crates/cisco/src/commands.rs`), a constant
for it in the `fixtures` module of `crates/cisco/src/parsers/mod.rs`, and the
parser tests run on it next to the existing ones (`crates/cisco/src/parsers/`).
The lists of commands are closed: a version that needs another command is a
change to the list, with its tests in `commands.rs`.

A new FortiOS version is likewise a directory under
`crates/fortios/tests/fixtures/`, named after the version (`7.4.13`), holding
the answer to every call of `FORTIOS_COMMANDS` (`crates/fortios/src/api.rs`),
a constant for it next to `V7_4_13` in the `fixtures` module of
`crates/fortios/src/parser.rs`, and the parser tests run on it next to the
existing ones.

## Adding a version of NetBox

The supported releases are the variants of `Dialect`
(`crates/netbox/src/version.rs`), each tested on the last patch of its minor
by the `integration` job of `.github/workflows/ci.yml`. A run refuses another
release (or warns, `netbox.unsupported_version`). For a new minor, say 4.8:

1. **Run the integration tests on it**, before changing anything:
   `NETBOX_VERSION=v4.8.0 mise run dev:test-integration`. A field the tool
   writes that the release removed or renamed is refused, naming it
   (`unknown field … NetBox would drop it`); a shape or a unit that changed
   shows as a second run that is not empty, or a value read back that differs.
2. **Read its release notes**, the "Breaking Changes" of each release: what
   the tests do not write (a field NetBox now renders otherwise, a token or a
   requirement of the API) is found there. The selection custom fields read as
   `{value, label}` in 4.7, and the v1 tokens 4.7 removed, came from there.
3. **Add the variant** to `Dialect` and to `Dialect::SUPPORTED`. Where the
   release writes or reads an object differently, the difference is a method
   of `Dialect`, matched on `self`, between the `VERSION SEAM` banners, and the
   code that writes or reads the object asks it: never a version compared
   anywhere else. A release that differs in nothing only adds its variant.
4. **Add the release to the matrix** of the `integration` job, and to the
   tests of `version.rs` that name the supported releases.
5. **Update** the NetBox prerequisites of `README.md`, the first line of
   `CLAUDE.md` and the comment of `unsupported_version` in
   `config.example.toml`.

Dropping a minor is the same in reverse; the default of `NETBOX_VERSION` in
`docker-compose.yml` is the oldest supported release.

## Adding a source

### A network source (switch, router, firewall)

The device exists in NetBox; the source only has to describe it.

1. **Collect into a `DeviceState`** (`crates/core/src/network/model.rs`), in
   its own crate or in the crate of its vendor. Split the work as the existing
   ones do: a transport that runs a closed list of commands or calls, pure
   parsers from text to data, a `collect` that assembles the state. Leave
   `None`, or turn off the `…_managed` flag, for what the source cannot tell.
   A truncated or empty answer is a collection error, never an empty state: an
   empty state plus `--prune` deletes everything.
2. **Declare the type**: `TYPES` (and `REPORT_TYPES` or `API_TYPES` when it is
   not read over SSH) in `crates/core/src/network/inventory.rs`, with the keys
   and secrets its entry needs; `SourceType` in `crates/cli/src/select.rs`.
3. **Plug it into the run**: `reader_of` and `Collector::collect` in
   `crates/cli/src/collector.rs`.
4. **Tests**: parsers on fixtures; the collection with a fake transport
   (closed list, in order, a refused or malformed answer fails the
   collection); one end-to-end run in `crates/cli/src/network.rs` against
   `FakeGateway`, applied then diffed again to nothing.
5. **Document**: an entry in `config.example.toml`, the row of the type in
   `README.md`.

### A hypervisor source

The source owns its objects; it reports them and the reconciliation does the
rest. `crates/proxmox` and `crates/vmware` are the models.

1. **Client and collection**: a read-only client and a `collect` that returns
   plain data, with the version handling in one place.
2. **Translation**: one pure function from that data to `Vec<Desired>`
   (`crates/core/src/inventory/model.rs`), with no I/O. Declare only what the
   source says; mark what could not be read with `unknown_dependents`.
3. **Declare the type**: `HypervisorType` and `HYPERVISOR_TYPES` in
   `crates/cli/src/config.rs` (and any new key in `HYPERVISOR_KEYS`),
   `SourceType` in `crates/cli/src/select.rs`. An entry of another kind than
   `hypervisor` (as `bmc`) has its own types and keys there (`BMC_TYPES`,
   `BMC_KEYS`), its `SourceKind`, and is skipped by the network loader
   (`check_entry` in `crates/core/src/network/inventory.rs`).
4. **Plug it into the run**: `Apis::read` in `crates/cli/src/hypervisors.rs`.
5. **Tests**: collection and translation on fixtures; the translation
   reconciled with an empty NetBox then with its own result, which must change
   nothing; if the source replaces a tool, a NetBox as that tool left it,
   which must change tags only.
6. **Document**: `config.example.toml`, `README.md`, and
   `docs/reference-defects.md` for what is not reproduced.

### A BMC source, or another source that completes devices

`crates/redfish` is the model: a source that owns nothing and completes a
device another source, or somebody, keeps. It follows the steps of a
hypervisor source, with three differences.

1. **Translation**: the device is reported as a `complement`
   (`Desired::complement`), with nothing but the fields the source knows; what
   it needs to exist (a manufacturer, a device type) is `ensure_only`.
2. **Proof**: what is said on the word of something reached at a configured
   address is `Guarded` (`crates/core/src/inventory/guard.rs`), and is only
   reconciled once NetBox shows the device to be the right one.
3. **Failure unit**: one entry reads many machines. One that cannot be read
   goes into `Reading::errors`; the reading itself succeeds, and the run
   marks the source `Partial`.

A new BMC family or firmware is a new directory under
`crates/redfish/tests/fixtures/`: record the answer to every path the
collection reads (`crates/redfish/src/collect.rs` lists them), anonymise it,
then add its test to `crates/redfish/tests/collection.rs` (values read in the
file, quoted), its line to
`the_collection_only_ever_reads_and_asks_each_recorded_answer_once` with the
number of answers of the file, and its `…_completes_its_server_once_and_a_second_run_writes_nothing`
to `crates/redfish/tests/translation.rs`. A vendor whose serial is not in
`SerialNumber` is one more arm of `serial` in `crates/redfish/src/translate.rs`,
with its test; a call the collection needs is one more variant of `Call` in
`crates/redfish/src/client.rs`, never a request sent beside the list.

## Workflows and releases

After editing a workflow, run
`mise x actionlint@1.7.12 -- actionlint .github/workflows/*.yml`. Actions are pinned by
commit, with the release in a comment; look the release up
(`gh api repos/<owner>/<repo>/releases/latest --jq .tag_name`) rather than
writing it from memory.

The release build can be tried locally:

```sh
mise run dev:release-build darwin-universal   # or linux-amd64, linux-arm64 (docker)
mise run dev:licenses
```

`dev:release-build` generates the third-party notices itself (cargo-about) and
compiles the binary with them: `crates/cli/build.rs` embeds the file
`OMNISYNC_NOTICES` names, for `netbox-omnisync licenses`, and fails the build
when that file is missing or empty. Without the variable, as in a plain
`cargo build`, nothing is embedded and the command says so.

A release is made by the maintainer: the version of `Cargo.toml` is bumped,
then an annotated tag `vX.Y.Z`, signed with a key of `.github/release-signers`,
is created locally and pushed. A new signing key goes into that file, by a
reviewed commit, before it tags.
`.github/workflows/release.yml` refuses any other tag and never creates one.
