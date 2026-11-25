# CLAUDE.md

netbox-omnisync syncs hypervisors (Proxmox VE, VMware vSphere), the BMCs of
servers (Redfish: Dell iDRAC, HPE iLO), switches and routers (Cisco IOS,
NX-OS, Nipper reports) and firewalls (FortiOS) into NetBox 4.5 to 4.7. It replaces netbox-ssot, netbox-switch-sync and
netbox-sync. User documentation: `README.md`. Design: `docs/design.md`.

## Commands

The toolchain is pinned by `rust-toolchain.toml` (Rust 1.95.0, edition 2024);
`mise install` provides it with cargo-about and cargo-deny. Every mise task is prefixed `dev:`.

```sh
mise run dev:lint      # fmt, clippy -D warnings, cargo doc -D warnings, deny licenses, typos, shellcheck, actionlint, zizmor
mise run dev:test      # cargo test --workspace --locked
mise run dev:test-integration   # the ignored tests, against a disposable NetBox in Docker (NETBOX_VERSION, v4.5.10 by default; 8 to 13 minutes)
cargo deny check       # advisories, bans, licences and sources

cargo test -p omnisync-core reconcile                    # the tests of one module
cargo test -p omnisync-cisco a_transceiver_command       # one test, by a part of its name
cargo test -p omnisync-proxmox --test collection         # one integration test file
cargo run -p omnisync-cli -- help                        # the binary is netbox-omnisync

mise run dev:release-build darwin-universal   # dist/netbox-omnisync-<platform>, its .sha256, and the notices it embeds
mise run dev:coverage                     # coverage of the unit tests: summary, and target/llvm-cov/html/index.html
mise run dev:licenses                     # dist/THIRD-PARTY-NOTICES.txt (cargo-about)
```

`dev:release-build` takes `linux-amd64`, `linux-arm64` or `darwin-universal`;
the Linux ones need docker. Done means `dev:lint`,
`cargo deny check` and `dev:test` pass. `dev:test-integration`
(`crates/cli/tests/integration`) starts its own stack and destroys it whatever
ends the task; run it after a change to what is written to NetBox or to how
its answers are read. CI runs it, with `cargo deny check`, every Monday and
on demand (`.github/workflows/ci.yml`, job `integration`).

The tests need no network, no NetBox and no device: sources are served from
fixtures (wiremock, an in-process SSH server), NetBox by `FakeGateway`, the
DNS by a fake resolver or a fake server on a loopback UDP port
(`crates/cli/src/dns.rs`, `testing`). Never contact a real BMC, hypervisor or
NetBox from a test or to write one.

## Architecture

A Cargo workspace, one crate per concern:

| Crate | Role |
|---|---|
| `crates/core` (`omnisync-core`) | Pure logic, no I/O beyond reading the configuration file: the `Gateway` trait, `Change`, `Outcome`, the report and the progress, and the two families below (`network`, `inventory`) |
| `crates/netbox` (`omnisync-netbox`) | `NetboxClient` (the REST implementation of `Gateway`), the readers of the NetBox state, the two appliers, and `testing::FakeGateway` |
| `crates/proxmox` (`omnisync-proxmox`) | Proxmox VE: `ProxmoxClient`, `collect` (plain data), `translate::desired` (pure), `neighbors` (what `lldpd` tells of the cards of a node, through a `Shell`) |
| `crates/cisco` (`omnisync-cisco`) | IOS and NX-OS over SSH (`transport`, `commands`, `parsers`), Nipper reports, known hosts |
| `crates/fortios` (`omnisync-fortios`) | FortiOS REST API: `api` (client, pinned certificate), `parser`, `collect` |
| `crates/vmware` (`omnisync-vmware`) | The VMware source: read-only SOAP (`vim25`) and REST (tags) client, collection of a whole vCenter in one session (and, when asked, the switch port each card of each host hears), translation to `Desired` and `Heard` (`docs/vmware-reference.md` is its reference) |
| `crates/ssh` (`omnisync-ssh`) | The SSH client side shared by the switches and the Proxmox nodes: known hosts, algorithms, one authentication attempt, an interactive shell or one command on an `exec` channel |
| `crates/tls` (`omnisync-tls`) | TLS to a host whose self-signed certificate is pinned by its SHA-256 (`Fingerprint`, `pinned_tls`): the FortiOS and the Redfish clients |
| `crates/redfish` (`omnisync-redfish`) | The BMC source (kind `bmc`): read-only Redfish client with a closed list of `GET` (`Call`), collection of one BMC, translation to a guarded report that completes an existing device (`tests/fixtures/README.md` says what was observed) |
| `crates/cli` (`omnisync-cli`) | The `netbox-omnisync` binary: `cli` (arguments, lock, exit codes), `config`, `select`, `host` (the short and the full name of the machine, through libc), the two runs (`hypervisors`, `network`), `dns` (the reverse lookups of a run, the only user of `hickory-resolver`), `journal` (one JSON line per sync), and the two commands that read it: `check` (a Nagios plugin, for Icinga) and `digest` (the daily mail, text and HTML, handed to sendmail) |

Everything NetBox goes through `omnisync_core::Gateway` (`list`, `create`,
`update`, `delete`). `cli::run` takes its arguments, environment, streams and
backend as parameters: the whole wiring is tested without a process.

### Two families

**Network** (switches, routers, firewalls): the device exists in NetBox, the
run completes it.

```
collect (SSH, API or report) -> DeviceState
  -> stack::desired_devices -> diff_device / diff_cables / diff_vlans -> Vec<Change>
  -> netbox::apply::Applier
```

Code: `crates/core/src/network/`, `crates/netbox/src/{state,apply}.rs`,
`crates/cli/src/network.rs`. The run is five ordered steps: collection and
NetBox reads, site VLANs, devices, cables, interface deletions.

**Inventory** (hypervisors, BMCs): the source owns its objects, marked by
tags; a BMC source owns nothing but the device types it creates, and only
completes devices (`Desired::complement`, behind `inventory::guard`).

```
collect -> translate -> Vec<Desired>
  -> reconcile(desired, current, run) -> Plan      (pure, crates/core/src/inventory/reconcile.rs)
  -> netbox::inventory_apply::apply
```

The translations are pure: a reverse DNS lookup (`dns_name_lookup`) is done
before them, by translating once with a resolver that only notes what it is
asked (`inventory::dns::Asked`), and its answers are handed in as a table
(`docs/design.md`, "DNS names").

`Plan.steps` come out sorted: creations and updates in dependency order
(`Kind::ALL`), then late references (`Phase::Link`), then deletions in reverse
order. The applier writes them as given and stops at the first failure.

Hypervisors run first, so that the network sources find their hosts in NetBox.
When the run also reads network sources, the hypervisors are asked what the
cards of their hosts hear of their switches (`Heard`, `hypervisors::run_hearing`),
and the cable step merges it into the neighbours of the switches
(`omnisync_core::network::hosts::merge_heard`) before `diff_cables`.
BMC sources are reconciled with them, in the same plan, when both are selected;
`--kind hypervisor` never selects one.

## Rules that are easy to break

Each rule names the tests that guard it. Do not weaken a guard to make a
change pass: the rule is the requirement.

**Read-only towards the sources.** Nothing but reads reaches a device or a
hypervisor; the only non-GET requests are the logins (Proxmox ticket, FortiOS
session) and the FortiOS logout. On a Proxmox node asked for its neighbours,
one command over SSH, `lldpcli -f json show neighbors`, without a terminal.
- `crates/proxmox/tests/collection.rs`: `the_collection_only_ever_reads`,
  `only_the_lldpcli_command_is_ever_run`
- `crates/ssh/src/lib.rs`: `one_command_is_run_without_a_terminal_and_its_output_is_given`
- `crates/vmware/tests/collection.rs`: `a_collection_that_wants_the_hints_only_sends_reads_and_session_operations`
- `crates/vmware/src/soap.rs`: `only_reads_and_session_operations_can_be_sent`
- `crates/cisco/src/transport.rs`: `a_refused_command_never_reaches_the_wire`,
  `no_command_is_ever_run_outside_the_session`
- `crates/fortios/src/api.rs`: `only_reads_go_through_the_session`,
  `a_path_outside_the_closed_list_is_refused_before_anything_is_sent`
- `crates/redfish/src/client.rs`: `every_call_is_a_get_carrying_the_basic_account`,
  `a_path_outside_the_closed_list_is_refused_before_anything_is_sent`,
  `a_path_a_bmc_gives_is_only_asked_when_it_has_the_shape_of_its_call`
- `crates/redfish/tests/collection.rs`:
  `the_collection_only_ever_reads_and_asks_each_recorded_answer_once`,
  `a_path_of_a_bmc_that_is_not_one_of_the_closed_list_is_never_asked`

**The account of a BMC never leaves for another host.** No redirect is
followed; the `308` an iLO 4 answers to a path without its final `/` is asked
again by the client on the same BMC, without reading `Location`. A certificate
pinned in `tls_fingerprints` is the only one accepted.
- `crates/redfish/src/client.rs`: `a_308_is_asked_again_with_the_final_slash_on_the_same_bmc`,
  `a_308_is_followed_once_and_no_other_redirect_ever_is`
- `crates/redfish/tests/tls.rs`: `the_pinned_certificate_of_a_bmc_is_taken_without_any_authority`,
  `another_certificate_is_refused_before_the_account_leaves`
- `crates/cli/src/config.rs`: `the_certificate_of_each_bmc_is_pinned_by_its_device`

**A BMC source only completes devices that exist, and proves each one.** It
never creates a device, never deletes, never tags a device; nothing is written
for a device unless a MAC address the BMC reports is on one of its NetBox
interfaces; a serial the BMC does not know (blank) is never written.
- `crates/core/src/inventory/guard.rs`:
  `a_bmc_whose_addresses_are_on_another_device_is_refused_naming_both`,
  `a_device_without_any_mac_address_in_netbox_is_not_written`,
  `a_device_that_is_not_in_netbox_is_left_out_with_a_warning`,
  `a_placeholder_address_proves_nothing` (an all-zero, broadcast or group MAC proves no server)
- `crates/core/src/inventory/reconcile.rs`:
  `a_report_that_only_completes_never_creates_its_object`,
  `a_bmc_alone_completes_a_device_and_never_tags_it`
- `crates/cli/src/hypervisors.rs`:
  `a_bmc_source_never_creates_a_device_nor_deletes_whatever_its_entry_says`
- `crates/cli/src/config.rs`: `a_bmc_entry_never_creates_nor_prunes_and_refuses_to_be_told_to`
- `crates/redfish/tests/translation.rs`: `a_serial_made_of_spaces_never_clears_the_one_netbox_has`,
  `a_permanent_address_netbox_holds_does_not_prove_the_server`,
  `the_serial_written_for_a_dell_is_never_its_serial_number`

**Two sources never write a field back and forth.** A report that completes
an object is merged field by field: it beats a fallback (`only_when_empty`)
whatever the priority, and the priority settles two definite values. Two
sources that own an object and run apart (two hosts, two kinds, two crons)
follow the priority as in one run: an object that carries the tag of a better
ranked source left out of the run (`Skipped`) is that source's, and the run
only adds its own tag to it, without a warning. A report another source
completes in the run is written as before.
- `crates/core/src/inventory/reconcile.rs`:
  `what_a_bmc_knows_wins_over_the_fallback_of_a_hypervisor_whatever_the_priority`,
  `a_device_a_bmc_completed_is_stable_whoever_reports_it_next`,
  `two_sources_that_know_a_field_differently_never_write_it_back_and_forth`,
  `an_object_a_better_source_left_out_of_the_run_holds_is_left_as_netbox_has_it`,
  `two_sources_run_apart_never_write_an_object_back_and_forth`,
  `an_object_a_worse_source_left_out_holds_is_written_by_the_better_one`,
  `an_object_the_better_source_no_longer_holds_is_written_by_the_one_that_runs`,
  `a_reference_of_an_object_left_to_a_better_source_is_still_in_use`,
  `what_completes_an_object_a_better_source_left_out_holds_is_still_written`
- `crates/cli/src/hypervisors.rs`:
  `the_hardware_of_a_device_a_bmc_documents_is_the_bmc_s_to_tell` (a hypervisor
  only fills the hardware of a device a `bmc` entry lists)
- `crates/cli/src/cli.rs`:
  `two_hosts_that_report_the_same_object_never_write_it_back_and_forth`,
  `a_vcenter_and_a_bmc_that_differ_on_a_serial_leave_the_one_of_the_bmc`,
  `a_proxmox_and_its_bmcs_settle_on_the_hardware_of_the_bmc_without_source_priority`,
  `a_proxmox_and_its_bmcs_settle_on_the_hardware_of_the_bmc_whichever_source_is_ranked_first`

**A BMC that cannot be read fails alone.** It is an error of the run; the
other BMCs are written, and the source, read in part (`SourceStatus::Partial`),
says nothing of what it did not report: no tag is taken back, nothing is orphaned.
- `crates/core/src/inventory/reconcile.rs`:
  `a_source_read_in_part_is_written_and_says_nothing_of_what_it_did_not_report`
- `crates/cli/src/hypervisors.rs`:
  `a_bmc_that_cannot_be_read_is_an_error_and_the_others_are_written`,
  `a_bmc_that_fails_after_a_good_run_clears_and_orphans_nothing`
- `crates/cli/src/cli.rs`:
  `a_missing_device_a_wrong_bmc_and_a_failed_bmc_leave_the_others_and_netbox_alone`
- A Proxmox node that `GET /nodes` says is `offline` or `unknown` is read in part the same way:
  `crates/proxmox/tests/collection.rs`:
  `a_node_proxmox_says_is_offline_is_left_out_and_named_and_the_others_are_read`,
  `a_node_whose_status_proxmox_does_not_know_is_left_out_as_an_offline_one`,
  `crates/cli/src/hypervisors.rs`: `a_node_proxmox_says_is_offline_is_an_error_and_orphans_nothing`

**What a host hears decides the cable of the port, after the switch.** On a
port of a switch of the run, the neighbour the switch announces is believed,
then what a card of a host hears (`QueryNetworkHint`), then the description;
a host that contradicts the description or the cable replaces it, prune or
not, report or not, with a warning. A blade (a host with a `parent_device`)
gives nothing; a card NetBox does not have leaves the port as it is. A switch
the run does not read is given nothing, nor a short name two of them share.
A host whose hint fails, a source that fails or is left out, say nothing.
Hints are only asked by a run that also reads network sources; a Proxmox node
is only logged into when its entry says `neighbors = "lldpd"` too, and only
its physical (`eth`) cards count.
- `crates/core/src/network/hosts.rs`: `a_card_that_hears_a_switch_is_a_neighbour_of_its_port`,
  `the_neighbour_a_switch_announces_wins_over_what_a_host_hears_and_the_difference_is_warned`,
  `what_a_host_hears_wins_over_the_description_of_the_port_and_the_difference_is_warned`,
  `a_switch_that_is_not_in_the_run_is_not_given_a_neighbour`,
  `a_host_inside_a_chassis_never_takes_the_cable_of_its_chassis`,
  `a_short_name_two_switches_of_the_run_hold_is_resolved_to_neither`,
  `a_card_netbox_does_not_have_leaves_the_description_of_the_port`,
  `the_serial_a_nexus_adds_to_its_name_is_not_part_of_it`,
  `a_host_that_reported_nothing_leaves_the_cables_as_they_are`
- `crates/core/src/network/cables.rs`:
  `a_cable_a_host_hears_replaces_the_one_netbox_has_even_on_a_report_and_without_prune`
- `crates/vmware/tests/collection.rs`: `the_hints_are_only_asked_when_the_collection_wants_them`,
  `a_host_whose_hint_fails_is_a_warning_and_the_others_are_read`,
  `a_network_system_read_that_fails_is_a_warning_and_the_vcenter_is_read`
- `crates/cli/src/network.rs`: `the_cable_of_a_report_switch_follows_what_the_host_hears`,
  `a_wrong_cable_of_a_report_switch_is_replaced_by_what_the_host_hears`,
  `a_blade_never_takes_the_cable_of_its_chassis`
- `crates/cli/src/hypervisors.rs`: `a_vcenter_that_fails_leaves_the_cables_of_its_hosts_alone`
- `crates/cli/src/cli.rs`: `a_run_of_the_hypervisors_alone_never_asks_for_the_hints`
- `crates/proxmox/tests/collection.rs`: `a_node_whose_neighbours_cannot_be_read_is_a_warning_and_the_others_are_read`,
  `a_neighbour_heard_on_a_bridge_is_left_out`,
  `the_switch_port_of_each_card_of_a_node_is_reported_under_its_netbox_name`
- `crates/cli/src/hypervisors.rs`: `a_node_is_only_logged_into_when_the_entry_asks_for_it`,
  `a_run_of_the_hypervisors_alone_never_logs_into_a_node`
- `crates/cli/src/config.rs`: `a_proxmox_entry_opens_no_ssh_session_unless_it_asks_for_its_neighbours`,
  `neighbours_asked_without_an_account_are_refused`,
  `the_ssh_password_of_a_proxmox_entry_is_only_needed_by_a_run_that_reads_its_neighbours`,
  `a_vmware_entry_takes_no_ssh_block`

**A BMC is only read when asked for.** `--kind hypervisor` runs every few
minutes and must not select a `bmc` source.
- `crates/cli/src/select.rs`: `selecting_the_hypervisors_never_selects_a_bmc_source`
- `crates/cli/src/cli.rs`: `only_a_run_that_asks_for_the_bmcs_reads_them`

**No transceiver command, on any platform.** A command containing
`transceiver` is refused before the lists are looked at: on some switches it
crashes and reboots the device.
- `crates/cisco/src/commands.rs`: `a_transceiver_command_is_refused_on_both_platforms`,
  `no_listed_command_names_a_transceiver`

**A closed command list per platform.** `NXOS_COMMANDS`, `IOS_COMMANDS` and
`FORTIOS_COMMANDS` are the only things asked; a command is sent only if it is
exactly one of the list of its platform. The lines typed before the commands
are a closed list as well (`SESSION_SETUP`, checked by `check_setup`).
- `crates/cisco/src/commands.rs`: `the_nxos_list_is_the_one_of_the_python_tool`,
  `the_ios_list_is_the_one_of_the_python_tool`, `an_arbitrary_command_is_refused`,
  `a_listed_command_with_anything_added_is_refused`,
  `a_listed_nxos_command_is_refused_for_ios`, `a_listed_ios_command_is_refused_for_nxos`
- `crates/cisco/src/commands.rs`: `only_the_session_settings_are_typed_before_the_commands`
- `crates/cisco/src/collect.rs`: `the_commands_run_are_the_closed_list_in_order`
- `crates/fortios/src/api.rs`: `the_calls_are_the_closed_list_of_the_reference_in_order`

**Strict NetBox filters.** NetBox ignores an unknown filter and returns every
object: a typo would turn a prune into a mass deletion. Each filter is checked
against the OpenAPI schema and refused before any request; so is an empty
value, which NetBox drops with the filter.
- `crates/netbox/src/client.rs`: `an_unknown_filter_is_refused_before_any_list_request`,
  `a_filter_on_an_endpoint_the_schema_does_not_know_is_refused`,
  `only_the_query_parameters_of_the_list_operation_are_filters`,
  `an_empty_filter_value_is_refused_before_any_list_request`
- `crates/netbox/src/testing.rs`: `an_empty_filter_value_filters_nothing_as_in_netbox`,
  `a_device_name_is_matched_whatever_its_case_on_every_site` (the fake behaves as NetBox)

**A field NetBox does not know is never written.** NetBox drops it and
answers the write as done: the same value would be written at every run. Each
field of a POST or a PATCH is checked against the body the OpenAPI schema
gives for the operation, and refused before anything is sent. A dry run checks
the fields of the writes it would make the same way (`Gateway::check_write`,
which every gateway that wraps another passes on), and sends none: the fields
it checks are those the writes send. A run reads the schema right after the
release of NetBox, before any source (`NetboxVersion::load_schema`), within
`SCHEMA_TIMEOUT` (300 s): NetBox builds it when asked, slowly once it has just
started (`cli.rs`: `a_netbox_that_cannot_give_its_schema_stops_the_run_before_any_source_is_read`).
- `crates/netbox/src/client.rs`: `the_schema_is_read_within_its_own_longer_timeout`,
  `a_field_netbox_does_not_take_is_refused_before_any_write`,
  `the_fields_of_a_write_are_checked_without_sending_it_even_in_a_dry_run`
- `crates/netbox/src/inventory_apply.rs`: `a_dry_run_checks_the_fields_of_every_write_and_sends_none`,
  `the_fields_a_dry_run_checks_are_those_the_writes_send`
- `crates/netbox/src/apply.rs`: `the_writes_a_dry_run_checks_are_those_the_applier_sends`
- `crates/cli/src/network.rs`: `diff_mode_checks_the_fields_of_the_writes_it_would_make`

**A NetBox release this build was not tested with is refused.** The release
is read in `/api/status/` (never the `API-Version` header, which a proxy may
drop) before any source is read; `netbox.unsupported_version = "warn"` runs it
anyway, with a warning. Everything that depends on the release of NetBox is in
`crates/netbox/src/version.rs` (`Dialect`, between its `VERSION SEAM` banners).
- `crates/netbox/src/version.rs`: `a_release_is_known_by_its_minor_whatever_its_patch_and_its_build`,
  `an_unsupported_release_is_refused_unless_the_configuration_says_to_warn`
- `crates/netbox/src/client.rs`: `the_release_of_netbox_is_read_from_its_status`
- `crates/cli/src/cli.rs`:
  `a_netbox_release_this_build_was_not_tested_with_is_refused_unless_told_to_warn`
- `crates/cli/tests/integration/version.rs`:
  `the_release_of_the_netbox_under_test_is_read_and_supported`

**A name NetBox holds twice is never resolved to one of them.** A device name is
unique per site only and read caselessly, a VRF or virtual chassis name is not
unique, nor a VLAN number without a group: several answers are an error, never
the first taken. A listing that changed while it was read is read again.
- `crates/netbox/src/state.rs`: `a_device_name_two_sites_hold_is_refused_naming_both`,
  `a_virtual_chassis_name_two_chassis_hold_is_refused_naming_both`
- `crates/netbox/src/apply.rs`: `a_vrf_name_two_vrfs_hold_is_an_error_naming_both`,
  `a_vlan_number_two_vlans_of_the_site_hold_is_an_error_naming_both`
- `crates/netbox/src/client.rs`: `a_listing_that_changed_while_it_was_read_is_read_again`,
  `a_listing_that_never_adds_up_fails`
- `crates/cli/src/config.rs`: `two_sources_cannot_share_an_ownership_tag`
- `crates/core/src/network/inventory.rs`: `a_name_that_differs_only_by_its_case_is_a_duplicate`,
  `two_names_that_read_the_same_variables_are_refused`
- `crates/core/src/network/cables.rs`: `a_neighbour_announced_in_another_case_keeps_its_cable`

**Writes are never retried.** A read answered by a gateway error is replayed;
a write never is (a POST answered 502 may have been applied).
- `crates/netbox/src/client.rs`: `a_write_is_never_retried`
- `crates/fortios/src/api.rs`: `login_is_never_replayed`

**No write in a dry run.** The client refuses every write before sending it,
and the appliers do not even attempt one.
- `crates/netbox/src/client.rs`: `a_dry_run_refuses_every_write_before_sending_anything`
- `crates/netbox/src/inventory_apply.rs`: `nothing_is_written_nor_attempted_in_dry_run`
- `crates/cli/src/cli.rs`: `a_dry_run_reports_the_changes_and_writes_nothing`,
  `the_real_client_of_a_dry_run_refuses_every_write`
- `crates/cli/src/network.rs`: `diff_mode_writes_nothing`

**Unknown is not empty.** A value the source did not report (`None`, a field
absent from `Desired`) is left as NetBox has it; only a reported empty value
clears. What could not be read (the interfaces of a stopped VM) is unknown.
- `crates/core/src/inventory/reconcile.rs`:
  `an_unreported_field_is_untouched_while_an_empty_one_clears`,
  `a_stopped_vm_keeps_its_interfaces_and_addresses`,
  `tags_the_source_could_not_read_are_left_as_they_are`
- `crates/core/src/network/diff.rs`: `unmanaged_description_is_not_compared`,
  `unreported_mtu_is_not_compared`, `parent_not_reported_is_left_as_netbox_has_it`,
  `unmanaged_ips_are_neither_pruned_nor_warned_about`

**A DNS name is only ever written by an answer.** An address without PTR
record, a lookup that fails or times out, an empty name, a name NetBox would
refuse: no `dns_name` is reported, never an empty one. A lookup never fails a
source, and the failures of a run are one warning, not one per address.
- `crates/core/src/inventory/dns.rs`: `refused_names_are_not_reported_and_told_in_one_warning`,
  `an_empty_name_is_not_reported_and_not_warned_about`,
  `an_address_that_is_never_looked_up_is_not_even_asked`
- `crates/vmware/tests/translation.rs`: `a_lookup_that_gives_no_name_never_clears_the_one_netbox_holds`
- `crates/proxmox/src/translate.rs`:
  `the_dns_name_comes_from_the_resolver_and_is_not_reported_when_the_lookup_fails`
- `crates/cli/src/hypervisors.rs`: `lookups_that_fail_clear_no_name_fail_no_source_and_give_one_warning`,
  `names_are_not_looked_up_unless_the_source_asks_for_it`
- `crates/cli/src/dns.rs`: `a_resolver_that_never_answers_costs_the_budget_and_one_warning`,
  `a_thousand_lookups_run_fifty_at_a_time_and_take_twenty_times_one`

**A failed or left-out source never has its objects orphaned.** Only a source
that ran to the end can say an object is gone.
- `crates/core/src/inventory/reconcile.rs`:
  `a_source_left_out_of_the_run_never_has_its_objects_orphaned`,
  `a_failed_source_keeps_its_orphans`,
  `what_a_source_that_did_not_succeed_reports_is_ignored`
- `crates/cli/src/hypervisors.rs`: `a_source_that_fails_keeps_what_netbox_holds_from_it`,
  `a_source_left_out_of_the_run_keeps_what_netbox_holds_from_it`
- `crates/cli/src/network.rs`: `a_device_whose_collection_fails_is_left_out_and_writes_nothing`

**Only what this tool tagged is ever deleted.** An object without the
`netbox-omnisync` tag was never adopted: it is nobody's orphan, whatever source
tag it carries.
- `crates/core/src/inventory/reconcile.rs`:
  `an_object_this_tool_never_tagged_is_never_its_orphan`

**An orphan something else still uses is not deleted.** A row this run leaves
as it is that refers to an orphan (NetBox would refuse the delete, PROTECT, or
clear the field, SET_NULL, or take it off a list, `tagged_vlans`) keeps it, as
a dependent NetBox would delete with it does; one this plan moves elsewhere
does not. An address NetBox assigns to
something else than an interface (an FHRP group) is held, never taken over.
- `crates/core/src/inventory/reconcile.rs`:
  `an_orphan_a_machine_nobody_reported_still_points_to_is_not_deleted`,
  `an_orphan_a_device_of_someone_else_still_uses_is_not_deleted`,
  `an_interface_whose_address_moves_to_another_one_is_deleted_in_the_same_run`,
  `an_address_netbox_assigns_to_an_fhrp_group_is_never_taken_over`

**A VLAN several sites share has no site, and its group is never created.**
A site of `[[vlan_groups]]` keeps its VLANs in a NetBox VLAN group: they are
declared, created and looked up in the group, at no site (NetBox refuses a
VLAN of a site on an interface of another one). The group is a prerequisite:
a source whose group NetBox lacks fails alone and writes nothing, and a VLAN
is never created without it. A name another VLAN of the group has is an error
naming both, before the write NetBox would refuse, and so is a VLAN of the
group that also has a site. A group is found whatever the case of its name.
A VLAN of a site nobody owns is told, never touched.
- `crates/cli/src/config.rs`:
  `a_site_in_two_vlan_groups_is_refused_naming_the_site_and_both_groups`,
  `a_vlan_group_names_the_sites_whose_vlans_it_holds_and_each_source_follows_its_site`
- `crates/proxmox/src/translate.rs`, `crates/vmware/src/translate.rs`:
  `the_vlans_of_a_site_that_is_in_a_vlan_group_are_declared_in_the_group_and_at_no_site`
- `crates/core/src/inventory/reconcile.rs`:
  `the_vlan_of_a_site_that_joined_a_group_goes_once_its_interfaces_point_to_the_one_of_the_group`,
  `the_vlan_of_a_site_an_interface_nobody_reported_still_uses_is_not_deleted`,
  `a_vlan_whose_group_is_not_in_netbox_is_an_error_and_is_not_created_without_it`,
  `a_vlan_whose_name_another_vlan_of_the_group_has_is_an_error_naming_both`,
  `a_vlan_of_a_site_nobody_owns_that_its_group_holds_too_is_a_warning_with_its_interfaces`,
  `a_vlan_of_the_group_that_also_has_a_site_is_an_error_naming_it_and_is_not_created_again`
- `crates/cli/src/hypervisors.rs`:
  `a_source_whose_vlan_group_netbox_does_not_hold_fails_alone_and_writes_nothing`,
  `a_leftover_vlan_of_a_site_no_hypervisor_is_at_is_told_from_the_table`
- `crates/netbox/src/state.rs`: `a_vlan_group_is_found_whatever_the_case_of_its_name`
- `crates/core/src/network/vlans.rs`:
  `a_missing_vlan_of_a_group_is_created_in_the_group_and_at_no_site`,
  `a_vlan_a_port_points_to_outside_its_group_is_read_as_one_to_rewrite`
- `crates/netbox/src/apply.rs`: `the_vlan_of_a_device_whose_site_is_in_a_group_is_the_one_of_the_group`
- `crates/cli/src/network.rs`:
  `a_site_that_joins_a_vlan_group_gets_its_vlans_in_the_group_and_its_ports_moved_to_them`,
  `a_source_whose_vlan_group_netbox_does_not_hold_is_an_error_and_writes_nothing`,
  `a_port_left_on_a_vlan_of_its_site_that_the_device_does_not_want_is_cleared`,
  `a_vlan_of_the_group_that_also_has_a_site_is_an_error_naming_it`

**No token or account travels through another host.** The proxy of the
environment is never used; NetBox in plain http only on the loopback; the
lock lives in a private state directory and is never opened through a link.
- `crates/{netbox,proxmox,vmware,redfish,fortios}/tests/proxy.rs`: `proxy_of_the_environment_is_not_used`
- `crates/netbox/src/client.rs`: `plain_http_is_only_taken_on_the_loopback`
- `crates/cli/src/cli.rs`: `the_lock_lives_in_a_private_directory_and_is_never_a_link`

**The host key of a switch is checked as OpenSSH checks it.** A hashed entry
(`|1|…`, the default of Debian) pins its host, a `@revoked` key is refused.
- `crates/ssh/src/known_hosts.rs`: `a_hashed_entry_pins_the_key_of_the_host_it_names`,
  `a_key_a_revoked_line_names_is_refused`

**An empty answer of a vCenter is not an inventory.** Without a session a
vCenter answers a read with nothing, as a success. The session is proven alive
after everything is read, and a vCenter without datacenter is refused.
- `crates/vmware/tests/collection.rs`: `a_session_lost_on_the_way_fails_the_collection`,
  `a_vcenter_without_datacenter_is_never_an_inventory`,
  `tags_that_cannot_be_read_fail_the_collection`

**A custom field NetBox does not define stops the run, before any write.**
NetBox refuses a write that carries it (`extras/api/customfields.py`): met at
that write, the run would stop half way through its plan.
- `crates/cli/src/hypervisors.rs`:
  `a_custom_field_netbox_does_not_define_stops_the_run_before_any_write`

**Only the custom fields the tool manages are sent.** From NetBox 4.7 a
selection custom field is read as `{"value", "label"}`, which NetBox refuses
on write: sending back what was read would have every write of the object
refused.
- `crates/core/src/inventory/reconcile.rs`: `custom_fields_are_merged_on_the_managed_keys_only`
- `crates/cli/tests/integration/hypervisors.rs`:
  `a_selection_custom_field_of_someone_else_survives_a_write_of_the_managed_ones`

**Adoption changes only tags.** The first run on a NetBox the old tools filled
replaces their tags and writes nothing else; a second run writes nothing.
- `crates/core/src/inventory/reconcile.rs`: `adoption_changes_only_tags`,
  `every_tag_of_the_old_tools_is_removed_on_adoption`,
  `a_second_run_after_adoption_changes_nothing`
- `crates/netbox/src/inventory_apply.rs`: `adoption_sends_the_tags_and_nothing_else`,
  `adopting_what_the_old_tools_left_changes_tags_only_and_once`

**A renamed host or machine is recognised, never guessed, never stolen.** A
device or virtual machine reported under a name NetBox does not know is the
NetBox object that shares its MAC addresses, and is renamed in place with
everything under it. Only an object no reported one has by name, held by a
tool for that very source (every source it is held for having run to the end:
one read in part, `SourceStatus::Partial`, has not), and for a machine in the
same cluster, can be it; one candidate, or a best one with at least twice the
matches of the second, else a warning and nothing. A report that only
completes (`Desired::complement`, a BMC) is never looked for this way, never
keeps the device it names from being renamed by its owner, and is skipped
with a warning rather than written on a device renamed in the same plan.
- `crates/core/src/inventory/reconcile.rs`:
  `a_renamed_virtual_machine_is_recognised_by_its_mac_address_and_renamed_in_place`,
  `a_renamed_device_is_recognised_by_the_mac_address_of_an_interface_and_renamed_in_place`,
  `candidates_that_match_alike_are_not_guessed_between`,
  `a_best_candidate_short_of_twice_the_matches_of_the_second_is_not_taken`,
  `the_best_candidate_is_taken_when_it_has_twice_the_matches_of_the_second`,
  `an_address_every_machine_has_designates_none`,
  `an_object_another_reported_one_matched_by_name_is_never_a_candidate`,
  `two_reported_objects_never_end_on_the_same_netbox_object`,
  `an_object_reported_without_a_mac_address_is_not_looked_for`,
  `an_object_that_shares_no_mac_address_is_never_a_candidate`,
  `an_object_of_another_source_is_never_a_candidate`,
  `an_object_no_tool_holds_for_the_source_is_never_a_candidate`,
  `an_object_also_held_for_a_source_that_did_not_succeed_is_never_a_candidate`,
  `an_object_also_held_for_a_source_read_in_part_is_never_a_candidate`,
  `a_source_read_in_part_renames_nothing_it_reports_under_a_new_name`,
  `a_completing_source_read_in_part_does_not_keep_a_device_from_being_recognised`,
  `a_report_that_only_completes_is_never_looked_for_by_its_mac_addresses`,
  `a_completing_report_under_the_old_name_does_not_keep_a_renamed_device_from_being_recognised`,
  `a_renamed_device_is_completed_under_its_new_name_in_the_write_that_renames_it`,
  `a_virtual_machine_of_another_cluster_is_never_a_candidate`,
  `a_device_and_a_virtual_machine_are_never_taken_for_one_another`
- `crates/netbox/src/inventory_apply.rs`:
  `a_virtual_machine_renamed_in_its_source_is_renamed_in_place_with_everything_under_it`,
  `a_host_renamed_in_its_source_is_renamed_in_place_with_everything_under_it`
- `crates/cli/src/hypervisors.rs`:
  `a_host_renamed_in_its_hypervisor_is_renamed_in_place_and_its_bmc_follows_once_it_names_it_so`,
  `a_bmc_told_the_new_name_of_a_host_waits_for_the_run_that_renames_it`

**The file says which host launches each source, all of them or none.** A
file without `runners` nor `runner` is run by one host, and asks the system
for no name. With the list, every source names a host of it and every host
launches one, or the load is refused; a run is the one of its host (its full
name, `host::full_name`, compared as written), selects among its sources
alone, and is refused before anything is contacted on a host the list does
not have. `--runner` names another host for a dry run only: a journal only
ever names its machine. The sources of the other hosts stay known, left out.
- `crates/cli/src/config.rs`: `a_source_names_the_host_that_runs_it`,
  `a_file_without_runner_is_run_by_one_host`,
  `a_runner_on_some_sources_only_is_refused_naming_the_others`,
  `a_runner_that_is_not_in_the_list_is_refused`, `a_runner_without_a_list_is_refused`,
  `a_host_of_the_list_that_runs_no_source_is_refused`, `a_host_listed_twice_or_empty_is_refused`
- `crates/cli/src/select.rs`: `without_runners_every_source_is_a_candidate_of_the_run`,
  `no_filter_selects_the_sources_of_the_host`, `a_filter_narrows_among_the_sources_of_the_host`,
  `a_source_of_another_host_is_an_error_naming_that_host`,
  `a_host_that_is_not_in_the_list_is_an_error_naming_the_runners`,
  `a_filter_no_source_of_the_host_passes_names_the_host`,
  `the_candidates_carry_the_host_the_file_gives_them`
- `crates/cli/src/cli.rs`: `a_run_launches_the_sources_of_its_host_alone`,
  `a_run_on_a_host_that_is_no_runner_is_refused_before_anything_is_contacted`,
  `a_run_on_a_host_without_a_full_name_is_refused`, `the_short_name_of_a_runner_is_not_its_name`,
  `the_runner_option_replaces_the_name_of_the_host`,
  `the_runner_option_is_refused_without_a_list_of_runners`,
  `the_runner_option_is_only_taken_by_a_dry_run`,
  `a_file_without_runners_never_asks_for_the_name_of_the_host`,
  `a_run_needs_the_secrets_of_the_sources_of_its_host_alone`

**A run needs the secrets of the sources it selected, and no other.** The
same file is loaded on every host, each launching its own sources and holding
only their secrets (and `NETBOX_TOKEN`, which every run needs). The load
checks every entry in full and never fails on a secret: a secret the
environment lacks is a `Wanted::Missing` naming its variables, never an empty
value, and `Config::require` refuses the run for the selected sources only,
all their variables at once, before anything is contacted. A source left out
stays known to the run: its `source-*` tag is not a leftover. A reader handed
a source without its secret fails naming the variable, and sends nothing.
- `crates/cli/src/cli.rs`:
  `a_run_needs_the_secrets_of_the_sources_it_selected_and_no_other`,
  `the_password_shared_by_the_switches_is_only_needed_by_a_run_that_selects_one`,
  `a_selected_source_without_its_secret_stops_the_run_before_anything_is_contacted`,
  `a_run_without_filter_needs_every_secret`,
  `the_netbox_token_is_needed_whatever_the_selection`,
  `an_invalid_entry_is_refused_even_when_its_source_is_left_out`,
  `a_hypervisor_left_out_of_a_run_keeps_its_tag_on_what_it_shares_without_its_secrets`,
  `the_real_client_is_never_built_without_the_token`
- `crates/cli/src/config.rs`:
  `a_run_is_only_refused_for_the_secrets_of_the_sources_it_selects`,
  `an_invalid_entry_is_refused_whatever_the_environment_holds`,
  `a_source_without_its_account_holds_none_and_says_which_variables_would_give_it`
- `crates/core/src/network/inventory.rs`:
  `a_run_misses_the_token_and_the_secrets_of_the_sources_it_selects_only`,
  `the_shared_password_is_missing_for_the_switches_that_need_it_only`,
  `a_firewall_with_half_its_account_cannot_be_read_and_names_the_other_half`,
  `an_entry_is_checked_in_full_without_any_secret`
- `crates/cisco/src/transport.rs`:
  `a_source_whose_password_the_environment_does_not_hold_is_never_contacted_and_names_its_variable`
- `crates/fortios/src/api.rs`:
  `a_source_whose_account_the_environment_does_not_hold_has_no_client_and_names_its_variables`
- `crates/cli/src/hypervisors.rs`:
  `a_source_whose_account_the_environment_does_not_hold_is_never_contacted_and_names_its_variables`

**Every sync that contacted NetBox is journaled, and nothing else is.** One
line per run past the secrets, a refusal of NetBox included; none for a dry
run nor for a run refused before (configuration, selection, secrets, lock). A
journal that cannot be written fails the run; a rewrite never leaves half a
file, nor drops a line it does not understand. The host of a run and of each
source (`runner`) are optional keys of version 1: a file one host runs writes
its lines byte for byte as before, and the lines written before are read.
- `crates/cli/src/cli.rs`: `a_run_appends_one_entry_to_the_journal`,
  `a_dry_run_writes_nothing_in_the_journal`,
  `a_run_refused_before_netbox_is_contacted_writes_nothing_in_the_journal`,
  `a_run_netbox_refuses_is_journaled_as_failed`,
  `a_journal_that_cannot_be_written_fails_the_run_naming_it`
- `crates/cli/src/journal.rs`: `a_journal_that_cannot_be_rewritten_is_left_as_it_was`,
  `a_line_that_does_not_parse_is_kept_and_skipped_by_the_readers`,
  `a_line_that_is_not_utf8_is_kept_byte_for_byte_and_skipped_by_the_readers`,
  `a_temporary_file_a_killed_run_left_does_not_stop_the_next_one`,
  `the_temporary_file_is_never_written_through_a_link`,
  `an_entry_is_one_json_line_of_the_schema_of_version_1`,
  `an_entry_names_its_runner_and_the_runner_of_each_source`,
  `an_entry_without_runner_is_written_as_before`,
  `a_line_written_before_the_runners_is_still_read`
- `crates/cli/src/cli.rs`:
  `a_run_of_a_file_several_hosts_share_journals_its_host_and_the_one_of_each_source`

**The check never says OK over a gap.** A source the configuration has and no
run succeeded for is CRITICAL (of a file several hosts share, a source of the
host of the journal: the others are judged from the journal of their own
host, and the check still reads the journal alone); a kind without `--max-age` is UNKNOWN; a usage
error of `check` is UNKNOWN on stdout (exit 3), never the 1 Icinga reads as a
WARNING. An error of a source starts with its name: the one of a member of a
stack or of a cluster peer names the source, then the device. A warning of the
last run of a source is a WARNING until a run no longer says it, never over a
worse state, and unless `--ignore-warning` matches it.
- `crates/cli/src/check.rs`: `a_configured_source_no_run_selected_is_critical`,
  `a_source_whose_kind_has_no_max_age_is_unknown`,
  `an_error_fails_the_source_it_names_or_every_selected_one`,
  `the_error_of_a_member_of_a_stack_fails_its_source_alone`,
  `the_warnings_of_the_last_run_of_a_source_make_the_check_a_warning`,
  `a_warning_ends_with_the_first_run_that_no_longer_says_it`,
  `a_warning_of_a_source_read_once_a_night_lasts_until_its_next_run`,
  `the_warnings_come_after_the_sources_that_are_not_ok`,
  `a_warning_said_for_several_sources_is_listed_once`,
  `a_warning_cannot_break_the_output`,
  `a_warning_the_operator_ignores_does_not_change_the_state`,
  `a_warning_that_names_its_source_ends_with_the_next_run_of_that_source`,
  `a_warning_that_names_no_source_stands_for_every_source_of_its_run`,
  `a_source_of_another_host_is_not_judged`,
  `a_source_of_the_host_no_run_selected_is_critical`,
  `a_kind_only_another_host_runs_needs_no_max_age`,
  `the_warnings_of_the_sources_of_another_host_do_not_stand`,
  `a_journal_without_runner_judges_every_source`,
  `a_run_of_a_host_never_says_ok_over_a_source_nobody_is_said_to_launch`
- `crates/cli/src/network.rs`:
  `the_error_of_a_device_that_is_not_its_source_names_the_source_then_the_device`,
  `a_warning_is_given_the_source_of_the_device_it_starts_with`
- `crates/core/src/inventory/reconcile.rs`: `a_warning_names_the_source_it_is_about`
- `crates/cli/src/cli.rs`: `a_usage_error_of_the_check_is_unknown_on_stdout`

**The digest is never markup of a source.** Every name, key, value and error
is escaped for HTML; the digest needs no secret. A run is in the digest of the
period it ended in.
- `crates/cli/src/digest.rs`: `every_text_of_a_source_is_escaped`,
  `a_run_belongs_to_the_period_it_ended_in`
- `crates/cli/src/cli.rs`: `without_an_address_the_digest_prints_its_message`

**Ownership tags are matched by slug.** `netbox-omnisync` and `source-<slug>`
are known by their slug and attached under whatever name NetBox holds for it
(the old tools named theirs `Source: <name>`).
- `crates/core/src/inventory/reconcile.rs`:
  `the_tag_of_a_source_is_attached_under_the_name_netbox_holds_for_its_slug`,
  `an_ownership_tag_netbox_holds_under_another_name_is_not_asked_for_again`
- `crates/cli/src/hypervisors.rs`: `the_tag_of_a_source_is_the_one_the_old_tools_gave_it`

## Rules about tests

No test can guard these; reviews do.

- **Expected values are written by hand from the raw fixture**, or from the
  requirement, never copied from what the code returns. The line read in the
  fixture is quoted above the assertion (see the header and the body of
  `crates/proxmox/tests/collection.rs`).
- **A defect of a reference tool is fixed, not ported.** Write the test on the
  correct behaviour, see it fail on the ported behaviour, fix, then add a row
  to `docs/reference-defects.md` naming the test.
- **Fixtures are anonymised observed outputs**: recorded from real equipment,
  then identifying values replaced, structure untouched. Never write a
  fixture by hand to fit the parser. Where they live and how to add one:
  `CONTRIBUTING.md`.

## Conventions

- Errors are typed (`thiserror`) and carry their own message; an error line is
  the name of what failed followed by that message. A warning about one source
  starts with its name and `: `, as an error does (the check takes it back at
  the next run of that source alone); one about the run names no source. No secret in a message:
  the tests named `…never_shows_the_token`, `no_secret_is_ever_printed` check it.
- A secret of a source is read from the environment as a `Wanted<T>`
  (`crates/core/src/network/inventory.rs`) and reached through `held()` only:
  a new source type declares the variables it misses there, and never fails
  the load for them.
- A new key of a hypervisor entry is added to `HYPERVISOR_KEYS`
  (`crates/cli/src/config.rs`), one of a `bmc` entry to `BMC_KEYS`: unknown
  keys are refused. A key every entry takes whatever its kind (`runner`) is in
  both and in `ENTRY_KEYS` of the network loader, and read in one place. A `bmc` entry takes no DNS key (a BMC reports no address,
  `a_bmc_entry_takes_no_reverse_dns_lookup`), and its reader no resolver.
- The names NetBox has for a vendor and the slugs of what is created for a
  server are shared (`crates/core/src/inventory/hardware.rs`): two sources
  that describe the same hardware must name it alike.
- Output is deterministic: `BTreeMap`/`BTreeSet`, sorted steps, outcomes taken
  in configuration order whatever finishes first.
- Comments say why, above the code; lines are 120 columns (`rustfmt.toml`).

## Release

`.github/workflows/release.yml` runs on a pushed tag `vX.Y.Z`, which must be
an annotated tag matching the version of `Cargo.toml`, signed with a key of
`.github/release-signers`, on the commit the job checked out
(`scripts/release-check-tag.sh`). It never creates the tag. The binaries are
built by `scripts/release-build.sh`, the same script the `release-build` job
of CI runs on every push through `.github/workflows/build.yml`.
