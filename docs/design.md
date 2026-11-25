# Design

How netbox-omnisync decides what an object is, whose it is, what to write and
what to delete. The code is the reference; each section names the file that
holds the rule, and the tests named here pin it.

Two families share the NetBox client and the report, and nothing else:

- **Inventory** (hypervisors, and the BMCs of servers): a source reports the
  objects it wants; a pure reconciliation compares them with NetBox and plans
  the writes. Objects are marked with ownership tags.
- **Network** (switches, routers, firewalls): the device already exists in
  NetBox; a run completes it with what the device reports. No tag is used.

Related documents: [reference-defects.md](reference-defects.md) lists the
behaviours of the replaced tools that were fixed rather than ported, and
[vmware-reference.md](vmware-reference.md) is the inventory of netbox-sync
the VMware source was written from. Neither is repeated here.

## Inventory family

### Identity

A source does not know NetBox ids, and an object created in a run has none
yet: both sides name an object by its identity. The source builds it from what
the hypervisor says (`Identity` constructors, `crates/core/src/inventory/model.rs`);
`crates/core/src/inventory/identity.rs` builds the same one from a NetBox row.
Two objects are the same when their keys are equal.

| Kind | NetBox endpoint | Identity | Letter case |
|---|---|---|---|
| Tag | `extras.tags` | name | ignored |
| Tenant | `tenancy.tenants` | name | ignored |
| Site | `dcim.sites` | name | ignored |
| Manufacturer | `dcim.manufacturers` | name | ignored |
| Device type | `dcim.device_types` | manufacturer name, model | ignored |
| Platform | `dcim.platforms` | name | ignored |
| Role | `dcim.device_roles` | name | ignored |
| Cluster type | `virtualization.cluster_types` | name | ignored |
| Cluster group | `virtualization.cluster_groups` | name | ignored |
| Cluster | `virtualization.clusters` | name | ignored |
| VRF | `ipam.vrfs` | name | ignored |
| VLAN group | `ipam.vlan_groups` | name | ignored |
| VLAN | `ipam.vlans` | site name, else group name, else nothing; VLAN id | ignored on the site or group |
| Prefix | `ipam.prefixes` | prefix, VRF | ignored |
| Device | `dcim.devices` | name | ignored |
| Virtual machine | `virtualization.virtual_machines` | name, cluster name (empty without a cluster) | ignored |
| Interface | `dcim.interfaces` | device name, interface name | ignored |
| VM interface | `virtualization.interfaces` | identity of the virtual machine, interface name | kept on the interface name |
| Virtual disk | `virtualization.virtual_disks` | identity of the virtual machine, disk name | kept on the disk name |
| MAC address | `dcim.mac_addresses` | address in upper case, and the interface it is assigned to (kind and identity), or nothing when unassigned | — |
| IP address | `ipam.ip_addresses` | host part in canonical form, VRF | — |

Notes:

- Names, never slugs: the replaced tools did not build slugs alike. The one
  exception is the ownership tags, see below.
- The mask of an IP address is a field, not part of its identity: a mask
  corrected on the host updates the address instead of creating a second one.
- The VRF part is the VRF name in lower case, empty for the global table, or
  "any" when the source cannot tell: the object is then looked up in every
  table, and the VRF NetBox holds is kept.
- A VLAN that has both a site and a group is identified by its site.
- A source declares its VLANs at its site, or in the VLAN group
  `[[vlan_groups]]` puts that site in (`VlanGroups::scope_of`): the same VLAN
  number is then one object for every site of the group. Such a VLAN is
  declared with a `group` reference and **no** `site`: NetBox refuses a VLAN
  of a site on an interface of another one. The group itself is only referred
  to, never declared, so never created ("VLAN groups" below).
- The same IP address may be reported by two machines (a virtual address,
  `172.17.0.1` on every Docker host): the reconciliation keeps one object per
  holder. An address NetBox assigns to another device or virtual machine is
  never taken from it.
- A row that cannot be identified (no name, a parent that was not read) is
  left out with a warning: it is neither updated nor deleted.
- When several NetBox objects have the identity of a reported one, the one a
  tool owns is chosen; if that does not settle it, the object is skipped with
  its dependents and a warning, never guessed.

The kinds are declared in dependency order (`Kind::ALL`): an object only
refers to objects of an earlier kind, except the late references written in a
second step (primary IP, primary MAC, LAG, parent interface).

### A renamed device or virtual machine

The name is the identity: a host or a machine renamed in its source would be a
new object, and the one NetBox has an orphan, deleted with its interfaces, its
addresses and whatever was documented on it. So a device or a virtual machine
reported under a name NetBox does not know is first looked for by the MAC
addresses of its interfaces (`Reconciler::recognise`), the rule of netbox-sync
(`vmware-reference.md`, 11.2 and 12.3) within stricter bounds.

The candidates are the NetBox objects of the same kind for which all of this
holds:

1. no reported object has it by its identity, in this run;
2. it carries `netbox-omnisync` or a tag of a replaced tool (`LEGACY_TAGS`),
   **and** the `source-<slug>` tag of a source that reports the object: a
   machine made by hand, or another source's, is never renamed;
3. every configured source whose tag it carries ran to the end: one that
   failed, was left out or was read in part (`SourceStatus::Partial`, below)
   may still know it under the name it has;
4. for a virtual machine, it is in the cluster the machine is reported in;
5. its interfaces hold, as MAC address objects (`dcim.mac_addresses`), at
   least one of the MAC addresses reported for the interfaces of the object.

Each candidate counts for the number of reported addresses it holds. A single
candidate is the object. Between several, the best one is taken only when it
has at least twice the matches of the second: a generated address is shared by
every clone of a template, and `00:00:00:00:00:00` by anything. Otherwise
nothing is guessed: a warning names the object and the candidates, and the
object is handled as one NetBox does not have. A NetBox object that two
reported objects would each be is taken for neither, with a warning for each.
An object reported without any MAC address (a stopped machine whose interfaces
could not be read, a Proxmox node) is not looked for.

The object recognised is the reported one: it is updated in place, so the
report shows an update of `name` with the old one before. What is reported
under the new name (interfaces, virtual disks, MAC addresses, and through
their interface the IP addresses) is looked up under the name NetBox still
holds (`Reconciler::held_key`), and so matched rather than created anew. It is
in NetBox: `create_devices = false` does not keep a device from being renamed.
The next run finds it by its name.

A virtual machine moved to another cluster is not recognised: the cluster is
part of its identity, and the candidates are those of its cluster. The other
fallbacks of netbox-sync (serial, asset tag, primary IP) are not done.

A report that only completes an object (a `complement`, "Completing an object"
below) has no part in this, on either side:

- what only completing reports name is never looked for by its MAC addresses:
  nobody owns it, so there is nothing to rename
  (`a_report_that_only_completes_is_never_looked_for_by_its_mac_addresses`);
- the object such a report names is not "had by its identity" in the sense of
  rule 1: a `bmc` entry that still gives the old name of a host does not keep
  its hypervisor from renaming it. The device is renamed in place, and what
  the BMC says of it is skipped for that run with a warning (`device esx01:
  renamed esx02 by this run, and bmc.lab01 only completes it under the name it
  had; skipped`): one object is never written under two names in one plan
  (`a_completing_report_under_the_old_name_does_not_keep_a_renamed_device_from_being_recognised`);
- a completing report that already gives the new name is merged with its
  owner's before anything is recognised: the rename and the completed fields
  are one update
  (`a_renamed_device_is_completed_under_its_new_name_in_the_write_that_renames_it`).
  From the command line this last case waits one run, because the proof a BMC
  owes is checked against NetBox as it is before the run ("The proof a BMC
  owes").

### What a source reports

A `Desired` object carries only what the source knows
(`crates/core/src/inventory/model.rs`):

- A field, reference, custom field or tag set that is **absent** is left as
  NetBox has it. An **empty** value (`""`, `null`, no reference, an empty tag
  set) is a value and clears.
- `create_only` fields (a slug, a colour) are written at creation and never
  patched afterwards.
- `only_when_empty` fields and references are written only when NetBox holds
  nothing there: a primary IP or a device type chosen by hand survives.
- `ensure_only` objects (a site, a tenant) only have to exist: one found in
  NetBox that no tool owns is used as it is, neither tagged nor updated.
- `unknown_dependents` lists the kinds the source could not read this time
  (the interfaces and addresses of a stopped virtual machine): the ones NetBox
  holds are kept.
- A `complement` only completes an object its source does not own (the device
  a BMC knows the model and the serial of): it is never created, never tagged,
  never an orphan (see "Completing an object" below).
- Only the custom fields the tool manages are compared; `tags` from the source
  are managed, any other tag on the object is left alone.

A value NetBox renders differently is not a difference: a choice equals its
value, `2` equals `2.0` and `"2.00"`, `null` equals an empty text or list, and
the identifying name is compared without case (`same_value`,
`Kind::caseless_field`).

### The VLANs of a Proxmox source

Proxmox names no VLAN: it only tags frames. Two places say which VLAN an
interface is in (`crates/proxmox/src/collect.rs`, `translate.rs`):

- **A guest.** Each network card of its configuration is a `netN` line
  (`virtio=<MAC>,bridge=vmbr0,tag=10` for a virtual machine,
  `name=eth0,…,hwaddr=<MAC>,tag=10` for a container). `tag` makes an access
  port of that VLAN; `trunks` (`10;20-22`) a tagged port of those VLANs, its
  `tag` being then the untagged one (a trunk without `tag` has none, and the
  one NetBox has is cleared); `trunks` over every VLAN a `tagged-all` port
  without list. A port that is not tagged is written with an empty list of
  tagged VLANs: NetBox refuses an access or tagged-all port that keeps those
  of the trunk it was. A trunk of more than 64 VLANs (`trunks=2-4000`) is a
  warning, and its interfaces keep what NetBox has: listing it would create a
  VLAN per id. A card with neither `tag` nor `trunks` says nothing: its
  interface keeps what NetBox has, a VLAN set by hand on a bridge that is not
  VLAN-aware included. The other side of that choice: a `tag` removed from a
  card leaves the VLAN it had in NetBox. The interfaces themselves come from the agent of the
  guest: the card is matched to **every** interface that has its MAC address
  (a bond inside the guest and its members share it). A line that cannot be
  read is a warning naming the guest and its key, never "no VLAN". The
  configuration of a container is only read when it runs, and its failure
  leaves its VLANs unknown; the one of a virtual machine was already read, for
  its disks.
- **A node.** An entry of type `vlan` in `/nodes/{node}/network` (`bond2.25`)
  is an access port of its `vlan-id`, and a child of its `vlan-raw-device`
  when that interface is synced. The `bridge-vids` of a bridge are not read.

The VLAN is declared at the site of the cluster, or in the VLAN group of that
site, `ensure_only`: one NetBox holds is used as it is, name included, and
one it lacks is created as `VLAN<id>`. The syntax of `trunks` and of the `netN` line of a container was
read in `man qm` and `man pct`: no real example was ever observed.

### DNS names

A translation is pure and a reverse DNS lookup is not, so the lookup is handed
to the translation as a `ReverseDns` (`crates/core/src/inventory/dns.rs`).
For a source that sets `dns_name_lookup`, the run translates twice
(`crates/cli/src/hypervisors.rs`, `looked_up`): once with a resolver that only
notes the addresses it is asked, then, those being looked up
(`crates/cli/src/dns.rs`, `ReverseLookups`), with the table of the answers.
The addresses looked up are therefore exactly the ones reported, after the
subnet and interface filters.

`Names` holds what both hypervisor translations share: a link-local, loopback
or unspecified address is not asked; the name loses its final dot and its
upper case; a name NetBox would refuse is not reported. An address without
answer reports no `dns_name` at all, which is "unknown" and not "empty":
NetBox keeps the name it has.

`ReverseLookups` serves the whole run: one cell per address and list of
resolvers (asked once, whoever reports it), a semaphore of fifty lookups in
flight shared by the sources, three seconds a lookup and fifteen for the
lookups of one source. Failures are counted, never returned: they are one
warning of the run, under no source.

### Ownership

`crates/core/src/inventory/reconcile.rs`. Every managed object carries:

- `netbox-omnisync`, the tag of the tool;
- `source-<slug>` for each source that reports it, the slug being the source
  name in lower case, spaces turned into hyphens, everything but `a-z`, `0-9`,
  `_` and `-` removed (`hypervisors::source_tag`).

The tags are created when NetBox has none of that **slug**, and attached under
whatever name NetBox holds for the slug. A tag object has no tag itself.

An object found by its identity is taken over whether or not a tool had marked
it. **Adoption** is what happens to one the replaced tools had marked: their
tags (`LEGACY_TAGS`: `netbox-synced`, `netbox-synced-orphaned`, `netbox-ssot`,
`netbox-ssot-orphan`, `type-proxmox`, `proxmox-netbox-sync`, and any
`source-*` tag that is not the tag of a configured source) are removed and the
two tags above are set. On a NetBox those tools filled, the first run changes
tags and nothing else, and the second run changes nothing
(`adoption_changes_only_tags`, `a_second_run_after_adoption_changes_nothing`).

The tags a source puts on a machine (vSphere tags, Proxmox tags) are told from
the tags set by hand in NetBox by the description of the tag: it is
`netbox-omnisync` (`TAG_MARKER`) alone, or followed by `: ` and a text — the
description vSphere gives the tag, or any wording written in NetBox afterwards.
Text that merely starts like the marker does not count
(`the_marker_is_the_whole_description_or_followed_by_a_colon`).

The marker is global, not tied to a source: a marked tag leaves a virtual
machine once the source that reports that machine, with its list of tags, no
longer lists it — a tag Proxmox made, set by hand on a vSphere machine, leaves
it too. An object whose source reports no list of tags (hosts, Proxmox nodes,
BMC devices) keeps all its tags. Any tag without the marker is never removed.

The marker is written to a tag the tool creates, never to one NetBox already
has: a tag created before (by netbox-ssot, which marked none, or by hand) gets
it by editing its description in NetBox. `NetBox-synced`, the marker of
netbox-sync, is still recognised (`LEGACY_TAG_MARKERS`), never written
(`a_tag_netbox_sync_made_leaves_a_machine_once_vsphere_no_longer_tags_it`).

When two sources report the same object differently, the first one in
`netbox.source_priority` wins and a warning names both; a source left out of
the list comes last. A report that only wants the object to exist
(`ensure_only`) says nothing of its fields: it never disagrees with another,
and the first report that describes the object wins whatever its priority
(`a_report_that_only_wants_an_object_to_exist_never_keeps_another_from_describing_it`).

The priority holds between runs as well. Two sources that report the same
object do not always run together: each host of `runners` launches its own,
and so does a cron per `--kind` or per `--source`. A source left out of a run
(`SourceStatus::Skipped`) has no report in it, but the tag it left on an
object says it reported that object at its last run: a source that stops
reporting a shared object takes its tag back. So an object NetBox holds that
carries the tag of a source left out of the run, ranked before the winner of
the reports of the run (`Reconciler::held_by_a_better_source`, the order of
`Reconciler::wins`), is left as NetBox has it: the run only adds its own
ownership tag, which is all a run of both sources would have written for the
loser. Its fields, references, lists and custom fields are neither compared
nor written, what it points to is still in use, and the tags that came from
the tags of a source stay. Without this, each of the two would write its
values over the other's at every run.

- The better source runs: it wins, as in a run of both, and keeps the tag of
  the other.
- The better source no longer reports the object: its own run takes its tag
  back, and the next run of the other writes its values, once. Its tag only
  goes when that source prunes and nothing keeps the orphan (an object still
  pointed to, a network that still holds addresses, what the source could not
  read): until then the object stays as the better source left it.
- The object is not in NetBox yet: the first source that runs creates it, the
  better one rewrites it once at its own run, then nothing more.
- A better source that failed or was read in part is in the run, not left
  out: nothing changes for it.
- A report another source completes in the run (a BMC) is written as before:
  what completes it is not the loser's to drop.
- The tag does not tell whether the source left out described the object or
  only wanted it to exist (`ensure_only`): it holds it either way.

There is no warning: the one of a run of both compares two reports, and only
one is in this run; a warning at every run would keep `check` in WARNING over
a state that is wanted
(`an_object_a_better_source_left_out_of_the_run_holds_is_left_as_netbox_has_it`,
`two_sources_run_apart_never_write_an_object_back_and_forth`,
`an_object_a_worse_source_left_out_holds_is_written_by_the_better_one`,
`an_object_the_better_source_no_longer_holds_is_written_by_the_one_that_runs`,
`a_reference_of_an_object_left_to_a_better_source_is_still_in_use`,
`what_completes_an_object_a_better_source_left_out_holds_is_still_written`,
and `two_hosts_that_report_the_same_object_never_write_it_back_and_forth` in
`crates/cli/src/cli.rs`).

### Completing an object

A hypervisor does not always know the hardware it runs on; the BMC of the
server does, and knows nothing else. Its source (`crates/redfish`, kind `bmc`)
reports the device as a `complement`: a report that owns nothing
(`Reconciler::complete`, `crates/core/src/inventory/reconcile.rs`).

- The reports that own the object are settled first, as a whole, as above.
  Each completing report is then added to the winner **field by field**:
  - a field the owner does not report is taken;
  - a field the owner only writes when NetBox has none (`only_when_empty`: the
    generic device type of a Proxmox node) is taken, **whatever the
    priority**: a source that knows beats a fallback;
  - a field both give with the same value is no difference;
  - a field both give differently goes to the first of `source_priority`
    (then the first by name), and the warning names the field and both
    sources: `device esx01: serial reported differently by vc01 and bmc.lab01;
    vc01 wins (source priority)`.
- An object only completing reports describe is updated where it exists, and
  nothing more: it is not created (a warning says so), it gets no ownership
  tag, and so it can never be an orphan of that source.

This is what keeps two sources from writing a field back and forth: the
hypervisor that runs alone five minutes later finds its fallback already
filled and its other fields untouched, and the BMC that runs alone the next
day finds what it wrote. Tests:
`what_a_bmc_knows_wins_over_the_fallback_of_a_hypervisor_whatever_the_priority`,
`a_device_a_bmc_completed_is_stable_whoever_reports_it_next`,
`two_sources_that_know_a_field_differently_never_write_it_back_and_forth`
(reconciliation), and
`a_proxmox_and_its_bmcs_settle_on_the_hardware_of_the_bmc_without_source_priority`,
`…_whichever_source_is_ranked_first` (`crates/cli/src/cli.rs`, a Proxmox VE and
two BMCs served from their fixtures).

A vCenter knows the hardware of its hosts as well, and the reconciliation
keeps no memory of a run: left as it is, a vCenter read every five minutes and
a BMC read once a day that differ on a serial would each write theirs in turn.
The run therefore turns the device type and the serial a hypervisor reports
into fallbacks for every device a `bmc` entry of the configuration lists,
whether that entry is part of the run or not (`crates/cli/src/hypervisors.rs`,
`the_hardware_of_a_device_a_bmc_documents_is_the_bmc_s_to_tell`;
`crates/cli/src/cli.rs`,
`a_vcenter_and_a_bmc_that_differ_on_a_serial_leave_the_one_of_the_bmc`).

What stays uncovered: two hypervisor sources that both know a field of one
object, differ on it, and run apart, each write theirs in turn.

### The proof a BMC owes

Nothing ties the address of a BMC to a NetBox device but a line of
configuration. What a BMC says is therefore `Guarded`
(`crates/core/src/inventory/guard.rs`): it is handed to the reconciliation only
when one of the MAC addresses the BMC reports for its server (the address in
use of each Ethernet interface, never the permanent one) is on an interface of
that device in NetBox. Left out, with a warning and with everything the BMC
reports, its device type included:

- a device that is not in NetBox (it is never created from its BMC);
- a name several devices have;
- a BMC that reports no MAC address;
- a device NetBox holds no MAC address for yet: nothing can be checked, so
  nothing is written until a source has written its interfaces;
- a device none of whose addresses the BMC knows: the BMC of another server.

A BMC does not list every card of its server: the addresses are enough to
recognise it, and are never written.

The proof is checked against what NetBox holds before the run writes anything.
A `bmc` entry that names a host by the name its hypervisor gives it from this
very run on (a rename, "A renamed device or virtual machine") therefore finds
no device of that name and is left out, with the first warning above; the run
renames the device, and the next one completes it
(`a_bmc_told_the_new_name_of_a_host_waits_for_the_run_that_renames_it`,
`a_host_renamed_in_its_hypervisor_is_renamed_in_place_and_its_bmc_follows_once_it_names_it_so`
in `crates/cli/src/hypervisors.rs`).

A BMC reports no IP address: a `bmc` entry takes neither `dns_name_lookup`
nor `dns_servers` (both are unknown keys there), and its reader is given no
resolver.

### A source read in part

One `bmc` source reads many BMCs, and the unit of failure is the BMC. When
some cannot be read, the source is `SourceStatus::Partial`: what it reports
is written, and what it does not report says nothing — its tags stay on what
it shares with other sources, and it has no orphan. Each unread BMC is an
error of the run (exit 1). A `bmc` source never prunes and never creates a
device, whatever its entry says: both keys are refused when the file is read,
and forced off in the run (`hypervisors::run`).

A Proxmox cluster is read in part the same way when `GET /nodes` says a node
is `offline`: pveproxy relays the calls about a node to that node, and one that
is down answers nothing but an error. The node is not read, each one is an
error of the run, and the others are written (`collect::nodes`,
`ProxmoxCluster::offline`).

For the recognition of a renamed object, a source read in part is one that
did not run to the end: an object held for it is never a candidate, and what
it reports under a name NetBox does not know is created, not taken for the
object it stopped reporting — that object may be in the part it could not
read (`an_object_also_held_for_a_source_read_in_part_is_never_a_candidate`,
`a_source_read_in_part_renames_nothing_it_reports_under_a_new_name`). A `bmc`
source holds no device (it tags none), so one of its BMCs failing never keeps
a hypervisor from renaming a host
(`a_completing_source_read_in_part_does_not_keep_a_device_from_being_recognised`).

### Orphans

After every reported object is matched, an unmatched NetBox object is an
orphan only if **all** of this holds:

1. it carries the tag of a configured source whose status in this run is
   *succeeded*. A source left out of the run (`--source` named another one) or
   that failed said nothing: its objects stay. What a failed source did report
   is ignored too, since it is partial;
2. it carries no tag of a replaced tool or of an unknown source: that tool may
   still be running;
3. its source did not declare its kind unknown on an ancestor (the interfaces
   of a stopped virtual machine), and it is not the prefix of an address kept
   for that reason;
4. no matched object still points to it through a field the source did not
   report, a list (`tagged_vlans`) included.

Then, per orphan:

- every source that dropped it has `prune = false`: it is kept, and listed;
- another source still claims it: only the tag of the source that dropped it
  is removed;
- otherwise it is deleted — unless NetBox would delete with it a dependent
  that stays (an interface with its device): the deletion is then dropped, up
  to the top of the chain, with a warning.

An orphan a row this run leaves as it is still refers to is kept as well,
with a warning: through a plain foreign key (NetBox would refuse the delete,
or clear the field) or through a list (`Kind::reference_list_fields`: NetBox
takes a deleted VLAN off the `tagged_vlans` of a port without a word).

### VLAN groups

A site of a `[[vlan_groups]]` table keeps its VLANs in a NetBox VLAN group
(`VlanGroups`, `crates/core/src/inventory/model.rs`; read by
`config::parse_vlan_groups`, which gives each hypervisor the group of its
site). Nothing else changes for the source: its hosts, its machines and its
cluster stay at its site.

- **Moving in.** The first run after a site joins a group reports its
  interfaces on the VLANs of the group: each reference is rewritten, and the
  VLAN of the site, which the source owned and no longer reports, is an
  orphan, deleted in the same plan **after** the references moved (writes
  come before deletions). Rule 4 and the paragraph above keep one that
  something else still uses.
- **The group is a prerequisite.** `hypervisors::sync` fails a source that
  refers to a group NetBox does not hold before anything is compared: nothing
  is written for it, and what NetBox holds from it stays (the source is
  *failed*). The reconciliation guards the same case on its own
  (`Reconciler::vlan_creation`): a VLAN whose group is missing is skipped,
  never created without it — it would have neither group nor site, and be
  made anew at every run.
- **A name is unique in a group.** A VLAN to create whose name another VLAN
  of the group has (in NetBox, or created earlier in the same plan) is
  skipped, with an error of its source naming both (`Plan::errors`): the
  write would be refused, and a refused write stops the run.
- **Leftovers.** A VLAN of a site nobody owns is never touched. Once the
  group of its site holds the same number, `site_vlan_leftovers` tells it in
  a warning with the interfaces that still point to it.
- **A group VLAN that also has a site** is identified by its site (see
  "Identity"), and NetBox refuses it on an interface of another site of the
  group. Both families tell it as an error naming it ("clear its site"): the
  hypervisor run does not create a second VLAN of that number in the group
  (`Reconciler::vlan_creation`), the network run neither creates nor renames
  it (`GroupVlans::sited`).
- **The groups come from the table.** The binary hands `[[vlan_groups]]` to
  the hypervisor run (`run_with_groups`): the leftovers of a site of a group
  that no hypervisor source is at are told too, by any run that reads a
  hypervisor.

A device NetBox lacks is not created when `create_devices = false`: it is
skipped with its dependents, and a virtual machine on it only loses that
reference.

### Ordered writes

`reconcile` returns a `Plan` whose steps are sorted; the applier
(`crates/netbox/src/inventory_apply.rs`) writes them as given:

1. **Write**: creations and updates, in dependency order of the kinds;
2. **Link**: the references to an object of the same or a later kind, once
   every object exists;
3. **Delete**: deletions in reverse dependency order, a child interface
   before its parent.

A reference is carried by identity and resolved to an id when written: the id
the reconciliation found, or the id of the object this run created. A
reference that cannot be resolved is left as NetBox has it, with a warning,
rather than cleared.

## Network family

### What a run compares

A collector returns a `DeviceState` (`crates/core/src/network/model.rs`):
serial, interfaces, VLANs, IPv4 addresses, neighbours. `stack::desired_devices`
splits it into the NetBox devices it describes (the members of a virtual
chassis, the two units of a firewall cluster), and three pure functions give
the changes: `diff_vlans`, `diff_device` and `diff_cables`.

Optional values are `Option`s: `None` means the source does not report the
field, which is then not compared. A whole aspect can be unmanaged for a
source (`lag_managed`, `dot1q_managed`, `ips_managed`, `vlan_names_managed`):
a Nipper report tells neither addresses nor LAG membership, a firewall does
not name VLANs.

The 802.1Q of a port is three fields, and a source may know the first alone:
`dot1q_managed` says its mode is known, `untagged_vlan_managed` and
`tagged_vlans_managed` say each of the two others is. A Nipper report gives
the mode of a port and its access VLAN, whatever the mode: the native VLAN
of a trunk and the VLANs it allows are in no column
(`crates/cisco/tests/fixtures/README.md`). The trunk of a report is therefore
`tagged` with both unmanaged, until its description gives its VLANs
(`descriptions::vlans_from_descriptions`, the optional group `vlans` of
`neighbor_pattern`, read as the list of `switchport trunk allowed vlan`, `all`
included): its tagged VLANs are then managed, its native one never is. Before
the VLAN step, which hides the number of a VLAN of a site that joined a group,
the run settles what NetBox holds there (`vlans::settle_native_vlans`): the
untagged VLAN of a port NetBox has as a trunk is its native one and is taken
out of the list, where a switch that tells its native VLAN does it itself
(`dot1q::trunk`); the one of a port NetBox has as an access port is cleared. The
reading has nothing of the rules of the cables: a port-channel, a disabled
port, a port whose neighbour is announced are read. On a switch whose
configuration was read, the same group is only compared with it, on the
VLANs the switch defines, the only ones the collection keeps
(`descriptions::vlans_against_descriptions`). What these readings have to
say travels with the state (`DeviceState::warnings`, each starting with its
port), and the run starts them with the name of the source.

### The five steps of a run

`crates/cli/src/network.rs`. The order is what makes each write valid:

1. **Collection and NetBox reads.** Every source is collected at the same time
   (at most 8), then the NetBox side of each is read (at most 4). Nothing is
   written.
2. **Site VLANs.** A VLAN a device defines and the site lacks is created; its
   name follows the switches. The device writes point at these VLANs. A site
   of a `[[vlan_groups]]` table keeps its VLANs in its VLAN group instead
   (`VlanHome`): the group is looked up by its name once the devices are read
   (a group NetBox lacks fails the sources of its sites, and those only), its
   VLANs are read by `group_id`, a missing one is created in the group and at
   no site, and the applier resolves the VLAN number of a port in the group.
   The group is found whatever the case of its name: the `name` filter of
   NetBox is exact, so every group is read and compared. A port only knows
   the number of its VLAN: one still on a VLAN of its site (told by the id
   NetBox gives, untagged and tagged apart) is read as on `FOREIGN_VLAN`
   (`mark_foreign_vlans`), a number no source asks for, so that the device
   step rewrites it: with the VLAN of the group, or with nothing when the
   device no longer puts a VLAN there. A VLAN whose name another VLAN of the
   group has is not created (an error naming both) nor renamed (a warning),
   unless a rename of the same step frees it. A report defines no VLAN, so
   this step creates none for its ports: once it is done, a VLAN of a port of
   a report that its home does not hold (`vlans::leave_out_missing_vlans`) is
   left out of the port, where the device step would fail on it, and told in
   one warning per source. The access VLAN left out becomes unmanaged, not
   empty.
3. **Devices**, one after the other. Inside a device
   (`crates/netbox/src/apply.rs`):
   1. interfaces created or updated, each after the LAG and the parent it
      points at, with its MAC address;
   2. stale MAC address objects deleted (with `--prune`);
   3. addresses created, updated or re-attached to their interface;
   4. the primary address and the serial;
   5. addresses deleted (with `--prune`).
4. **Cables**, read after the device writes so that new interfaces are seen:
   deletions of replaced cables, then creations. What the hosts of the
   hypervisors of the run hear (`omnisync_core::network::hosts::Heard`) is
   merged first into the neighbours of the synced switches
   (`hosts::merge_heard`): a neighbour of protocol `host` on the port it
   names, unless the switch announces one there itself, the host is a blade
   (it has a `parent_device`), or NetBox does not have its card. A vCenter tells
   it (`QueryNetworkHint`); a Proxmox, which has no such call, through
   `lldpd` on each node, read over SSH (`omnisync_proxmox::neighbors`).
5. **Interface deletions** (with `--prune`), last: their addresses were
   re-attached in step 3, children before parents.

### Protections of deletion

Nothing is deleted without `--prune`. With it, `crates/core/src/network/diff.rs`
still keeps:

| Kept | Why | Test |
|---|---|---|
| The current primary address | Losing it cuts the management entry of the device | `current_primary_ip_is_never_pruned` |
| Every interface that may carry the primary address | NetBox deletes an interface's addresses with it | `interface_holding_the_primary_ip_is_never_pruned`, `every_interface_that_may_carry_the_primary_ip_is_kept` |
| IPv6 addresses, and the interfaces carrying one | IPv6 is not collected: unmanaged, not absent | `ipv6_is_never_pruned`, `interface_carrying_an_ipv6_is_never_pruned` |
| Every address, and the interfaces carrying one, when the source tells no address (a report) | Same reason | `unmanaged_ips_are_neither_pruned_nor_warned_about`, `unmanaged_ips_keep_the_interfaces_carrying_them` |
| The parent of an interface that stays | NetBox refuses to delete it, which would stop the deletions | `parent_of_a_kept_interface_is_kept_too`, `every_ancestor_of_a_kept_interface_is_kept` |
| Interfaces listed in `ignore_interfaces`, and their addresses | Unknown, not absent | `ignored_interface_is_never_pruned_nor_its_addresses` |
| Everything on the other member of a firewall cluster | Only its serial is synced | `unmanaged_device_only_gets_its_serial_even_with_prune` |
| MAC address objects of an interface whose MAC is not reported | Unmanaged | `mac_objects_untouched_when_the_mac_is_unmanaged` |
| VLANs | Never deleted, with or without `--prune` | `vlan_is_never_deleted` (`vlans.rs`) |

An address NetBox assigns to another device or virtual machine is never moved
(`ip_held_by_another_device_or_vm_is_never_taken`); it is created a second
time with a warning, or not at all where the table enforces unique addresses.

For cables, `crates/core/src/network/cables.rs`:

| Rule | Test |
|---|---|
| A cable is deleted or replaced only when both its ends are on devices this run syncs | `protection_a_cable_is_replaced_only_between_two_devices_the_run_syncs`, `prune_ignores_cables_to_unselected_switches` |
| The cables of a source read from a report or through an API (Nipper, FortiOS) are created, never deleted nor replaced | `prune_never_deletes_a_cable_of_a_report_switch`, `cable_of_a_report_switch_is_never_replaced` |
| A local end whose neighbour is unresolved or ambiguous keeps its cable | `protection_an_unresolved_end_keeps_the_existing_cable_and_warns`, `ambiguous_port_keeps_the_current_cable_from_the_prune` |
| LLDP and CDP disagreeing, or one end claimed by two links: nothing is written, the cable is kept | `lldp_and_cdp_disagreeing_write_nothing`, `prune_keeps_cable_when_neighbours_disagree`, `two_pairs_on_one_end_write_nothing` |
| A link that is down shows no neighbour: its cable is kept | `protection_the_cable_of_a_link_that_is_down_is_not_pruned` |
| An end cabled to something that is not an interface (patch panel, circuit) is occupied: no cable is written over it | `end_cabled_to_a_non_interface_termination_is_occupied` |
| A device whose interfaces could not be read is left out of the cable step | `failed_interface_read_never_prunes_cables` (`crates/cli/src/network.rs`) |
| What a host hears replaces the cable of the port, prune or not, report or not; a foreign termination still keeps it | `a_cable_a_host_hears_replaces_the_one_netbox_has_even_on_a_report_and_without_prune` |
| What the switch announces on a port beats what a host hears there, which beats the description | `the_neighbour_a_switch_announces_wins_over_what_a_host_hears_and_the_difference_is_warned`, `what_a_host_hears_wins_over_the_description_of_the_port_and_the_difference_is_warned` (`hosts.rs`) |
| A blade never takes the cable of its chassis | `a_host_inside_a_chassis_never_takes_the_cable_of_its_chassis` (`hosts.rs`), `a_blade_never_takes_the_cable_of_its_chassis` (`crates/cli/src/network.rs`) |

## NetBox access

`crates/netbox/src/client.rs`, behind the `Gateway` trait (four operations:
list, create, update, delete).

- **Filters** are checked against the OpenAPI schema of the instance, fetched
  once per run: NetBox ignores an unknown filter and would return every
  object. A run reads the schema right after the release of NetBox, before
  any source, within a bound of its own (`SCHEMA_TIMEOUT`, 300 s, never less
  than the timeout of a request): NetBox builds it when asked and keeps it a
  day per release, so the first run after a start or an upgrade pays for it
  (2 s on a fresh 4.5.10 or 4.7.5, Docker on a laptop; longer on a slow or
  busy host). Read at
  the first write instead, a slow schema failed the run half way through. It
  is never replayed on a gateway error: each attempt would ask NetBox to
  build it again, and a proxy that cuts it at 60 s would cost four times that
  before the same failure.
- **Reads** are paginated, at most four requests in flight for the whole
  client, and replayed up to three times on a gateway error (502, 503, 504)
  with a doubling wait. A timeout or a refused connection fails at once.
- **Writes** are never replayed.
- **Dry run**: the client refuses every write before sending anything, and the
  inventory applier does not attempt any.
- The token is never printed: error messages are scrubbed of it.

## Configuration and secrets

`crates/cli/src/config.rs`, `crates/core/src/network/inventory.rs`. One file
is loaded on every host that runs the tool, each launching its own sources
(those the file gives it with `runner`, see "Which host launches a source",
or those its command line names with `--source`, `--kind`, `--type`) and
holding only their secrets. The file must
be the same everywhere, because of the ownership tags: a `source-*` tag that
is not the tag of a configured source is removed on adoption (see
"Ownership"), so a host whose file lacked the sources of another would take
their tags off the objects they share. A source left out of a run must
therefore be known to it, without its secrets.

- **The load checks the whole file and never fails on a secret.** Every entry
  is validated (keys, types, addresses, regular expressions, the names
  `source_priority` ranks), whatever is selected. What a source is read with
  is a `Wanted<T>`: `Held(value)`, or `Missing(variables)` with the names of
  the variables that would give it. There is no empty value standing for a
  missing one: half an account (a user without its password) is `Missing` and
  the half that was there is dropped.
- **The run asks for the secrets of what it selected.** Once the selection is
  known and before NetBox or any source is contacted, `Config::require` lists
  every missing variable of the selected sources, and `NETBOX_TOKEN`, in one
  error (`missing environment variables: A, B or C, D (or E and F)`, exit 1).
  No filter selects every source: every secret. `SWITCH_PASSWORD` is not a
  secret of its own: it is one of the two variables a switch read with a
  password can take, so it is asked for only when such a switch is selected
  and has no `SWITCH_<NAME>_PASSWORD`.
- **A source without its secret cannot be read.** `Wanted::held` is the only
  way to the value, and a reader handed such a source (the SSH transport, the
  FortiOS client, the Proxmox, vSphere and Redfish readers, the NetBox client)
  fails with the same error, naming the variables, before it builds a client:
  an empty password is never sent.

Pinned by `a_run_needs_the_secrets_of_the_sources_it_selected_and_no_other`,
`a_selected_source_without_its_secret_stops_the_run_before_anything_is_contacted`,
`a_run_without_filter_needs_every_secret`,
`an_invalid_entry_is_refused_even_when_its_source_is_left_out` and
`a_hypervisor_left_out_of_a_run_keeps_its_tag_on_what_it_shares_without_its_secrets`
(`crates/cli/src/cli.rs`).

### Which host launches a source

`crates/cli/src/config.rs` (`Runners`), `select.rs`, `host.rs`. When the file
is on several hosts, the split used to live in the cron line of each one
(`--source a --source b`), and in nothing the tool could read: the `check` of
a host found the sources of the others CRITICAL in its journal, where they
never ran. A list of sources in the command of Icinga would have had the same
flaw as the cron lines: a source forgotten there runs without being watched.
The file therefore says it, once, for the runs and for the check.

- **A list and a key.** `runners`, at the top of the file, lists the hosts;
  `runner`, in an entry, names the one that launches the source (`host` is
  the address of the equipment). The key is in the entry, not in a table of
  the sources of each host: what is about a source stays in its entry. Both
  loaders of `[[sources]]` take the key, and `config::parse_runners` reads it
  for every entry, as `parse_vlan_groups` reads what belongs to no loader.
- **All or nothing, checked at the load.** No list and no `runner`: one host
  runs everything and nothing changes. With a list, a `runner` that is not in
  it, an entry without one, a host that launches nothing, a host listed twice
  or empty are refused, on every host: no source can be launched by nobody
  without the file saying so.
- **A host is its full name, compared as written.** The canonical name the
  system gives to its short name (`getaddrinfo` with `AI_CANONNAME`, what
  `hostname -f` asks), read through libc as the short one is. A release for
  Linux is linked with musl, whose resolver reads `/etc/hosts` then the DNS
  itself, without `nsswitch.conf`: the name it gives is the first name of the
  first line of `/etc/hosts` that holds the short one (seen on Alpine 3.24:
  `192.0.2.5 sat01.lab02 sat01` gives `sat01.lab02`, the short name first
  gives the short name, and a short name left on the line of `localhost`
  above gives `localhost`, which no list has). A short name is never taken for a
  full one: two writings of a host would be two hosts. The name is only asked
  for when the file has a list, so a file one host runs depends on no name
  resolution. A host the list does not have, or that has no full name, is
  refused before anything is contacted: a machine renamed fails at its first
  run instead of no longer launching its sources. `sync --dry-run --runner HOST` gives
  the name instead of the system (what another host would do, seen from a
  workstation), and is refused without a list. It is refused without
  `--dry-run` too: a run that wrote under the name of another host would
  leave, in the journal of its machine, a last line of that host, and the
  check of the machine would judge the sources of the other and say OK over
  its own. A journal therefore only ever names its machine.
- **The selection is made among the sources of the host**
  (`select::select`, `Host`). No filter: the sources of the host. A
  `--source` of another host and a filter no source of the host passes are
  errors naming the host. The sources of the other hosts stay known to the
  run, left out (`SourceStatus::Skipped`): their tags and their objects are
  not touched, and their secrets are not asked for. A hypervisor left out
  this way says nothing of what its hosts hear either: the cable step only
  has what the hypervisors of its own run heard.
- **A limit: a host that never runs.** A host of `runners` where the tool or
  its cron line is missing has no run and no journal; no other host can see
  it, for want of a shared state. What tells it is outside the tool: the
  Icinga service of that host, UNKNOWN (`cannot read the journal …`).
- **A limit: a file that differs between two hosts.** Each host judges the
  sources its own copy of the file gives it. A source moved from one host to
  another in a file deployed on the first alone is launched by neither, and
  judged by neither: each one believes it is the other's. The file must be
  the same everywhere, as the ownership tags already require; deploying it
  to every host at once is the operator's to ensure.

Pinned by `a_source_names_the_host_that_runs_it`,
`a_runner_on_some_sources_only_is_refused_naming_the_others`,
`a_runner_that_is_not_in_the_list_is_refused`,
`a_host_of_the_list_that_runs_no_source_is_refused` (`config.rs`),
`no_filter_selects_the_sources_of_the_host`,
`a_source_of_another_host_is_an_error_naming_that_host`,
`a_host_that_is_not_in_the_list_is_an_error_naming_the_runners` (`select.rs`),
`a_run_launches_the_sources_of_its_host_alone`,
`a_run_on_a_host_that_is_no_runner_is_refused_before_anything_is_contacted`,
`the_runner_option_replaces_the_name_of_the_host` and
`a_file_without_runners_never_asks_for_the_name_of_the_host` (`cli.rs`).

## Journal, check and digest

`crates/cli/src/journal.rs`, `check.rs`, `digest.rs`. A sync used to tell
what it did by its report alone, which cron mailed run by run. It now also
appends one line to a journal, and two commands read it: `check` for the
monitoring, `digest` for one mail a day.

- **What is journaled.** One JSON line (schema `version` 1) per sync that got
  past the configuration, the selection and the secrets, written after the
  report and before the lock is released, so that two writers never meet:
  `started` (RFC 3339 with the offset of the host), `seconds`, `configured`
  (every source of the file, with its kind), `selected`, `changes` (a
  `Change` without its NetBox id), `applied`, `warnings`, `errors`; and, for
  a file several hosts share, `runner` (the host the run was) and the `runner`
  of each source of `configured`, both absent otherwise: a file one host runs
  writes its lines byte for byte as before. The version stays 1: these are
  optional keys, which an older binary ignores, whereas a version 2 would
  have the new binary skip the eight days of lines a host already wrote, and
  find a source read once a night CRITICAL until the next night. Past the
  secrets NetBox is contacted, and whatever ends the run from there is a line:
  a NetBox that refuses its release, cannot give its schema or cannot be
  reached is a run with that error, which fails every selected source. Before
  that (configuration, selection, secrets, lock) the operator sees the
  refusal on stderr and nothing is journaled; a dry run writes nothing; a run
  interrupted by Ctrl-C is dropped where it is, journal included.
- **Rewritten, never appended in place.** A reader may read at any time: each
  append writes the whole file into a temporary file of the same directory,
  then renames it over the journal. The same rewrite drops the entries that
  started more than 8 days ago (`RETENTION`, a week for the longest digest and
  a day of margin), and keeps any line it does not understand (another
  version, an edited line) as it is: the readers skip it. A journal that
  cannot be written fails the run (exit 1): its writes are made, and a run the
  monitoring will not see must not pass for a success.
- **Readable by the monitoring.** A new journal is `0644` whatever the umask,
  and a directory the tool creates for it is `0755`. A rewrite is a new file
  renamed over the old one: it keeps the mode of the journal it replaces, but
  takes the owner and the group of the writer, never those of the old file. A
  group given to the journal for a `0640` is therefore lost at the next run:
  a journal another user reads stays `0644`. The default journal lives next
  to the lock, whose directory stays private: a monitoring that runs as
  another user reads a journal the configuration puts elsewhere (`journal`).
- **One writer.** The lock excludes the runs of one user (it lives in the
  state directory of that user), the journal of the configuration does not:
  every run that writes it must be the same user. A run as another user
  (root, with the production file) is not excluded by the lock of the cron,
  may rewrite the journal at the same time and lose the line of the other,
  and leaves the journal, or the directory it created, to its own user.
- **Durable.** The temporary file is named after the PID, truncated if a
  killed run left it (a later run may get the same PID), never opened through
  a link, synced before the rename, and the directory is synced after it. The
  journal is read as bytes: a line that is not UTF-8 is a line not understood
  like any other, kept byte for byte and skipped by the readers.
- **`check`** evaluates the sources the last entry lists as configured, so
  that a source no run selects any more is not forgotten. When that entry
  names its host (`runner`), they are the sources of `configured` that host
  launches: the journal is the one of a host, and the others answer for the
  rest from theirs. It stays a function of the journal alone (it reads
  neither the configuration nor the name of the host, so a journal copied
  elsewhere gives the same verdict), and the invariant holds for each host: a
  source of the host no run selected is CRITICAL, a kind it launches without
  `--max-age` is UNKNOWN, and a kind only another host launches needs none. A source failed in
  an entry that selected it when an error starts with `<its name>: `, or when
  an error starts with the name of no selected source (NetBox refused the
  run). Every error of a source therefore starts with its name: the write
  error of a member of a stack or of a cluster peer reads
  `<source>: <device>: …` (`crates/cli/src/network.rs`). Its last success is the end (`started` + `seconds`) of the last entry
  that selected it and where it did not fail: older than the `--max-age` of
  its kind, or missing, is CRITICAL; a recent success with a failed last run
  is a WARNING. So are the warnings of the last entry that selected each
  source that are about it, with the rule of the errors: a warning starts with
  the source it is about (the one that reports the object of a warning of the
  plan, `Warning.source` in `crates/core/src/inventory/reconcile.rs`, the
  winner of a difference two sources settle, the source an orphan is held
  for; the source of the device in a network run), and one that names no
  selected source is about the run. They are listed once each after the sources and never over a worse state: a
  warning repeats at every run until someone acts, and the daily digest would
  tell it up to a day late. A warning `--ignore-warning` matches is listed
  apart and changes nothing: some are said by design at every run, and an
  acknowledgement in Icinga would also hide a run that fails. A kind without `--max-age`
  makes the whole check UNKNOWN before anything is evaluated: an OK for the
  others would hide the gap. A usage error is UNKNOWN on stdout (exit 3), not
  the 1 of the other commands, which Icinga would take for a WARNING.
- **`digest`** takes the entries that ended within `--since` before now (after
  the start of the period, up to now): an entry exists once its run ended, so
  a run that started before the period and ended in it was in no earlier
  digest, and two back to back periods never share nor miss a run. It
  sends nothing when they hold no change and no error (warnings alone are no
  reason for a mail). The text part is the report of the period
  (`report::render`); the HTML part shows each change with the time of its
  run, grouped as the report groups them (`report::sections_of`), its fields
  as the report tells them (`report::field_lines`), so that both parts never
  disagree. A warning or an error repeated by several runs is listed once,
  with its count. Every text of a source is escaped as the report escapes it,
  then for HTML. Both parts are base64, under a boundary base64 cannot hold
  (`=_…`). It loads the configuration as a sync does but asks for no secret,
  and takes no lock: the rename makes the journal safe to read.

Pinned by `a_run_appends_one_entry_to_the_journal`,
`a_dry_run_writes_nothing_in_the_journal`,
`a_run_refused_before_netbox_is_contacted_writes_nothing_in_the_journal`,
`a_run_netbox_refuses_is_journaled_as_failed`,
`a_journal_that_cannot_be_written_fails_the_run_naming_it` (`crates/cli/src/cli.rs`),
`a_journal_that_cannot_be_rewritten_is_left_as_it_was`,
`a_line_that_does_not_parse_is_kept_and_skipped_by_the_readers`
(`journal.rs`), `an_error_fails_the_source_it_names_or_every_selected_one`,
`a_source_whose_kind_has_no_max_age_is_unknown`,
`a_source_of_another_host_is_not_judged`,
`a_source_of_the_host_no_run_selected_is_critical` (`check.rs`),
`an_entry_without_runner_is_written_as_before`,
`a_line_written_before_the_runners_is_still_read` (`journal.rs`) and
`every_text_of_a_source_is_escaped` (`digest.rs`).

## Failure units

What one failure stops, and what goes on.

| Failure | Stops | Goes on |
|---|---|---|
| The configuration (every entry of the file, selected or not), a secret a selected source or NetBox misses, an unknown `--source`, the lock | The run, before anything is contacted (exit 1) | — |
| A hypervisor source cannot be read | That source: nothing of it is written, nothing it owns is deleted | The other sources |
| A reverse DNS lookup fails, times out, or no resolver can be built | Nothing: that address reports no DNS name, NetBox keeps the one it has (one warning for the run) | The source, with every other field of the address |
| A BMC of a `bmc` source cannot be read | That BMC: nothing is written for its device, nothing NetBox holds for it is cleared | The other BMCs of the source, the other sources |
| A BMC does not prove it manages its device (no shared MAC address), or its device is not in NetBox | Nothing: a warning, and nothing is written for that device | Everything else |
| NetBox cannot be loaded for the hypervisors | The hypervisor part | The network part |
| A write of the hypervisor plan fails | Every step after it (they may depend on it) | The network part |
| A network source fails its collection or its NetBox read (a missing VRF or device included) | That source | The other sources |
| The VLAN step fails for a site | The network run: the device writes point at these VLANs | — |
| A write fails on a device | The rest of that device | The other devices, the cables, the deletions |
| The cable step fails | The cables | The interface deletions |
| The journal cannot be written | Nothing: the writes are made, the report printed (exit 1) | — |
| Ctrl-C | Everything, where it is: nothing more is written, nor journaled (exit 130) | The writes already made stay; the next run starts from there |

Any error makes the run exit 1. Once the sources start being read, the report
is printed whatever fails afterwards.
