# netbox-omnisync

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#licence)
[![CI](https://github.com/jbox-web/netbox-omnisync/actions/workflows/ci.yml/badge.svg)](https://github.com/jbox-web/netbox-omnisync/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jbox-web/netbox-omnisync)](https://github.com/jbox-web/netbox-omnisync/releases/latest)

netbox-omnisync reads hypervisors, switches, routers and firewalls and writes
what it finds into [NetBox](https://netboxlabs.com/docs/netbox/): devices,
virtual machines, interfaces, addresses, VLANs and cables. It also reads the
BMC of a server (Dell iDRAC, HPE iLO) through Redfish, for the model and the
serial a hypervisor does not know. It is one binary, run from cron, and it only
ever reads from the equipment.

It replaces three tools, and takes over the objects they left in NetBox:

| Tool | What it synced | Here |
|---|---|---|
| netbox-ssot (Go) | Proxmox VE | `type = "proxmox"` |
| netbox-switch-sync (Python) | Cisco IOS and NX-OS, Nipper reports, FortiOS | `type = "ios"`, `"nxos"`, `"nipper"`, `"fortios"` |
| netbox-sync (Python) | VMware vSphere | `type = "vmware"` |

## Install

Each release ships one binary per platform, with its checksum:
`netbox-omnisync-linux-amd64` and `netbox-omnisync-linux-arm64` (static, they
need no library) and `netbox-omnisync-darwin-universal` (one binary for Apple
silicon and Intel Macs). The names carry no version, so the
`latest/download` URLs below stay valid from one release to the next.

```sh
curl -fsSLO https://github.com/jbox-web/netbox-omnisync/releases/latest/download/netbox-omnisync-linux-amd64
curl -fsSLO https://github.com/jbox-web/netbox-omnisync/releases/latest/download/netbox-omnisync-linux-amd64.sha256
sha256sum -c netbox-omnisync-linux-amd64.sha256
install -m 0755 netbox-omnisync-linux-amd64 /usr/local/bin/netbox-omnisync
netbox-omnisync version
```

```text
netbox-omnisync-linux-amd64: OK
netbox-omnisync 0.1.0
```

On macOS, `shasum -a 256 -c netbox-omnisync-darwin-universal.sha256` does the same
check. The release also carries `THIRD-PARTY-NOTICES.txt`, the licences of the
code the binaries embed; a release binary prints them itself, after its own
licence:

```sh
netbox-omnisync licenses
```

A binary built from the sources with a plain `cargo build` prints its own
licence and says that the notices are not embedded: only the release build
(`scripts/release-build.sh`) generates them.

From the sources, with the Rust toolchain `rust-toolchain.toml` pins:

```sh
cargo build --release --locked
```

The binary is `target/release/netbox-omnisync`.

## Usage

```sh
netbox-omnisync help
```

```text
netbox-omnisync 0.1.0 — sync hypervisors and network devices into NetBox
Writes to NetBox unless --dry-run is given: start with a dry run.
Usage: netbox-omnisync <COMMAND>

Commands:
  sync         Sync the sources into NetBox
  check        Tell Icinga the state of each source, from the journal
  digest       Mail what the runs of a period changed, from the journal
  version      Show the version
  licenses     Show the licences of the tool and of what it embeds
  completions  Print the completion script of bash or zsh
  help         Show this help

Sync sources:
  -k, --kind <KIND>    Only hypervisor, bmc, switch, router, firewall
  -t, --type <TYPE>    Only vmware, proxmox, redfish, ios, nxos, nipper, fortios
  -s, --source <NAME>  Only the source of this name

Sync options:
  -n, --dry-run        Report what would change, write nothing
      --prune          Also delete what a network source no longer has
  -q, --quiet          Print nothing when there is nothing to report
  -c, --config <FILE>  Configuration file [default: config.toml]

Examples:
  netbox-omnisync sync --dry-run               What would change, every source
  netbox-omnisync sync -n -k hypervisor        The same, hypervisors only
  netbox-omnisync sync -n -k switch -k router  A filter given twice widens
  netbox-omnisync sync -s pve01.lab01          Sync one source

Exit codes:
    0  Nothing to do, or everything written
    1  An error: command line, configuration, a source, NetBox
    2  --dry-run found changes
  130  Interrupted by Ctrl-C: what was written stays
```

Nothing is done without a command: `netbox-omnisync` alone prints this help on
stderr and exits 1, so that a cron job that lost its `sync` does not pass for a
run. `netbox-omnisync help sync` prints the options of a sync alone, with
`--runner`, which this screen has no line for (see "The same file on several
hosts"); `help check` and `help digest`, those of the two commands that read
the journal of the runs (see "Journal, monitoring and digest").

A run **writes to NetBox** unless `--dry-run` is given. Start with a dry run:

```sh
netbox-omnisync sync --config config.toml --dry-run
```

### Shell completion

`netbox-omnisync completions bash|zsh` prints a script that completes the
commands and their options, the values of `--kind` and `--type`, and the
files of `--config` and `--journal`:

```sh
netbox-omnisync completions zsh > "${fpath[1]}/_netbox-omnisync"   # a folder of your fpath you can write to
mkdir -p ~/.local/share/bash-completion/completions
netbox-omnisync completions bash > ~/.local/share/bash-completion/completions/netbox-omnisync
```

zsh loads it once `compinit` runs in `.zshrc`; bash needs bash-completion 2.
The names of the sources are not completed.

### Selecting sources

Without a filter every source of the configuration runs. `--kind`, `--type`
and `--source` narrow the run: a filter given several times widens (any of its
values), two different filters narrow (a source must pass each of them). When
the file says which host launches each source (`runner`, see "The same file
on several hosts"), "every source" is every source of the host of the run,
and the filters choose among them.

```sh
netbox-omnisync sync --dry-run --kind hypervisor
netbox-omnisync sync --dry-run --kind bmc
netbox-omnisync sync --dry-run --kind switch --kind router
netbox-omnisync sync --dry-run --kind switch --type nxos
netbox-omnisync sync --dry-run --source pve01.lab01
```

`--kind hypervisor` never selects a `bmc` source: the hypervisors are synced
every few minutes, a BMC is read once a day.

A name that is not in the configuration, or filters no source passes, is an
error before anything is contacted:

```text
error: unknown source(s): nope
```

```text
error: no source matches --kind switch --type nxos
```

### Deletions

Nothing is deleted from the network sources (switches, routers, firewalls)
unless `--prune` is given: interfaces, addresses, MAC address objects and
cables the device no longer has are then deleted, within the protections
listed in [docs/design.md](docs/design.md). VLANs are never deleted by a
network source.

`--prune` does not apply to hypervisors. Each hypervisor source has its own
`prune` key in the configuration, true when left out: what NetBox holds from
that source and the source no longer reports is deleted on every run that
reads the source to the end. A `bmc` source never deletes anything and has no
such key. That includes the VLANs of a site a hypervisor source created,
once the site keeps its VLANs in a VLAN group (see
[VLANs shared by several sites](#vlans-shared-by-several-sites)).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing to do, or everything written |
| 1 | An error: the command line, the configuration, a source, NetBox, or another run in progress |
| 2 | `--dry-run` found changes (and no error) |
| 130 | Interrupted by Ctrl-C; the writes already made stay in NetBox, the next run starts from there |

These are the codes of `sync` (and of `digest`, which never exits 2);
`check` exits with the codes of a Nagios plugin (see "Monitoring: `check`").
A usage error exits 1, not 2 (3, UNKNOWN, for `check`):

```sh
netbox-omnisync sync --apply
```

```text
error: unexpected argument '--apply' found

Usage: netbox-omnisync sync [OPTIONS]

For more information, try '--help'.
```

### One run at a time

A run holds the lock file `netbox-omnisync.lock` in `netbox-omnisync/` under
`$XDG_STATE_HOME` (`~/.local/state` when it is not set), next to the known
hosts: the same file for a cron job and an interactive shell of one user,
whatever their `TMPDIR`. Its directory is created readable by its owner only
(one of the user writable by others is made private again, one of another
user writable by others is refused), and the file is never opened
through a symbolic link. A second run started meanwhile is refused and exits 1:

```text
error: another run (PID 49752, started 2026-11-20T07:51:55) holds /home/sync/.local/state/netbox-omnisync/netbox-omnisync.lock
```

The lock is released when the run ends, however it ends; the file stays.

## Configuration

One TOML file holds the NetBox URL and every source:
[config.example.toml](config.example.toml) documents each key with fictitious
values. Copy it to `config.toml` (ignored by git) and fill in the real fleet.

No secret is written in the file: they all come from the environment.
`<NAME>` is the name of the source upper-cased, every non-alphanumeric
character replaced by `_` (`pve01.lab01` gives `PVE01_LAB01_TOKEN`).

| Variable | What it is |
|---|---|
| `NETBOX_TOKEN` | The NetBox API token, with write access (required by every run) |
| `NETBOX_URL` | Overrides `netbox.url` of the file; `https`, or plain `http` on the loopback only (the token would travel in clear) |
| `<NAME>_TOKEN` | API token of a Proxmox hypervisor, alone: it names its account (`user@realm!name=secret`); a `<NAME>_USERNAME` next to it is refused |
| `<NAME>_USERNAME`, `<NAME>_PASSWORD` | Account of a hypervisor, instead of a token (never both); the account shared by the BMCs of a `bmc` source, which takes no token |
| `<NAME>_SSH_PASSWORD` | Password of the nodes of a Proxmox read with `neighbors = "lldpd"` and `ssh.auth = "password"`; needed only by a run that also reads switches |
| `SWITCH_PASSWORD` | Password of the switches and routers when `ssh.auth = "password"` |
| `SWITCH_<NAME>_PASSWORD` | Password of one switch or router, instead of the common one |
| `SWITCH_USERNAME`, `SWITCH_SSH_AUTH`, `SWITCH_KEY_FILE` | Override `username`, `auth` and `key_file` of the common `[ssh]` table |
| `FIREWALL_<NAME>_USERNAME`, `FIREWALL_<NAME>_PASSWORD` | API account of a firewall, both required |

Everything is checked before anything is contacted, and a missing secret is
named by its variable, never by a value:

```sh
netbox-omnisync sync --config config.example.toml --dry-run
```

```text
error: missing environment variables: BMC_LAB01_PASSWORD, BMC_LAB01_USERNAME, FIREWALL_FW01_LAB01_PASSWORD, FIREWALL_FW01_LAB01_USERNAME, NETBOX_TOKEN, PVE01_LAB01_TOKEN (or PVE01_LAB01_USERNAME and PVE01_LAB01_PASSWORD), VCENTER01_LAB01_TOKEN (or VCENTER01_LAB01_USERNAME and VCENTER01_LAB01_PASSWORD)
```

A run needs `NETBOX_TOKEN` and the secrets of the sources it selects, and no
other: without a filter that is every source of the file (every source of its
host, when the file gives each source a `runner`), with
`--source pve01.lab01` only the variables of `pve01.lab01`. `SWITCH_PASSWORD`
is needed when a selected switch or router is read with a password and has no
`SWITCH_<NAME>_PASSWORD` of its own. The rest of the file is checked in full
whatever the selection: a wrong key, type, address or regular expression in
the entry of a source left out is still an error.

`HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` are ignored: NetBox, the
hypervisors, the BMCs and the firewalls are always reached directly, so that
no token or account goes through another host.

### VLANs shared by several sites

NetBox keeps a VLAN at a site, and refuses it on an interface of another
site. Two sites that carry the same VLANs (one LAN stretched over two rooms)
keep them once, in a NetBox VLAN group, with a `[[vlan_groups]]` table:

```toml
[[vlan_groups]]
name = "East"                    # the VLAN group, as NetBox names it
sites = ["east-01", "east-02"]   # the NetBox sites whose VLANs it holds
```

It is a property of the sites, not of the sources: every source whose `site`
(hypervisors) or whose device (switches, routers, firewalls) is at one of
them then looks its VLANs up in the group, puts its interfaces on them, and
creates the ones the group lacks **in the group and at no site**. A site is
in one group at most; a site in none keeps its own VLANs, as before.

When a site joins a group:

- the interfaces the sources report are moved to the VLAN of the group that
  has the same number;
- a VLAN of the site that a hypervisor source owns (its tags) and no longer
  reports is deleted by that source, as any orphan is, once no interface the
  run leaves alone still points to it, untagged or tagged (a warning says
  which one does);
- a VLAN of the site that nobody owns (made by hand) is never touched. Once
  the group holds a VLAN of the same number, each run that reads a hypervisor
  says so in a warning, for every site of the table, with the interfaces that
  still point to it: move them, then delete it by hand. Network sources never
  delete a VLAN.
- a VLAN of the group that also has a site is an error naming it: NetBox
  refuses it on an interface of another site. Clear its site.

Converting the VLANs of one site by hand first (clear their `site`, set
their `group`) keeps the references of its interfaces and leaves only the
duplicates of the other sites to delete.

### The same file on several hosts

The tool can run on several hosts, each launching its own sources: a central
server for most of them, a satellite on another site for the sources only it
can reach. The file says which host launches each source: the hosts are
listed at its top (`runners`), and every entry names one of them (`runner`).

```toml
runners = ["sync01.lab01", "sat01.lab02"]

[[sources]]
name = "vcenter01.lab01"
kind = "hypervisor"
type = "vmware"
host = "192.0.2.20"
runner = "sync01.lab01"

[[sources]]
name = "pve02.lab02"
kind = "hypervisor"
type = "proxmox"
host = "192.0.2.12"
runner = "sat01.lab02"
```

```sh
# The same line on every host: each one launches the sources the file gives it.
netbox-omnisync sync --config config.toml
# On the satellite, this reads pve02.lab02 alone; on the central server it is refused.
netbox-omnisync sync --config config.toml --kind hypervisor --type proxmox
```

- **A host is known by its full name**, the one `hostname -f` prints (the
  canonical name its system gives to its short name: the first name of the
  first line of `/etc/hosts` that holds it, or what the DNS answers),
  compared as it is written: write the full name first on that line.
  A short name is never taken for a full one, nor the reverse. The name is
  only asked of the system by a run of a file that has `runners`.
- **All the sources or none.** A file without `runners` nor `runner` is run
  by one host, as before: nothing changes in `sync`, in the journal or in
  `check`. Once the file has a list, every source needs a `runner` of the
  list, and every host of the list launches at least one source: a `runner`
  that is not in the list, a source without one, a host that launches nothing
  or a host listed twice is refused when the file is loaded, on every host.

  ```text
  error: config.toml: source entry 2 (pve02.lab02): runner 'sat1.lab02' is not one of runners (sync01.lab01, sat01.lab02)
  error: config.toml: runners is set and these sources have no runner: nexus01.lab01
  ```

- **A host that is not in the list runs nothing.** A machine renamed, or
  rebuilt under another name, fails at its first run instead of no longer
  launching its sources without a word; so does a machine whose system gives
  it no full name.

  ```text
  error: sync02.lab01 is not one of runners (sync01.lab01, sat01.lab02): it runs no source of this file
  ```

- **The filters choose among the sources of the host.** Without a filter a run
  launches the sources of its host; `--kind` and `--type` narrow among them;
  a `--source` another host launches, or a filter no source of the host
  passes, is an error that names the host.

  ```text
  error: not run by sync01.lab01: pve02.lab02 (run by sat01.lab02)
  error: no source of sat01.lab02 matches --kind switch
  ```

- **`--dry-run --runner HOST` shows what another host of the list would
  do**, from a workstation for instance. It is refused without `--dry-run`,
  when the file has no list, or when the list does not have that name: a run
  that writes is always the one of its machine, so that its journal only
  ever names one host, the one whose sources `check` judges. A machine whose
  system gives it another name than the one of the file is fixed in its
  `/etc/hosts`, or listed under the name it has.
- **Two sources of two hosts that report the same object follow
  `source_priority`**, as they do in one run: the object is the one of the
  first of them in the list (the first by name when the list ranks neither),
  and the run of the other only adds its tag to it. It is never rewritten
  from one host to the other.
- **Each host holds only the secrets of the sources it launches**, and
  `NETBOX_TOKEN`. A source left out of a run needs no secret; a selected one
  that misses a secret stops the run before anything is contacted.
- **Each host has its own journal, and its own `check`.** A run records the
  host it was and the host of each source; `check` judges the sources of the
  host of the last run alone, with the same command on every host. Declare
  one Icinga service per host of `runners` (see "Monitoring: `check`"): a
  host where the tool or its cron line is missing has no run and no journal,
  no other host can see it, and only its own service, UNKNOWN (`cannot read
  the journal …`), tells it.
- **What the cards of a host hear is told to the switches of the same run.**
  A hypervisor another host launches is left out of the run, and says
  nothing: launch a hypervisor on the host that reads the switches its hosts
  are plugged in, for their cables to follow what they hear ("Cables a host
  hears").
- **The configuration file must be identical on every host**, with every
  source of every host in it. A run takes the `source-*` tag of a source its
  file does not know for a leftover of a replaced tool, and removes it from
  the objects that source shares with the ones it runs (a cluster type, a
  manufacturer): the next run of the other host would put it back, and so
  on. A source that is in the file and left out of the run is known:
  its tags and its objects are left alone.

Other variables the tool reads:

| Variable | What it is |
|---|---|
| `SSH_AUTH_SOCK` | Socket of the SSH agent, for `ssh.auth = "agent"` |
| `SWITCH_KNOWN_HOSTS` | File the SSH host keys are recorded in; `netbox-omnisync/known_hosts` under `$XDG_STATE_HOME` (`~/.local/state`) when not set |
| `XDG_STATE_HOME`, `HOME` | Where the lock file (and the known hosts and the journal by default) live: `$XDG_STATE_HOME/netbox-omnisync`, `~/.local/state/netbox-omnisync` without it |
| `NO_COLOR` | Set and not empty: no colour in the report, even on a terminal |

The host key of a switch is recorded at the first connection; a switch that
later presents another key is refused.

## Output

The report goes to stdout, alone. The progress and the errors go to stderr.

- On a terminal, the progress is a live bar and the report is coloured.
- Elsewhere (cron, a pipe, a file), the progress is one timestamped line per
  step on stderr and the report has no colour.

Every sync but a dry run also appends a line to the journal of the runs,
which `check` and `digest` read (see "Journal, monitoring and digest").

`--quiet` prints nothing on stdout when the run has no change, no warning and
no error; a run that has something to say still prints its full report. Off a
terminal it also drops the progress lines, so that a run with nothing to say
writes nothing at all. What stops a run before it starts (a configuration
error, another run holding the lock) is still one line on stderr.

## What is synced

Hypervisor sources create and update their objects in NetBox. Network sources
and BMC sources only complete devices that already exist in NetBox.

| Type | Read through | Written to NetBox |
|---|---|---|
| `proxmox` | The Proxmox VE API of one node of the cluster; with `neighbors = "lldpd"`, one command over SSH on each node | The cluster and its type; each node as a device with its interfaces; virtual machines and containers with their interfaces, MAC addresses, IP addresses and their prefixes, virtual disks, platform and tags; the 802.1Q mode and the VLANs of the guest interfaces, from the `tag` and the `trunks` of the network cards (`netN`) of the configuration, and of the VLAN sub-interfaces of a node (`bond2.25`), with their parent interface; the site, tenant, roles, generic manufacturer and device type they refer to when missing, and the VLANs the site lacks, created as `VLAN<id>`. The interfaces of a guest come from its agent: a virtual machine whose agent does not answer has none, hence no VLAN either. A card without `tag` nor `trunks` leaves its interface as NetBox has it, so a `tag` removed in Proxmox stays in NetBox; a `trunks` of more than 64 VLANs is a warning and is not written. With `neighbors = "lldpd"` and a run that reads switches, the switch port each physical card of a node hears: see "Cables a host hears" |
| `vmware` | The SOAP API of a vCenter (read and session operations only) for the inventory, its REST API for the tags | The datacenter as a cluster group, the clusters and their type; each ESXi host as a device with its serial, asset tag, physical and VMkernel interfaces, MAC and IP addresses; virtual machines with their interfaces, MAC addresses, IP addresses, virtual disks, platform, comments and the vSphere tags of the machine, of its cluster and of its datacenter; the VLANs of the port groups; the site, tenant, roles, manufacturer, device type and platforms they refer to when missing. Distributed switches are not supported yet: a machine on one keeps its interface and addresses, without VLAN, and the run says so. When the run also reads switches, the switch port each physical card of a host hears (CDP, `QueryNetworkHint`): see "Cables a host hears" |
| `redfish` (kind `bmc`) | The Redfish service of the BMC of each listed device (Dell iDRAC 7, 8 and 9, HPE iLO 4), HTTP Basic, `GET` only | The device type of the device and its manufacturer, created when missing, and its serial: the service tag (`SKU`) of a Dell, the `SerialNumber` of any other vendor. Nothing else: no interface, no address, no tag on the device, and never a new device |
| `nxos`, `ios` | SSH, a closed list of `show` commands | Serial of the device (of each member of an IOS stack); interfaces with their enabled state, description, MTU, type, MAC address, LAG, 802.1Q mode and VLANs; IPv4 addresses with their VRF and the primary address; VLANs of the site; cables from LLDP and CDP neighbours, and from port descriptions when `neighbor_pattern` is set. A description that gives other VLANs than the configuration of its port is a warning |
| `nipper` | A Nipper configuration report (HTML file), no connection | Interfaces of the switch or stack with their enabled state, description and type; the 802.1Q mode of each port and the VLAN of an access port; the VLANs of a trunk and the cables, from port descriptions, when `neighbor_pattern` is set (see "VLANs of a switch known by a report"). Addresses, LAG membership and the native VLAN of a trunk are not read from a report and are left as NetBox has them; its cables are never deleted, but where a host hears the port |
| `fortios` | The FortiOS REST API, certificate pinned by `tls_fingerprint` | Serial of each cluster member; interfaces with their enabled state, alias (as label), description, overridden MTU, MAC address, type, parent, LAG and 802.1Q mode; IPv4 addresses, in the VRF named after their VDOM when it is not `root`; a VLAN of the site that no switch defines. Neighbours are not read: cables are left as NetBox has them |

A value a source does not report is left as NetBox has it; only a value
reported empty clears a field. IPv6 addresses are not collected from network
devices and are never deleted there.

**The login of a firewall** is `POST /api/v2/authentication`, then
`POST /logout` once read. `/logincheck`, the login of netbox-switch-sync,
opens no session from FortiOS 7.6.3
([Fortinet](https://community.fortinet.com/fortigate-3/troubleshooting-tip-fortios-v7-6-3-logincheck-no-longer-returns-a-session-cookie-227837)).
The password is sent in `secretkey`, which FortiOS 7.4 reads, and in
`password`, which Fortinet shows for 7.6.3: FortiOS 7.4.11 takes the two
together (tried on 2026-11-20); a firewall in 7.6.3 has not been tried yet. A
refused login says why, as FortiOS tells it (`LOGIN_FAILED (wrong user or
password)`, `LOGIN_LOCKED_OUT (account locked out)`, a login disclaimer to
accept, two-factor authentication), and nothing of the firewall is read.

### VLANs of a switch known by a report

A Nipper report gives the 802.1Q mode of each port (`Access`, `Trunk`) and
its access VLAN. It gives neither the native VLAN of a trunk nor the VLANs
the trunk allows: on a trunk, its `VLAN` column still is the access VLAN of
the port (`crates/cisco/tests/fixtures/README.md` says how this was
observed). What is written follows:

- **An access port** gets its mode and its VLAN from the report.
- **A trunk** gets its mode from the report, and its tagged VLANs from its
  description, when `neighbor_pattern` has a named group `vlans` and the
  description matches it. The group is read as the list of `switchport trunk
  allowed vlan`: `10-12,25`, or `all` for a trunk that carries every VLAN.
  A trunk whose description gives no VLAN keeps the tagged VLANs NetBox has.
  Its native VLAN is never written: NetBox keeps the untagged VLAN it has on
  a port it already has as a trunk, and that one, which the allowed list of
  a switch holds as well, is not repeated among the tagged VLANs. A port
  NetBox has as an access port and the report now gives as a trunk loses its
  access VLAN: nobody told it as a native one.
- Every port the report gives a mode is read, a port-channel as well, and a
  port that is disabled or tells no cable. A description may give VLANs
  without naming a host. A port the report gives an address (the routed
  management port of a stack) is not a switchport: its mode is left as it is.
- **A VLAN NetBox does not hold is never created**: a report names no VLAN.
  It is looked for at the site of the switch, or in the VLAN group of that
  site; a missing one is left out of the ports, and the run says which in one
  warning per switch. An access port whose VLAN is missing keeps the VLAN
  NetBox has.
- A list that cannot be read (`V:10-x`, a range that ends before it starts,
  or `Vlan 10-11-12`, where the dashes separate three VLANs) is a warning
  naming the port, and the trunk keeps its tagged VLANs: a list is never read
  in part. An access port whose description says another VLAN than the
  report is a warning too: the report is believed.

A switch read over SSH gives its VLANs itself. Its descriptions are only
compared, on the VLANs the switch defines: one that gives other VLANs than
the configuration of its port is a warning, and the configuration is written. As any warning, it lasts in the
[check](#monitoring-check) until a run no longer says it.

**A convention for port descriptions.** Any wording can be read, as long as
the pattern finds it. This one keeps the host, its port and the VLANs apart,
and what follows reads it:

```
[No Monitor] <host>/<port>[/<speed>] [<key>:<value> ...]
```

| Description | Host | Port | VLANs |
|---|---|---|---|
| `lab1-esx03.prod/vmnic2/1G V:10-12,17-18,21-25` | `lab1-esx03.prod` | `vmnic2` | 10 to 12, 17, 18, 21 to 25 |
| `lab1-rt02.prod/GigabitEthernet0/0 V:952,954 D:Interco` | `lab1-rt02.prod` | `GigabitEthernet0/0` | 952, 954 |
| `[No Monitor] lab1-fw01.prod/wan1 D:none V:952 T:HST` | `lab1-fw01.prod` | `wan1` | 952 |
| `[No Monitor] lab1-c190-01.prod/a0a/10G V:all` | `lab1-c190-01.prod` | `a0a` | every VLAN |
| `[No Monitor] drac-lab1-pve01.prod V:18` | `lab1-pve01.prod` | its management card | 18 |
| `N:CIRCUIT CTA/CTB/LE-143095 V:4-7,10-12` | none | none | 4 to 7, 10 to 12 |

`[No Monitor]` is a marker of the operator and is optional, the speed (`1G`,
`10G`, `100M`) is optional, `V:` gives the VLANs up to the next space, and
every other pair (`D:`, `T:`, `IP:`) is ignored, in any order. The first word of any other
description is read as a host too (`router of the provider` names `router`),
which NetBox does not hold: a warning at every run. Narrow the `host` group
to the names of your hosts (`(?P<host>lab[12]-[a-z0-9.-]+)`) to leave such
descriptions out:

```toml
neighbor_pattern = '(?i)^(?:\[No Monitor\]\s+)?(?:(?:i?drac|ilo)[-\s]+)?(?:(?P<host>[a-z0-9][a-z0-9.-]*)(?:/(?P<port>\S+?))?(?:/\d+[MG])?(?:\s+|$))?(?:.*?\bV:(?P<vlans>\S+))?'
```

### DNS names

With `dns_name_lookup = true` on a hypervisor entry, the DNS name of each
address the source reports, IPv4 and IPv6, is the name of its reverse lookup
(PTR record). It is off when the key is left out: the names NetBox has are
then kept as they are. A `bmc` entry takes neither `dns_name_lookup` nor
`dns_servers`: a BMC source reports no address.

- **Only an answer writes.** An address without PTR record, a lookup that
  fails or times out, an empty name: no DNS name is reported for that address
  and NetBox keeps the one it has. A name is never cleared.
- The name is written without its final dot and in lower case. Of several
  records, the first in alphabetical order is kept, so that the name does not
  change from one run to the next.
- A name NetBox would refuse (anything but letters, digits, hyphens and
  underscores in labels separated by dots, or more than 255 characters) is not
  written; the run lists such names in one warning per source.
- Link-local, loopback and unspecified addresses are never looked up.
- The resolvers asked are those of the system (`/etc/resolv.conf`, and the
  hosts file), or the ones of `dns_servers = ["192.0.2.53"]` (addresses, port
  53 unless written `"192.0.2.53:5353"`), over UDP then TCP.
- Lookups never fail a source. An address is asked once in a run, whatever
  the number of sources that report it; fifty lookups are in flight at most,
  each given 3 seconds, and the lookups of one source 15 seconds in all: a
  resolver that no longer answers costs those 15 seconds, then the addresses
  left are not asked. The lookups that failed are counted in one warning for
  the run:

```text
reverse DNS: 12 of 480 lookups failed (12 timed out); the DNS names NetBox holds for these addresses are kept
```

### BMC sources

A `bmc` source lists NetBox devices and the address of the BMC of each
(`devices` with `bmc_pattern`, or the `bmcs` table; see
[config.example.toml](config.example.toml)). A BMC presents the self-signed
certificate it was shipped with: `tls_fingerprints` pins it, device by device
(the SHA-256 of the certificate, as `openssl x509 -fingerprint -sha256` prints
it), so that the account goes to that BMC and no other, where
`validate_certs = false` would send it to whatever answers. For each device it reads the BMC
and writes the device type and the serial of the device, on these conditions:

- **The device exists.** A device that is not in NetBox is a warning: it is
  never created from its BMC.
- **The BMC is the one of that device.** One of the MAC addresses the BMC
  reports for its server must be on an interface of the device in NetBox
  (the address in use, never the permanent one). When none is, nothing is
  written and the warning names the device and the BMC: most likely the
  address of another server's BMC. A device NetBox holds no MAC address for
  yet is left alone as well, with a warning, until a source has written its
  interfaces.
- **The BMC answers.** A BMC that cannot be read is an error of the run (exit
  code 1); the other BMCs of the source are still read and written, and
  nothing NetBox holds for the unread one is touched.

What the BMC does not know is not written: a blank serial (seen on an iLO 4)
never clears the serial NetBox has. The host name the BMC was told is only
compared, on its short name, with the name of the device: a difference is a
warning.

The same device may be reported by a hypervisor source. A Proxmox VE source
knows nothing of the hardware and only gives a generic device type to a device
that has none: the device type and the serial of the BMC are written, whatever
`source_priority` says, and the hypervisor never writes them back. A vCenter
knows the hardware too, but the BMC is the hardware: for a device listed in a
`bmc` entry of the file, the vCenter only fills a device type or a serial that
NetBox does not have, and what the BMC wrote stays, whether the two run
together or apart (the hypervisors every five minutes, the BMCs once a day).

Each BMC costs four requests (iLO 4) or five plus one per network card
(iDRAC), a few seconds each on an old iDRAC, and the BMC logs every one: run
this kind once a day.

## NetBox prerequisites

- **NetBox 4.5, 4.6 or 4.7.** The integration tests run against the last
  release of each (4.5.10, 4.6.10, 4.7.5). A run reads the release of
  NetBox in `/api/status/` before anything else, and refuses another one
  before any source is read; `unsupported_version = "warn"` in `[netbox]` runs
  it anyway, with a warning in the report. Every field a run writes is checked
  against the OpenAPI schema of the NetBox it writes to: NetBox drops a field
  it does not know and answers as if it were written, so a field a release
  renamed or removed is refused instead, naming it. A `--dry-run` checks the
  fields of the writes it would make the same way, and sends none. The schema
  is read right after the release, before any source, once, and may take up
  to five minutes: NetBox builds it when asked, and a NetBox that has just
  started took more than a minute. A proxy in front of NetBox must let that
  request run as long (nginx: `proxy_read_timeout`), or the run stops on its
  504.
- **A token with write access**, given as `NETBOX_TOKEN`. A token starting
  with `nbt_` is sent as a v2 token (`Bearer`), any other as a v1 token.
  NetBox 4.7 no longer takes v1 tokens: from 4.5, create a v2 one. It
  must be able to read the OpenAPI schema (`/api/schema/`): every query filter
  is checked against it, and an unknown filter is refused instead of sent.
- **Rights.** For hypervisors: view, add, change and delete on tags, tenants,
  sites, manufacturers, device types, platforms, device roles, cluster types,
  cluster groups, clusters, VRFs, VLAN groups, VLANs, prefixes, devices,
  virtual machines, device and VM interfaces, virtual disks, MAC addresses and
  IP addresses. For network sources: view on devices, virtual chassis and
  VRFs; view, add, change and delete on interfaces, MAC addresses, IP
  addresses, VLANs and cables; change on devices.
- **For network sources**, the devices exist already, named as the source (or,
  for a stack, as the members of the `virtual_chassis` named in the
  configuration, with their `vc_position`), and so do the VRFs the device
  uses. A source whose device or VRF is missing is reported and skipped.
- **For BMC sources**: view on devices, interfaces and MAC addresses; change
  on devices; view, add and change on manufacturers, device types and tags.
  The devices exist already, with the MAC address of at least one of their
  cards.
- **For the sites of a `[[vlan_groups]]` table**, the VLAN group exists, under
  the name the table gives it: it is never created. A hypervisor source whose
  group NetBox does not hold is an error and writes nothing; so is a network
  source. Its VLANs have **no site** (NetBox refuses a VLAN of a site on an
  interface of another one), and their names are unique in the group, as
  NetBox requires: a VLAN whose name another VLAN of the group already has is
  an error naming both, and is not created. Network sources need view on VLAN
  groups.
- **For Proxmox sources**, the custom fields netbox-ssot defined exist:
  `source`, `source_id`, `host_cpu_cores`, `host_memory` and `arp_entry`. The
  tool fills them and does not create them.

### Ownership tags

Every object a hypervisor source manages carries two tags: `netbox-omnisync`,
and `source-<slug>` for each source that reports it (`pve01.lab01` gives
`source-pve01lab01`). The tags are created when missing and matched by their
slug. An object is only ever deleted when it carries the tag of a source that
was read to the end in this run and no longer reports it; a source that failed
or was left out of the run keeps everything.

Network sources use no tag: they act on the devices named in the configuration.
A BMC source never tags the devices it completes: they stay their
hypervisor's, or nobody's. It tags the manufacturers and device types it
creates, and adds its tag to the ones a hypervisor source already owns, so
that they are not deleted under the devices that use them; one made by hand is
used as it is, untagged.

### Renamed hosts and virtual machines

A host or a virtual machine renamed in its source is renamed in NetBox, not
created a second time: when a hypervisor source reports one under a name
NetBox does not have, it is recognised by the MAC addresses of its interfaces
among the objects NetBox holds from that source (and, for a virtual machine,
in the same cluster) that the source no longer reports under their name. The
report then shows one update, of `name`; its interfaces, addresses and disks
stay as they are. When several objects match and none has at least twice the
matches of the next, nothing is guessed: a warning names them, and the object
is created as a new one. What reports no MAC address cannot be recognised
this way: a machine whose interfaces the source could not read (on Proxmox, a
stopped one), and a Proxmox node. Details: [docs/design.md](docs/design.md).

A `bmc` entry names its devices as NetBox does, so a host renamed in its
hypervisor has to be renamed in that entry too. Until it is, the host is
still renamed in place, and its BMC is left out with a warning: while the
entry gives the old name, `device pve01.lab01: renamed pve02.lab01 by this
run, and bmc.lab01 only completes it under the name it had; skipped`, then
`not in NetBox` on the following runs. An entry that already gives the new
name is left out of the one run that renames the device (NetBox does not hold
that name yet when the BMC is checked) and completes it from the next one.

### First run on a NetBox the old tools filled

An object the old tools left is found by its identity (name, address, parent)
and adopted: the tags of the old tools (`netbox-ssot`, `netbox-ssot-orphan`,
`netbox-synced`, `netbox-synced-orphaned`, `type-proxmox`,
`proxmox-netbox-sync`, and the `source-*` tags of sources that are no longer
configured) are replaced by the two tags above. Adoption changes nothing else.
Run the first time with `--dry-run` and read the report: tag updates are
expected, anything else is a difference between the source and NetBox.

**Cables a host hears.** A run that reads hypervisors and switches together
asks each vCenter what each physical card of each connected host hears of
the switch it is plugged in (`QueryNetworkHint`, CDP: a standard vSwitch
offers no LLDP), and tells it to the cable step: the card is a neighbour of
the port it names. On a port of a switch of the run, the neighbour the switch
announces itself is believed first, what a host hears next, the description
of the port last. A host that contradicts the description of the port, or
the cable NetBox has there, gets the cable, with or without `--prune`, a
report switch included, and the run says so in a warning; a host that
contradicts what the switch announces is told in a warning and changes
nothing. The switch is known by its name without the domain, the serial a
Nexus adds between parentheses, or an alias; a switch the run does not read
is given nothing, and a short name two switches of the run share names
neither (a warning). A host installed in another device (`parent_device`: a
blade in its chassis) gives nothing: the switches of a chassis repeat what
the upstream switch announces. A card NetBox does not have leaves the port as
it is, with a warning, and so does a card the `interface_filter` of its entry
leaves out. A card that hears
nothing, a host whose hint cannot be read (a warning), a source that fails or
that the run does not select say nothing: the cables of their ports are left
as they are. `--kind hypervisor` alone never asks for it.

A Proxmox VE API tells no neighbour: an entry with `neighbors = "lldpd"`
logs into each node that is online, over SSH, with the account of its
`[sources.ssh]` block (the keys of the `[ssh]` block of the switches, the
same known hosts file), and runs `lldpcli -f json show neighbors` on a
channel without a terminal nor a shell, and nothing else, never through
`sudo`. Only the cards Proxmox lists as physical (`eth`) count: what a bridge
or the interface of a guest firewall hears is left out. A node is reached by
its name with the `domain` of the entry, or at the address
`[sources.ssh.hosts]` gives it. Two preconditions are on the nodes, and the
tool does not set them: `lldpd` running, started with `-c` when a switch
announces CDP only (it hears LLDP alone otherwise); and an account that can
read its socket, `root` or a member of the group `_lldpd`. A node that cannot
be logged into, or whose command fails, is a warning naming it.

A few behaviours of the old tools were defects and are not reproduced; they
are listed in [docs/reference-defects.md](docs/reference-defects.md).

## Cron

Hypervisors every five minutes, the network and the BMCs once a day, and one
mail a day of what they changed. The secrets come from a file only the cron
user can read, made of `export NAME=value` lines:

```cron
*/5 * * * * . /etc/netbox-omnisync/env && netbox-omnisync sync --config /etc/netbox-omnisync/config.toml --kind hypervisor --quiet >/dev/null 2>>/var/log/netbox-omnisync.log
17 3 * * *  . /etc/netbox-omnisync/env && netbox-omnisync sync --config /etc/netbox-omnisync/config.toml --kind hypervisor --kind switch --kind router --kind firewall --prune --quiet >/dev/null 2>>/var/log/netbox-omnisync.log
47 4 * * *  . /etc/netbox-omnisync/env && netbox-omnisync sync --config /etc/netbox-omnisync/config.toml --kind bmc --quiet >/dev/null 2>>/var/log/netbox-omnisync.log
0 7 * * *   . /etc/netbox-omnisync/env && netbox-omnisync digest --config /etc/netbox-omnisync/config.toml --since 24h --to noc@example.net
```

The daily network line selects the hypervisors too: their hosts then tell
the cable step which switch port each of their cards hears ("Cables a host
hears"). It needs the secrets of the hypervisors as well as those of the
switches.

Every sync writes its line in the journal (see below), so its report is not
needed on stdout: `>/dev/null` leaves cron nothing to mail, and the digest of
7:00 tells, in one mail, what the runs of the last 24 hours changed and what
failed; a day without change nor error sends nothing. The digest needs no
secret, but it reads `netbox.url` from the file, or `NETBOX_URL` from the
environment like the syncs: it sources the same file of variables. All these
lines run as one user, the owner of the journal (see "Journal, monitoring and
digest"): a sync run by hand as root would not be excluded by their lock.
What stops a run before it starts (a configuration error, another
run holding the lock) goes to stderr, into the log. The sync lines share the
lock file: a five-minute run that starts while the daily one is still going
is refused, exits 1 with one line on stderr, and the next one catches up;
Icinga (`check`) tells a source that no longer succeeds.

`ssh.auth = "agent"` needs an SSH agent, which cron does not have: use
`auth = "key"` with a key without passphrase, or `auth = "password"`.

Old switches may refuse what a current client offers. `ssh.disabled_algorithms`
(in the common `[ssh]` table or in the one of a switch) removes algorithms by
kind: `pubkeys`, `kex`, `keys`, `ciphers` and `macs`. An NX-OS 7.0(3), which
sends no `server-sig-algs` and refuses `rsa-sha2-*`, needs:

```toml
[ssh]
disabled_algorithms = { pubkeys = ["rsa-sha2-512", "rsa-sha2-256"] }
```

A kind or a name the client does not know is refused rather than ignored, and
`pubkeys` cannot disable all three RSA signatures (`rsa-sha2-512`,
`rsa-sha2-256`, `ssh-rsa`): an RSA key would have nothing left to sign with.

## Journal, monitoring and digest

Every sync that contacted NetBox appends one JSON line to the journal of the
runs, after its report, while it still holds the lock: when it started, how
long it took, every source of the configuration and the ones it selected,
its changes, the number written, its warnings and its errors; and, for a file
several hosts share, the host the run was and the one that launches each
source (`runner`). A run that
NetBox refused (its release, its schema) is a line with that error; a dry
run, a configuration error, a missing secret or another run holding the lock
write nothing; nor does a run interrupted by Ctrl-C. A journal that cannot be
written fails the run (exit 1), after its writes.

The journal is `journal.jsonl` next to the lock file unless the `journal` key
of the configuration names another one. Each line is replaced in one rename,
so a reader never sees half of it; lines older than 8 days are dropped, a line
that is not an entry is kept as it is. A new journal is readable by all (it
holds names and addresses, no secret); the default directory is not: when the
monitoring reads the journal as another user, name a journal in a directory
it can read (`journal = "/var/lib/netbox-omnisync/journal.jsonl"`, whose
directory is created readable by all when missing). Each run replaces the file
with a new one of the same mode but of its own owner and group: a group given
to the journal for a mode `0640` is lost at the next run, so a journal read by
another user stays `0644`.

**Every run that writes the journal must be the same user.** The lock lives
in the state directory of the user who runs, the journal where the
configuration says: a sync run by hand as root with the production file is not
excluded by the lock of the cron user, may rewrite the journal at the same
time (one of the two lines is lost), and leaves the journal, or the directory
it created, owned by root, which the next cron run cannot replace. Run the
syncs by hand as the cron user (`sudo -u <user> …`), or with `--dry-run`,
which writes nothing.

### Monitoring: `check`

`netbox-omnisync check` reads the journal as a Nagios plugin: every source of
the configuration (as the last line lists them) must have succeeded within
the maximum age of its kind. When the file gives each source a `runner`, the
sources judged are those of the host of the last run, the others being judged
from the journal of their own host; a kind that host launches no source of
needs no `--max-age` there, so the command is the same on every host. The
check reads the journal alone: neither the configuration nor the name of the
host. A source failed in a run when an error of the run
starts with its name and `: `, or when an error names no source the run
selected (NetBox refused the run).

```sh
netbox-omnisync check --journal /var/lib/netbox-omnisync/journal.jsonl \
  --max-age hypervisor=15m --max-age bmc=26h --max-age switch=26h --max-age router=26h \
  --max-age firewall=26h
```

```text
NETBOX-OMNISYNC WARNING - pve01.lab01: last run failed | sources=12 failed=1 stale=0 warnings=0
pve01.lab01: last run failed
  pve01.lab01: node pve01 is offline
```

| Code | State | When |
|---|---|---|
| 0 | OK | Every source succeeded within its maximum age |
| 1 | WARNING | The last run of a source failed, and its last success is recent enough; or the last run of a source has warnings |
| 2 | CRITICAL | A source has no success within its maximum age, or none in the journal |
| 3 | UNKNOWN | The journal cannot be read or has no entry, a kind has no `--max-age`, or a usage error |

The warnings of the last run of each source are listed after the sources, each
once, and make the state a WARNING: something the runs keep failing to write
is told within one check, not in the next daily digest. It is over as soon as
a run no longer says it; a source read once a night keeps the warnings of its
run until the next one. A warning starts with the source it is about, as an
error does (`vcenter01.lab01: ip 192.0.2.72/24 of web02: …`), and only the next
run of that source takes it back; one that names no source of its run (the
release of NetBox, the reverse lookups) is about every source of that run. A warning a run says by design (a field a
`source_priority` settles, a release of NetBox run with
`unsupported_version = "warn"`) would keep the check at WARNING for good:
`--ignore-warning REGEX` (repeatable) leaves out the warnings it matches,
listed apart under `ignored warnings:`. The perfdata count the warnings that
stand (`warnings=`). A duration is a whole number
and `s`, `m`, `h` or `d`. A check takes no lock and contacts nothing. An Icinga
2 command that runs it over SSH on the host of the runs:

```icinga2
object CheckCommand "netbox-omnisync" {
  import "by_ssh"
  vars.by_ssh_command = [
    "/usr/local/bin/netbox-omnisync", "check",
    "--journal", "/var/lib/netbox-omnisync/journal.jsonl",
    "--max-age", "hypervisor=15m", "--max-age", "bmc=26h",
    "--max-age", "switch=26h", "--max-age", "router=26h",
    "--max-age", "firewall=26h",
  ]
}

object Service "netbox-omnisync" {
  host_name = "sync01.example.net"
  check_command = "netbox-omnisync"
  check_interval = 5m
}
```

With a file several hosts share, declare this service on each host of
`runners`: each one answers for its own sources, and a host that never ran is
only told by its own service.

### Daily mail: `digest`

`netbox-omnisync digest --since 24h --to noc@example.net` reads the journal
and the URL of NetBox from the configuration (`--config`, `config.toml` by
default; no secret is needed) and mails the runs that ended in the period (a
run is journaled when it ends: the one still going when a digest is made is
in the next one): a text part (the report of the period) and an HTML part (each change with the
time of its run, the warnings and the errors, a link to the changelog of
NetBox from the start of the period). A warning or an error said by several
runs is listed once, with the number of runs. The HTML part shows the first
300 changes, the text part all of them.

- Nothing is printed nor sent when the period has no change and no error.
- Without `--to`, the message is printed on stdout, to read or to pipe.
- With `--to` (repeatable), it is handed to `/usr/sbin/sendmail -t -oi`
  (`--sendmail` names another one), which adds `From` and `Date`; a sendmail
  that cannot start or fails is an error (exit 1).
- `--since 24h` is 24 hours, not a day of the clock: on the days the clock
  changes, a daily cron line on local time leaves out, or mails twice, the runs
  of one hour.

## To do

- **Try the login on a FortiGate in FortiOS 7.6.3 or later.** The login
  sends the password in `secretkey`, which FortiOS 7.4.11 reads, and in
  `password`, which Fortinet shows for 7.6.3; only 7.4.11 was tried. On the
  first firewall upgraded, check that a run reads it; if its login is
  refused, the field 7.6.3 reads is to be found.

## Documentation

- [docs/design.md](docs/design.md): how objects are identified, owned,
  written and deleted.
- [docs/reference-defects.md](docs/reference-defects.md): defects of the
  replaced tools that were fixed rather than ported.
- [docs/vmware-reference.md](docs/vmware-reference.md): inventory of
  netbox-sync, the reference the VMware source was written from.
- [CONTRIBUTING.md](CONTRIBUTING.md): tests, fixtures, adding a version of a
  source or a new source.

## Licence

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
