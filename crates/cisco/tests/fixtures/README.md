# Cisco fixtures

Outputs observed on real switches, then anonymised: host names, addresses,
serial numbers and the names of customers are replaced by fictitious values of
the same shape; everything else, structure included, is what the switch or the
report gave. `CONTRIBUTING.md` says how a directory is added.

| Directory | What it holds |
|---|---|
| `ios/` | The output of each command of `IOS_COMMANDS`, one file per command |
| `nxos_i2/`, `nxos_i4/` | The output of each command of `NXOS_COMMANDS`, on two NX-OS releases |
| `nipper/` | One excerpt of a Nipper configuration report (HTML) per stack: `fplab1-sw001.html`, `fplab2-sw001.html`, and `fplab1-sw001-convention.html`, the first stack seven weeks later, once its port descriptions were rewritten |

Expected values of the tests are written by hand from these files, never from
what the code returns.

## What the switchport table of a Nipper report means

The table whose header is `Interface | Active | Description | VLAN | Mode |
Port Security | Security Violation` has one row per port. A report says
nothing of what its columns are, so the two reports the fixtures were made
from were compared, port by port, with `show interfaces switchport` of the
same two stacks (2026-11-25; 138 ports of one stack, 137 of the other):

| Column | What it is | Observed |
|---|---|---|
| `Mode` | `Administrative Mode`: `Access` for `static access`, `Trunk` for `trunk` | 275 ports out of 275 |
| `VLAN` | `Access Mode VLAN`, the VLAN of `switchport access vlan`, **whatever the mode** | 275 ports out of 275 |

So on a trunk the `VLAN` column is not the native VLAN: it is the access VLAN
the port would have if it were not a trunk. On the 128 trunks of the two
stacks it never is `Trunking Native Mode VLAN` (the column says 1 or 2, the
native VLAN is 3 or 24). A report gives neither the native VLAN of a trunk nor
the VLANs it allows: `Trunking VLANs Enabled` is in no table.

One row is not a switchport. `GigabitEthernet0/0`, the routed management port
of the stack, is given `1 | Access` by the report, and `show interfaces
switchport` does not list it. It is the only port the `Interfaces` table gives
an address (`192.0.2.1 255.255.248.0` in `fplab1-sw001.html`, `None` for every
other port).

The descriptions of these two reports give the VLANs of some ports in two
forms: `V:4-6,10-12,14-19,952` (the syntax of `switchport trunk allowed vlan`)
and free text, `Vlan 10-11-12`, where the dashes separate three VLANs.

`fplab1-sw001-convention.html` is the report of the first stack on
2026-11-24, after its descriptions were rewritten to the convention the
README recommends (`<host>/<port>[/<speed>] V:<vlans>`): of its 64 trunks, 46
have a list, 6 say `V:all`, 4 name a circuit or an uplink without any VLAN and
8 are unused. Six of the lists are `V:19-20,24`, on trunks whose native VLAN
is 24: the list of a description is the allowed list, native VLAN included. Its section and table numbers are not those of the two others
(the report has one section less): the parser knows a table by its header.
