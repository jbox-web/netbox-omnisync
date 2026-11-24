# lldpd fixtures

What `lldpcli -f json show neighbors` printed on standard output, on Debian 12
nodes running `lldpd` 1.0.16-1+deb12u1, anonymised: the names of the
switches and of the nodes take the domain `lab.example`, a provider's switch
is `PROVIDER-SW001.provider.example`, addresses are moved into
`198.19.0.0/16` and every MAC address is replaced by a fictitious one of the
same shape (`02:00:00:00:xx:xx`, one per real address across the five files).
Everything else, the structure and the whitespace included, is what the
command printed.

| File | Recorded on | What it shows |
|---|---|---|
| `pve01.json`, `pve02.json`, `pve03.json` | The three nodes of the cluster of `../8.4/api.json` (Proxmox VE 8.4), 2026-11-22 | Each physical card (`eth` in `/nodes/<node>/network`) hears a Nexus in LLDP: `via: "LLDP"`, the switch name as the key of `chassis`, `port.id.type: "ifname"` and the port in `port.id.value`. `pve02.json` also holds the neighbours heard on the bridges of the guest firewalls (`fwpr141p0`, `fwln141i0`…): the node itself, a MAC address as port. |
| `empty.json` | A node whose switches announce CDP only, `lldpd` running without `-c`, 2026-11-22 | No neighbour: `{"lldp": {}}`, with a blank line inside. `lldpcli` wrote `lldpd: no neighbor.` on its standard error. |
| `cdp.json` | A host facing the same switches, `lldpd` started with `-c -r` for the capture, 2026-11-23 | A neighbour heard in CDP: `via: "CDPv2"`, the switch name as the key of `chassis` (`id.type: "local"`), `port.id.type: "ifname"`, `port.id.value` and `port.descr` both the port. `capability` is an object here, not a list. |

Never observed: a card hearing two neighbours, LLDP and CDP from the same
switch together (`lldpd -c` facing a Nexus, which announces both, gave the
LLDP one alone), a neighbour without a port name.
