# VMware fixtures

Answers observed on a vCenter Server 6.7.0 (API 6.7.3), anonymised: names,
addresses, MAC addresses, UUIDs, serial numbers, datastore paths and notes are
replaced by fictitious values of the same shape; everything else, structure
included, is what the server sent. One directory per vSphere version.

Expected values of the tests are written by hand from these files, never from
what the code returns. The end-to-end tests of the command line
(`crates/cli`) serve the same files through `tests/common/mod.rs`.

## What is read, and nothing else

Every operation below is a read or a session operation. The client refuses any
other one.

SOAP, `POST /sdk`, namespace `urn:vim25`:

| Operation | File | Purpose |
|---|---|---|
| (GET) `/sdk/vimServiceVersions.xml` | `vimServiceVersions.xml` | API versions the server speaks |
| `RetrieveServiceContent` | `RetrieveServiceContent.xml` | Product, and the managed objects to talk to |
| `Login` | `Login.xml` | Session (cookie `vmware_soap_session`) |
| `CreateContainerView` | `CreateContainerView.<Type>.xml` | Every object of a type under the root folder |
| `RetrievePropertiesEx` | `RetrievePropertiesEx.<Type>.0.xml` | First page of the properties of these objects |
| `ContinueRetrievePropertiesEx` | `RetrievePropertiesEx.<Type>.<n>.xml`, n > 0 | Next pages, by token |
| `DestroyView` | `DestroyView.<Type>.xml` | Releases the view |
| `Logout` | `Logout.xml` | Ends the session |
| `RetrievePropertiesEx` | `RetrievePropertiesEx.HostSystem.networkSystem.xml` | The network system of each host (`configManager.networkSystem`), asked apart from the other properties of the hosts |
| `QueryNetworkHint` | `QueryNetworkHint.<network system>.xml` | The switch port each physical card of a host hears, by CDP |

Types and properties asked for:

| Type | Properties |
|---|---|
| `Datacenter`, `Folder` | `name`, `parent` |
| `ClusterComputeResource`, `ComputeResource` | `name`, `parent`, `host` |
| `DistributedVirtualSwitch` | `name`, `uuid` |
| `DistributedVirtualPortgroup` | `name`, `key`, `config.defaultPortConfig`, `config.distributedVirtualSwitch` |
| `HostSystem` | `name`, `parent`, `summary.config.product`, `summary.hardware`, `summary.runtime.connectionState`, `hardware.systemInfo`, `config.network.pnic`, `config.network.vnic`, `config.network.vswitch`, `config.network.portgroup`, `config.network.proxySwitch` |
| `VirtualMachine` | `name`, `config.annotation`, `config.guestFullName`, `config.hardware.device`, `config.hardware.memoryMB`, `config.hardware.numCPU`, `config.instanceUuid`, `config.uuid`, `config.template`, `config.extraConfig`, `guest.guestFullName`, `guest.net`, `guest.ipStack`, `guest.hostName`, `guest.toolsRunningStatus`, `runtime.host`, `runtime.powerState`, `runtime.connectionState` |

`config.extraConfig` was reduced to its `guestOS.detailed.data` entry when it
was captured: it is the only one read, and the others may hold anything.

These are the properties the answers were captured with. The collector asks
for all of them but two, which no rule of the translation needs:
`hardware.systemInfo` of a host and `runtime.connectionState` of a machine.
`guest.toolsRunningStatus` is asked for: only running tools tell the addresses
of a guest. Inside the properties already read, the translation also uses the
`xsi:type` of a network card (`VirtualVmxnet3`), `backing.diskMode`,
`backing.thinProvisioned` and the `backing.parent` chain of a disk, and
`spec.ipRouteSpec` of a vmkernel interface.

`configManager.networkSystem` and `QueryNetworkHint` were recorded on
2026-11-23, on the same vCenter, with the same anonymisation (the host and
network system ids are the real ones): the property with the very envelope the
client sends, each hint with `govc host.vnic.hint -debug`. The switch names
keep their three observed shapes: a name with the domain of the site
(`stack01.lab.switch.example.com`), and the name of a Nexus followed by its
serial between parentheses (`nexus01.lab.example(FOC0000A0A1)`).
`QueryNetworkHint.provider.xml` comes from a host of another vCenter 6.7, whose
switches are run by a provider: its name carries the domain of the provider
(`PROVIDER-SW001.provider.example`). It is only decoded, never served.

What the hints show:

- Only CDP: the hosts have standard switches only, which offer no LLDP, so no
  `lldpInfo` was ever observed and it is not read.
- A card may hear nothing: `vmnic0` of `networkSystem-10` has no
  `connectedSwitchPort`, nor has the USB card `vusb0`.

REST (tags), vSphere 6.7 paths:

| Call | File |
|---|---|
| `POST /rest/com/vmware/cis/session` | `rest.session.json` |
| `GET /rest/com/vmware/cis/tagging/category` | `rest.category.list.json` |
| `GET /rest/com/vmware/cis/tagging/category/id:<id>` | `rest.category.<n>.json` |
| `GET /rest/com/vmware/cis/tagging/tag` | `rest.tag.list.json` |
| `GET /rest/com/vmware/cis/tagging/tag/id:<id>` | `rest.tag.<n>.json` |
| `POST /rest/com/vmware/cis/tagging/tag-association/id:<id>?~action=list-attached-objects` | `rest.tag.<n>.attached-objects.json` |
| `POST /rest/com/vmware/cis/tagging/tag-association?~action=list-attached-tags-on-objects` | `rest.attached-tags-on-objects.json` |
| `DELETE /rest/com/vmware/cis/session` | no body |

The two `POST ...?~action=list-*` calls are reads: this API has no `GET` form
for them.

The client sends the session calls, the list of tags, the read of each tag and
the list of the objects attached to it. The category calls and the grouped
`list-attached-tags-on-objects` were captured as well and are not used.

## Things the fixtures show

- `RetrievePropertiesEx.unauthenticated.xml`: without a session, vCenter 6.7
  answers `200` and an **empty result**, not a fault. An empty answer must
  therefore never be read as "this vCenter has no such object".
- `RetrievePropertiesEx.SessionManager.0.xml` and
  `RetrievePropertiesEx.SessionManager.unauthenticated.xml`: the property
  `currentSession` of the session manager is there with a session, absent
  without one. Reading it after everything else proves the session lived
  through the whole collection.
- `CreateContainerView.unauthenticated.xml`: creating a view without a session
  is a fault (`NotAuthenticated`, HTTP 500), as is a continuation token the
  server does not know (`fault.ContinueRetrievePropertiesEx.xml`,
  `InvalidArgument`).
- `rest.unauthenticated.json`: the REST API answers `401` without a session.
- The virtual machines come in two pages (`maxObjects` was 100).
- This vCenter has no distributed switch: both `DistributedVirtual*` answers
  are empty. No observed answer exists for them yet.
- `Login.xml` was anonymised before it was ever written; the session key in it
  is fictitious.
