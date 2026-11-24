# netbox-sync v1.8.0 — what the VMware source writes to NetBox

Reference inventory for the `netbox-omnisync` port. Scope: vCenter 6.7 → NetBox 4.5 to 4.7, with the
production settings listed in section 1. Everything below was established by reading the source;
the tool was not run.

- Reference: `github.com/bb-Ricardo/netbox-sync`, tag `v1.8.0`,
  commit `2e4c0f316361c497d2c77bc5f6661df26acc77d3` (`module/__init__.py:10` says `1.8.0`).
- All `path:line` citations are relative to the root of that clone.
- "Not established" means the clone does not answer the question (it depends on vSphere, on
  NetBox, or on the production deployment). These points are collected in section 22.
- NetBox version gates: the API version is read from the `API-Version` response header
  (`module/netbox/connection.py:190-212`), which NetBox 4.5 to 4.7 send (`netbox/middleware.py:89`
  in 4.5.10, `:93` in 4.6.10 and 4.7.5). Every gate of the tool compares with 4.2 or an older
  release (`module/netbox/connection.py:495`, `module/netbox/object_classes.py:1308`, `:1334`,
  `:1873`, `:1923`, `module/sources/common/source_base.py:270`, `:324`,
  `module/sources/vmware/connection.py:1128`, `:1390`, `:1870`, `:2233`, `:2240`, `:2246`, `:2321`;
  `min_netbox_version` is `0.0`, `3.7` or `4.2`), so every `>= 3.x / 4.x` branch quoted below
  is the one taken on NetBox 4.5 to 4.7; branches for older versions are not described.

## 1. Settings in effect

### 1.1 Production settings

| Option | Value | Effect (details in the sections) | Source |
|---|---|---|---|
| `permitted_subnets` | `10.0.0.0/8` (or `192.168.0.0/16`) | Only addresses inside are synced; no IPv6 can pass | `module/sources/common/permitted_subnets.py:61-117` |
| `vm_tag_source` | `object, cluster, datacenter` | vSphere tags of the VM, (cluster), datacenter become NetBox tags on VMs; also enables the REST session | `module/sources/vmware/connection.py:218-226`, `:704-761` |
| `skip_vm_templates` | `true` (also the default) | Templates are not synced | `module/sources/vmware/config.py:245-248`, `module/sources/vmware/connection.py:2108-2112` |
| `skip_vm_comments` | `false` (also the default) | `config.annotation` → VM `comments` | `module/sources/vmware/connection.py:2195-2197` |
| `track_vm_host` | `true` | VM `device` = ESXi host device | `module/sources/vmware/connection.py:2236-2237` |
| `cluster_site_relation`, `host_site_relation` | `.* = Harbor` | Constant site for clusters, hosts, VMs, VLANs | `module/sources/vmware/connection.py:448-492` |
| `cluster_tenant_relation`, `host_tenant_relation`, `vm_tenant_relation` | `.* = Example FR` | Constant tenant on clusters, devices, VMs | `module/sources/vmware/connection.py:1396-1398`, `:1671`, `:2200` |
| `host_role_relation` | `.* = Hypervisor ESX` | Device role | `module/sources/vmware/connection.py:1103-1112` |
| `vm_role_relation` | `.* = Virtual Machine ESX` | VM role | `module/sources/vmware/connection.py:1113-1114` |
| `ip_tenant_inheritance_order` | `device, prefix` (also the default) | IP tenant = device/VM tenant first | `module/sources/common/source_base.py:562-579` |
| `validate_tls_certs` | `false` (also the default) | No effect on written data | `module/sources/vmware/config.py:63-68` |

Relations are regexes applied with `re.match` (anchored at the start only); the first matching
relation wins (`module/sources/vmware/connection.py:916-948`). For cluster relations the name
tested is `<datacenter>/<cluster>`, then `<cluster>` alone (`module/sources/vmware/connection.py:926-935`).

### 1.2 Defaults that change what gets written

| Option (section) | Default | Effect | Source |
|---|---|---|---|
| `dns_name_lookup` (source) | `true` | A PTR lookup is done for every IP touched in the run; the result goes to `dns_name` (section 14.6) | `module/sources/vmware/config.py:213-218`, `module/netbox/inventory.py:392-446` |
| `set_primary_ip` (source) | `when-undefined` | `primary_ip4/6` only set when currently empty | `module/sources/vmware/config.py:223-240`, `module/sources/vmware/connection.py:1228-1236` |
| `match_host_by_serial` | `true` | Serial is a fallback identity for hosts | `module/sources/vmware/config.py:200-204`, `module/sources/vmware/connection.py:1056-1060` |
| `collect_hardware_serial` | `true` | Device `serial` is filled | `module/sources/vmware/config.py:209-212`, `module/sources/vmware/connection.py:1651-1655` |
| `collect_hardware_asset_tag` | `true` | Device `asset_tag` is filled | `module/sources/vmware/config.py:205-208`, `module/sources/vmware/connection.py:1660-1668` |
| `skip_offline_vms` | `false` | Powered-off VMs are synced (status `offline`) | `module/sources/vmware/config.py:249-255`, `module/sources/vmware/connection.py:345-348` |
| `strip_host_domain_name`, `strip_vm_domain_name` | `false` | Names are written exactly as vCenter reports them | `module/sources/vmware/config.py:261-268` |
| `set_source_name_as_cluster_group` | `false` | Cluster group = datacenter name | `module/sources/vmware/config.py:308-313`, `module/sources/vmware/connection.py:1315-1318` |
| `disable_vlan_sync` | `false` | VLANs not found in NetBox are **created** (section 16) | `module/sources/vmware/config.py:327-330`, `module/sources/common/source_base.py:944-967` |
| `overwrite_device_interface_name`, `overwrite_vm_interface_name` | `true` | A matched interface is renamed to the discovered name | `module/sources/vmware/config.py:363-372`, `module/sources/vmware/connection.py:1179-1183` |
| `overwrite_device_platform`, `overwrite_vm_platform` | `true` | Platform is overwritten on every run | `module/sources/vmware/config.py:373-382`, `module/sources/vmware/connection.py:1090-1096` |
| `host_management_interface_match` | `management, mgmt` | Selects the host primary IP (section 14.7) | `module/sources/vmware/config.py:383-387` |
| `sync_vm_interface_mtu` | `true` | VM interface `mtu` taken from the host switch | `module/sources/vmware/config.py:389-395`, `module/sources/vmware/connection.py:2475-2476` |
| `vm_disk_and_ram_in_decimal` | `true` | VM memory and disk sizes are converted to powers of 10 (sections 12, 13) | `module/sources/vmware/config.py:410-417` |
| `prune_enabled` (netbox) | `false` | Nothing orphaned is ever deleted (section 19) | `module/netbox/config.py:78-83`, `module/netbox/connection.py:763-765` |
| `prune_delay_in_days` (netbox) | `30` | Only appears in the text of the orphan tag description | `module/netbox/config.py:85-90`, `module/netbox/connection.py:560-565` |
| `ignore_unknown_source_object_pruning` (netbox) | `false` | Objects carrying `NetBox-synced` but no tag of a configured source are still orphan-tagged | `module/netbox/config.py:92-98`, `module/netbox/inventory.py:362-366` |
| `use_caching` (netbox) | `true` | Read-side cache only (`last_updated__gte`); no effect on what is written | `module/netbox/config.py:121-126`, `module/netbox/connection.py:372-550` |

## 2. Run sequence

| Step | What happens | Source |
|---|---|---|
| 1 | Sources are instantiated in config-file order; each opens its SOAP session and, because a tag source is set, its REST session | `module/sources/__init__.py:95-122`, `module/sources/vmware/connection.py:111-118` |
| 2 | All NetBox objects of the dependent types are read (tags, manufacturers, device types, platforms, cluster types/groups, device roles, sites, site groups, clusters, devices, VMs, VM interfaces, interfaces, IP addresses, prefixes, tenants, VRFs, VLANs, VLAN groups, custom fields, virtual disks, MAC addresses) | `netbox-sync.py:97-98`, `module/sources/vmware/connection.py:55-79` |
| 3 | Base tags are ensured (section 3.1) | `netbox-sync.py:106`, `module/netbox/connection.py:552-584` |
| 4 | `apply()` per source: datacenters, clusters, single-host clusters, distributed port groups, hosts, powered-on VMs, then all remaining VMs, then re-evaluation of objects with IP conflicts, then `update_basic_data()` | `module/sources/vmware/connection.py:314-415` |
| 5 | Tagging pass over the whole inventory (section 3.3) | `netbox-sync.py:114`, `module/netbox/inventory.py:311-390` |
| 6 | PTR lookups | `netbox-sync.py:117` |
| 7 | With `-n/--dry_run` the run stops here, nothing is written | `netbox-sync.py:119-122`, `module/common/cli_parser.py:51` |
| 8 | Three write passes: (a) PATCH attributes to unset, (b) POST/PATCH everything, (c) again for unresolved references, `primary_ip*`, `primary_mac_address`, and DELETE of objects flagged `deleted` | `module/netbox/connection.py:715-744`, `:648-657`, `:709-710` |
| 9 | Prune (skipped, disabled), then deletion of unused tags (section 3.5) | `netbox-sync.py:128-131` |

Write mechanics: a new object is POSTed with every key that was set; an existing object is
PATCHed with **only the keys whose value changed** (`module/netbox/connection.py:642-688`).
Object references are sent as NetBox IDs, tags as a list of `{"name": ...}`, VLAN lists as ID
lists (`module/netbox/connection.py:657`, `module/netbox/object_classes.py:1370-1383`, `:1623-1636`).
GET requests always carry `exclude=config_context` and `limit=200` (`module/netbox/connection.py:249-258`).

## 3. Generic rules that apply to every object type

### 3.1 Tags created by the tool

| Tag name | Slug at creation | Description (overwritten on every run) | Colour | Source |
|---|---|---|---|---|
| `NetBox-synced` | `netbox-synced` | `Created and used by NetBox Sync Script to keep track of created items. DO NOT change this tag, otherwise syncing can't keep track of deleted objects.` | not set | `module/netbox/__init__.py:44`, `module/netbox/connection.py:580-584` |
| `NetBox-synced: Orphaned` | `netbox-synced-orphaned` | `A source which has previously provided this object no longer states it exists. Objects would be automatically removed after 30 days but pruning is currently disabled.` | `607d8a`, only when the tag is created | `module/netbox/connection.py:50`, `:560-578` |
| `Source: <source name>` (the INI section name of the vCenter) | `source-<name>` | `Marks objects synced from vCenter '<source name>' (<host_fqdn>) to this NetBox Instance.` | not set | `module/sources/common/source_base.py:33-34`, `module/sources/vmware/connection.py:2587-2592` |
| one tag per vSphere tag name | `format_slug(name)` | `NetBox-synced: <vSphere tag description>`, or `NetBox-synced` when the vSphere description is empty | not set | `module/sources/vmware/connection.py:690-700` |

Slug rule (`format_slug`): replace space, `,` and `.` by `-`; lowercase; drop every character
outside `a-z0-9_-`; truncate (100 for tags). Dashes are not collapsed
(`module/netbox/object_classes.py:425-459`).

### 3.2 Identity of named objects, and slugs

- Lookup of an existing object goes through `get_by_data`. Its "match by slug" branch tests
  `"slug" in object_type.data_model` on the **class**, where `data_model` is the empty dict of
  the base class (`module/netbox/object_classes.py:309`); the real model is only set per
  instance (for example `module/netbox/object_classes.py:1356`). The branch is therefore never
  taken (`module/netbox/inventory.py:118-123`).
- Effective identity: the display name, compared **case-insensitively**
  (`module/netbox/inventory.py:125-137`). Display name = primary key, plus the secondary key
  in parentheses for types that have one (`module/netbox/object_classes.py:749-803`).
- For the same reason `slug_used` always answers `False`, so no `-1`, `-2` suffix is ever
  appended (`module/netbox/inventory.py:155-180`, `module/netbox/object_classes.py:461-490`).
- A slug is only written when the object has none, in practice at creation:
  `format_slug(<primary key>, 100)` (`module/netbox/object_classes.py:652-660`). The slug of an
  existing object is never modified.

| Type | Primary key | Secondary key | Source |
|---|---|---|---|
| Tag, tenant, site, manufacturer, platform, cluster type, cluster group, device role, custom field | `name` | none | `module/netbox/object_classes.py:1268-1272`, `:1348-1352`, `:1386-1390`, `:1439-1443`, `:1736-1740`, `:1771-1775`, `:1789-1793`, `:1806-1810`, `:1824-1828` |
| Device type | `model` | none (manufacturer is not part of the identity) | `module/netbox/object_classes.py:1753-1757` |
| Cluster | `name` | `site` | `module/netbox/object_classes.py:1843-1848` |
| Device | `name` | `site` | `module/netbox/object_classes.py:1890-1895` |
| VM | `name` | `cluster` | `module/netbox/object_classes.py:1931-1936` |
| Interface / VM interface / virtual disk | `name` | `device` / `virtual_machine` | `module/netbox/object_classes.py:2014-2019`, `:1970-1975`, `:2076-2081` |
| VLAN | `vid` | shown as `vid (site: <site>)`, or `vid (group: <group>)`, else `vid (<name>)` | `module/netbox/object_classes.py:1492-1548` |

### 3.3 Update semantics

| Rule | Source |
|---|---|
| A key whose new value is `None` is skipped: a value that disappears in vCenter is **never cleared** in NetBox | `module/netbox/object_classes.py:560-563` |
| String fields are truncated to the model length before comparison (lengths are given per type below) | `module/netbox/object_classes.py:568-575` |
| A change of the primary key that is only a change of letter case is ignored | `module/netbox/object_classes.py:710-712` |
| Numeric fields are compared as floats (`4` equals `4.0`) | `module/netbox/object_classes.py:693-700` |
| Choice fields returned by NetBox as `{"value": ...}` are compared on `value` | `module/netbox/object_classes.py:675-677` |
| `custom_fields` is merged: keys sent by the tool overwrite, all other keys are kept | `module/netbox/object_classes.py:683-687` |
| `tags` passed in object data are only **added** to the current list | `module/netbox/object_classes.py:606-609`, `:932-1011` |
| `tagged_vlans` replaces the whole list when provided | `module/netbox/object_classes.py:611-613`, `:1082-1125` |
| A nested dict (`{"name": ...}`) is resolved to an existing object by the identity of 3.2, or the object is created | `module/netbox/object_classes.py:639-647`, `module/netbox/inventory.py:213-246` |

### 3.4 Tagging pass: who gets `NetBox-synced` and `Source: <name>`

Every inventory object that has a `source` after `apply()` receives both tags, and loses the
orphan tag if it had it (`module/netbox/inventory.py:336-347`). An object gets a `source` when
it is created/updated with `source=self`, or when it is **referenced** by such an update
(`module/netbox/object_classes.py:646-647`). The source is only set once: with several
vCenters in one run, a shared object keeps the first source that touched it
(`module/netbox/object_classes.py:741-747`).

| Object | Tagged? | Why | Source |
|---|---|---|---|
| Cluster group, cluster, device, VM, interface, VM interface, virtual disk, IP address, MAC address | yes | written with `source=self` | `module/sources/vmware/connection.py:1341`, `:1444-1446`, `:1087-1098`, `:1142-1148`, `module/sources/common/source_base.py:319-322`, `:355-359`, `:584-591` |
| Cluster type, site, tenant, platform, device type, VLAN (also a pre-existing one that is merely referenced) | yes | referenced by a sourced update | `module/netbox/object_classes.py:646-647`, `module/sources/common/source_base.py:682-683` |
| Manufacturer | yes | explicit | `module/netbox/object_classes.py:1166-1167` |
| VRF | yes, although the type is read-only | the IP update references it; tags are added outside the read-only check | `module/sources/common/source_base.py:576-577`, `module/netbox/object_classes.py:646-647`, `:541-542`, `:1013-1048` |
| Device role | **no** | the role is set by an `update()` call without `source` | `module/sources/vmware/connection.py:1112-1114` |
| Prefix, VLAN group, site group | no | never referenced in written data | `module/sources/common/source_base.py:542-579` |
| Tag, custom field | no | no `tags` field in their model | `module/netbox/object_classes.py:1287-1298`, `:1356-1362` |

Objects **without** a source in this run (present in NetBox, not seen/touched):

| Condition | Action | Source |
|---|---|---|
| has a tag of a source that is configured but `enabled = false` | untouched | `module/netbox/inventory.py:353-356` |
| does not carry `NetBox-synced` | untouched | `module/netbox/inventory.py:359-360` |
| carries `NetBox-synced` and at least one `Source: <configured source>` tag | **all configured source tags are removed** | `module/netbox/inventory.py:362-364` |
| type not prunable (cluster, cluster group, cluster type, site, tenant, platform, device type, manufacturer, device role, VLAN, VRF…) | orphan tag removed if present; nothing else | `module/netbox/inventory.py:368-371` |
| prunable type (device, VM, interface, VM interface, virtual disk, IP address, MAC address) | `NetBox-synced: Orphaned` is added | `module/netbox/inventory.py:390`, `module/netbox/object_classes.py:1896`, `:1937`, `:1977`, `:2021`, `:2083`, `:2102`, `:2225` |
| IP address whose device/VM status is not `active` | not orphan-tagged (orphan tag removed), but its source tags were already removed by the rule above | `module/netbox/inventory.py:373-388` |

### 3.5 Preservation of foreign tags, and tag deletion

- Tags on an object that the tool did not put there are kept: the new list is "new tags +
  current tags" and the whole list is sent (`module/netbox/object_classes.py:996-1001`).
- On devices and VMs only: a tag currently on the object whose **description starts with**
  `NetBox-synced` and whose name is not in the tag list computed in this run is removed. This
  is how a detached vSphere tag disappears. Any hand-made tag with such a description is
  removed the same way (`module/sources/vmware/connection.py:1116-1125`).
- After the write passes, a tag is deleted from NetBox when its description starts with
  `NetBox-synced`, its `tagged_items` (value read at the start of the run) is `0`, and it was
  not attached to anything in this run (`module/netbox/connection.py:917-936`,
  `module/netbox/object_classes.py:984-986`). The tag list is not re-read: the type is already
  marked as resolved (`module/netbox/connection.py:415-417`, `:713`).

## 4. Tag (from vSphere tags)

`vm_tag_source = object, cluster, datacenter`; `host_tag_source` and `cluster_tag_source` are
unset, so only VMs receive vSphere tags (`module/sources/vmware/connection.py:724-734`).

| Tag source | How the vSphere object is found | Source |
|---|---|---|
| `object` | the VM itself | `module/sources/vmware/connection.py:738-739` |
| `cluster` | first `vim.ClusterComputeResource`, then first `vim.ComputeResource`, found by walking `VM.parent` upwards (max 20 levels) | `module/sources/vmware/connection.py:749-755`, `:1240-1267` |
| `datacenter` | first `vim.Datacenter` found by walking `VM.parent` upwards | `module/sources/vmware/connection.py:756-759` |

- The `cluster` lookup starts from the VM's own `parent` attribute, not from `runtime.host`.
  That chain never reaches a cluster: the parent of a machine is a folder of the `vm` tree, whose
  ancestors are folders and the datacenter (60 folders in the recorded vCenter 6.7, none under a
  cluster), and a machine of a vApp has no `parent` at all. `cluster` therefore contributed no
  tag in netbox-sync. netbox-omnisync takes the cluster of `runtime.host` (see
  `reference-defects.md`).
- Mapping: NetBox tag `name` = vSphere tag name (truncated to 100); `description` as in 3.1
  (truncated to 200). The vSphere category is ignored
  (`module/sources/vmware/connection.py:684-700`, `module/netbox/object_classes.py:1356-1362`).
- Identity: tag name, case-insensitive (3.2). Two vSphere tags with the same name map to one
  NetBox tag whose description is overwritten by each of them in turn
  (`module/sources/vmware/connection.py:697-700`).
- If the `vsphere-automation-sdk` import fails, or the REST login fails, tag sync is silently
  off for the run: no tag is added and, by 3.5, existing vSphere-derived tags are removed from
  VMs (`module/sources/vmware/connection.py:228-230`, `:256-260`, `:733-734`, `:1116-1125`).

## 5. Custom field

| Name | Type | Label | Description | Object type | Value | Source |
|---|---|---|---|---|---|---|
| `host_cpu_cores` | `text` | `Physical CPU Cores` | `Reported Host CPU cores` | `dcim.device` | `"<summary.hardware.numCpuCores> <summary.hardware.cpuModel>"` | `module/sources/vmware/connection.py:795-808` |
| `host_memory` | `text` | `Memory` | `Reported size of Memory` | `dcim.device` | `round(summary.hardware.memorySize / 1024**3)` followed by ` GB`; when that number is ≥ 1024 it is divided by 1024 (float, e.g. `1.5`) and followed by ` TB` | `module/sources/vmware/connection.py:810-826` |

- Identity: field name, case-insensitive. If the field exists, only `object_types` is updated,
  by appending; type, label and description are creation-only
  (`module/sources/common/source_base.py:969-996`, `module/netbox/object_classes.py:1301-1338`).
- No custom field is created or filled on VMs, interfaces or cluster groups in this
  configuration (`module/sources/vmware/connection.py:780-791`, `:859`, `:1327-1339`).

## 6. Cluster group

| NetBox field | vSphere source | Transformation | Source |
|---|---|---|---|
| `name` | `Datacenter.name` | stripped; truncated to 100 | `module/sources/vmware/connection.py:1318-1325`, `module/netbox/object_classes.py:1814-1820` |
| `slug` | — | creation only, `format_slug(name)` | `module/netbox/object_classes.py:652-660` |

Identity: name, case-insensitive (`module/sources/vmware/connection.py:1341`). One group per datacenter.

## 7. Cluster type

A single cluster type named `VMware ESXi` (slug `vmware-esxi` at creation) is referenced by
every cluster; identity by name (`module/sources/vmware/connection.py:1384-1388`).

## 8. Cluster

Built from every `vim.ClusterComputeResource` and every `vim.ComputeResource` (a standalone
host is a cluster named after the compute resource) (`module/sources/vmware/connection.py:319-326`).

| NetBox field | vSphere source | Transformation | Source |
|---|---|---|---|
| `name` | `ComputeResource.name` | stripped; truncated to 100 | `module/sources/vmware/connection.py:1354`, `:1385`, `module/netbox/object_classes.py:1858` |
| `type` | constant | `VMware ESXi` | `module/sources/vmware/connection.py:1386` |
| `group` | parent `Datacenter` (walk of `parent`) | the cluster group of section 6; a cluster without datacenter is skipped | `module/sources/vmware/connection.py:1358-1361`, `:1387` |
| `scope_type` / `scope_id` | `cluster_site_relation` on `<datacenter>/<cluster>` | `dcim.site` / site `Harbor` | `module/sources/vmware/connection.py:1382`, `:1390-1392` |
| `tenant` | `cluster_tenant_relation` | `Example FR` | `module/sources/vmware/connection.py:1396-1398` |

Identity (`module/sources/vmware/connection.py:1405-1446`): among NetBox clusters with exactly
the same name (case-sensitive here), take the first one whose site equals the computed site,
else whose group name equals the datacenter name, else whose tenant name equals the computed
tenant; if none qualifies, the first cluster with that name; otherwise create. All fields are
overwritten on every run.

## 9. Site, tenant, device role

None of these gets any attribute other than `name` (and `slug` at creation).

| Object | When it is created | Identity | Remarks | Source |
|---|---|---|---|---|
| Site `Harbor` | if no site has that name | name, case-insensitive | gets the two sync tags (3.4) | `module/sources/vmware/connection.py:1391`, `:1688`, `:2234` |
| Tenant `Example FR` | if no tenant has that name | name, case-insensitive | gets the two sync tags | `module/sources/vmware/connection.py:1398`, `:1701`, `:2254` |
| Device role `Hypervisor ESX`, `Virtual Machine ESX` | if no role has that name | name, case-insensitive | created with name and slug only (no colour, no `vm_role`); not tagged | `module/sources/vmware/connection.py:1112-1114`, `module/netbox/object_classes.py:1920-1928` |
| Device role `Server` | never created here | — | **if a role named `Server` exists, `vm_role` is forced to `true` on every run** | `module/sources/vmware/connection.py:2605-2612` |
| Site `vCenter: <source name>` | never created here (the site relation always matches) | — | if such a site exists, its `comments` are overwritten | `module/sources/vmware/connection.py:105`, `:2594-2603` |

## 10. Manufacturer, device type, platform

| Object | Field | Source value | Transformation | Source |
|---|---|---|---|---|
| Manufacturer | `name` | `HostSystem.summary.hardware.vendor`, or `Generic Vendor` when empty | normalised by the first matching case-insensitive regex of the mapping table (`.*Dell.*` → `Dell`, `^HP$`/`^HPE$` → `HPE`, `.*Cisco.*` → `Cisco`, `.*Lenovo.*`/`LEN` → `Lenovo`, `.*Supermicro.*` → `Supermicro`, `.*Fujitsu.*`/`FTS Corp` → `Fujitsu`, `.*Huawei.*` → `Huawei`, `.*Intel.*` → `Intel`, …); otherwise unchanged | `module/sources/vmware/connection.py:1619`, `:1630-1631`, `module/netbox/manufacturer_mapping.py:32-55`, `:66-75` |
| Device type | `model` | `HostSystem.summary.hardware.model`, or `Generic Model` when empty | truncated to 100 | `module/sources/vmware/connection.py:1620`, `:1632-1633`, `module/netbox/object_classes.py:1762` |
| Device type | `manufacturer` | the manufacturer above | overwritten on every run | `module/sources/vmware/connection.py:1682-1687` |
| Platform (host) | `name` | `"<summary.config.product.name> <summary.config.product.version>"`, e.g. `VMware ESXi 6.7.0` | truncated to 100 | `module/sources/vmware/connection.py:1621-1626`, `:1698-1699` |
| Platform (VM) | `name` | see section 12.2 | truncated to 100 | `module/sources/vmware/connection.py:2178-2191`, `:2249-2250` |

- Manufacturer identity: an existing manufacturer whose `slug` equals
  `format_slug(normalised name, 50)`; if found, its `name` is overwritten with the normalised
  name. Otherwise by name (case-insensitive), otherwise created
  (`module/netbox/object_classes.py:1127-1169`, `module/netbox/inventory.py:139-151`).
- Device type identity: `model` alone, case-insensitive (3.2).
- Platform identity: name, case-insensitive. The slug is written **only at creation**, as
  `format_slug(name, 100)`: `VMware ESXi 6.7.0` → `vmware-esxi-6-7-0`,
  `CentOS 7 (64-bit)` → `centos-7-64-bit`. An existing platform keeps whatever slug it has.
  No other platform field (manufacturer, description) is written
  (`module/netbox/object_classes.py:425-459`, `:652-660`, `:1778-1785`).

## 11. Device (ESXi host)

Built from every `vim.HostSystem`. A host is skipped when its cluster is unknown, or when a
host with the same name was already processed for the same site (warning)
(`module/sources/vmware/connection.py:1566-1608`).

### 11.1 Field mapping

| NetBox field | vSphere property | Transformation | Source |
|---|---|---|---|
| `name` | `name` | stripped; domain kept; truncated to 64 | `module/sources/vmware/connection.py:1553-1556`, `module/netbox/object_classes.py:1902` |
| `device_type` | section 10 | | `module/sources/vmware/connection.py:1682-1687` |
| `site` | `host_site_relation` on the host name | `Harbor` | `module/sources/vmware/connection.py:1597`, `:1688` |
| `cluster` | parent `ClusterComputeResource`, else `ComputeResource` | NetBox cluster of section 8 | `module/sources/vmware/connection.py:1566-1583`, `:1689` |
| `status` | `summary.runtime.connectionState` | `connected` → `active`, anything else → `offline` | `module/sources/vmware/connection.py:1635-1638` |
| `serial` | `summary.hardware.otherIdentifyingInfo[]` | first present of the identifier types `SerialNumberTag`, `ServiceTag`, `EnclosureSerialNumberTag` (key = `identifierType.key`, value stripped; for a repeated key the last entry wins); truncated to 50 | `module/sources/vmware/connection.py:1641-1655`, `module/netbox/object_classes.py:1907` |
| `asset_tag` | same list, identifier type `AssetTag` | dropped when it equals, case-insensitively, one of `Default string`, `NA`, `N/A`, `None`, `Null`, `oem`, `o.e.m`, `to be filled by o.e.m.`, `Unknown`; truncated to 50 | `module/sources/vmware/connection.py:1658-1668` |
| `platform` | section 10 | | `module/sources/vmware/connection.py:1698-1699` |
| `tenant` | `host_tenant_relation` | `Example FR` | `module/sources/vmware/connection.py:1671`, `:1700-1701` |
| `role` | `host_role_relation` | `Hypervisor ESX` (sent as `role`) | `module/sources/vmware/connection.py:1105-1112`, `module/netbox/object_classes.py:1922-1926` |
| `custom_fields` | section 5 | `host_cpu_cores`, `host_memory` | `module/sources/vmware/connection.py:1706-1708` |
| `primary_ip4`, `primary_ip6` | section 14.7 | only when empty | `module/sources/vmware/connection.py:1228-1236` |
| `tags` | — | no vSphere tag (no host tag source); sync tags per 3.4 | `module/sources/vmware/connection.py:1674-1677`, `:1702-1703` |

### 11.2 Identity, in order

| Step | Rule | Source |
|---|---|---|
| 1 | `"<name> (<site name>)"` equal, case-insensitive, using the untruncated vCenter name | `module/sources/vmware/connection.py:1035`, `module/netbox/inventory.py:125-137` |
| 2 | MAC addresses of the **physical** NICs against the `mac_address` of all NetBox device interfaces: a single device with matches is taken; with several, the best one is taken only if it has at least twice the matches of the second | `module/sources/vmware/connection.py:1047-1051`, `:494-590` |
| 3 | exact `serial` | `module/sources/vmware/connection.py:1056-1060` |
| 4 | exact `asset_tag` | `module/sources/vmware/connection.py:1062-1066` |
| 5 | a device whose primary IPv4 or IPv6 (without mask) equals the computed primary IP | `module/sources/vmware/connection.py:1082`, `:592-650` |
| 6 | otherwise the device is created | `module/sources/vmware/connection.py:1084-1087` |

A device found by steps 2–5 is updated with all fields, so it is renamed and re-sited
(`module/sources/vmware/connection.py:1098`).

netbox-omnisync does step 2 in the reconciliation, among the devices it holds for the source
only (`design.md`, "A renamed device or virtual machine", and `reference-defects.md`); steps
3 to 5 are not done.

## 12. Virtual machine

### 12.1 Which VMs are synced

| Case | Behaviour | Source |
|---|---|---|
| No `config.instanceUuid` | skipped | `module/sources/vmware/connection.py:2098-2101` |
| Template (`config.template` true) | skipped; an existing NetBox VM for it is handled as orphaned (3.4) | `module/sources/vmware/connection.py:2108-2112` |
| Two passes | pass 1 handles only `runtime.powerState == poweredOn`; pass 2 handles the rest. A given `instanceUuid` is handled once | `module/sources/vmware/connection.py:335-342`, `:2119-2125` |
| Host, cluster or datacenter of the VM cannot be resolved (`runtime.host` → parents) | skipped with an error | `module/sources/vmware/connection.py:2127-2148` |
| Duplicate name | a second VM with the same name in the same `<datacenter>/<cluster>` is skipped with a warning. Powered-on VMs win because they are processed first | `module/sources/vmware/connection.py:2150-2163` |
| Same name in two clusters | two distinct NetBox VMs (identity includes the cluster) | `module/netbox/object_classes.py:1935-1936` |
| Powered off | synced with `status = offline`; IP handling is skipped (section 14.1) | `module/sources/vmware/connection.py:2106`, `module/sources/common/source_base.py:363-367` |
| VMware Tools not running (`guest.toolsRunningStatus != guestToolsRunning`) | VM and interfaces are synced; no IP is added, moved or removed; no primary IP is set. Its previously synced IPs are untouched in this run and therefore fall under 3.4: they lose `Source: <name>`, and get the orphan tag when the VM is `active` | `module/sources/common/source_base.py:363-375`, `:595-598`, `module/netbox/inventory.py:351-390` |

### 12.2 Field mapping

| NetBox field | vSphere property | Transformation | Source |
|---|---|---|---|
| `name` | `name` | stripped; truncated to 64 | `module/sources/vmware/connection.py:2088-2091`, `module/netbox/object_classes.py:1941` |
| `cluster` | `runtime.host` → parent `ClusterComputeResource`, else `ComputeResource` | NetBox cluster | `module/sources/vmware/connection.py:2127-2143`, `:2225` |
| `site` | scope site of that NetBox cluster | `Harbor` | `module/sources/vmware/connection.py:2174-2176`, `:2233-2234` |
| `device` | `runtime.host` | NetBox device created for that host in this run; left unchanged if the host was not synced | `module/sources/vmware/connection.py:2236-2237`, `module/netbox/object_classes.py:560-563` |
| `status` | `runtime.powerState` | `poweredOn` → `active`, else `offline` | `module/sources/vmware/connection.py:2106` |
| `memory` | `config.hardware.memoryMB` | `int(memoryMB / 1024 * 1000)` (4096 → 4000) | `module/sources/vmware/connection.py:2218-2221` |
| `vcpus` | `config.hardware.numCPU` | none | `module/sources/vmware/connection.py:2228` |
| `serial` | `config.instanceUuid` | none | `module/sources/vmware/connection.py:2246-2247` |
| `platform` | see below | | `module/sources/vmware/connection.py:2178-2191` |
| `comments` | `config.annotation` | stripped; not written when empty (so never cleared) | `module/sources/vmware/connection.py:2195-2197`, `:2251-2252` |
| `tenant` | `vm_tenant_relation` | `Example FR` | `module/sources/vmware/connection.py:2200`, `:2253-2254` |
| `role` | `vm_role_relation` | `Virtual Machine ESX` | `module/sources/vmware/connection.py:1113-1114` |
| `tags` | section 4 | added; stale vSphere-derived tags removed (3.5) | `module/sources/vmware/connection.py:2203-2215`, `:2255-2256` |
| `primary_ip4`, `primary_ip6` | section 14.7 | only when empty | `module/sources/vmware/connection.py:1228-1236` |
| `disk` | — | not written (NetBox ≥ 3.7); see virtual disks | `module/sources/vmware/connection.py:2239-2243` |

Platform name of a VM, last rule that yields a value wins
(`module/sources/vmware/connection.py:2178-2191`):

1. `config.guestFullName`;
2. `guest.guestFullName` when it is set (reported by VMware Tools);
3. if `config.extraConfig` has a key `guestOS.detailed.data`: its `prettyName='…'` element.
   The value is split on commas outside quotes after replacing `' ` by `', `, and the
   element starting with `prettyName` is taken without the `prettyName='` prefix and without
   surrounding quotes (`module/common/misc.py:200-226`).

The result is not normalised further. The platform is overwritten on every run, so it follows
the Tools state. Slug rules: section 10.

### 12.3 Identity, in order

| Step | Rule | Source |
|---|---|---|
| 1 | `"<name> (<cluster name>)"` equal, case-insensitive (untruncated vCenter name) | `module/sources/vmware/connection.py:1035`, `module/netbox/inventory.py:125-137` |
| 2 | MAC addresses of the virtual NICs against the `mac_address` of all NetBox VM interfaces, same majority rule as for hosts | `module/sources/vmware/connection.py:1047-1051`, `:494-590` |
| 3 | exact `serial` (= `instanceUuid`) | `module/sources/vmware/connection.py:1068-1071` |
| 4 | primary IP | `module/sources/vmware/connection.py:1082` |
| 5 | otherwise the VM is created | `module/sources/vmware/connection.py:1084-1087` |

A VM found by steps 2–4 is renamed and moved to the new cluster (`module/sources/vmware/connection.py:1098`).

netbox-omnisync does step 2 in the reconciliation, among the machines of the same cluster it
holds for the source only; steps 3 and 4 are not done, and a machine is never moved to
another cluster this way.

## 13. Virtual disk

One per `vim.vm.device.VirtualDisk` in `config.hardware.device`.

| NetBox field | vSphere property | Transformation | Source |
|---|---|---|---|
| `name` | `deviceInfo.label` (e.g. `Hard disk 1`) | truncated to 64 | `module/sources/vmware/connection.py:2333`, `module/netbox/object_classes.py:2087` |
| `size` (MB) | `capacityInKB` | `int(int(capacityInKB / 1024) / 1024 * 1000)` (40 GiB → 40000) | `module/sources/vmware/connection.py:2320-2330` |
| `description` | `backing.diskMode`, `backing.thinProvisioned`, `fileName` of the root backing (following `backing.parent`) | joined with ` / `: disk mode capitalised with `_` → `-` (e.g. `Persistent`), then `ThinProvisioned` or `ThickProvisioned`, then the file name; truncated to 200 | `module/sources/vmware/connection.py:2303-2318`, `:2335` |
| `virtual_machine` | — | the VM | `module/sources/vmware/connection.py:1142-1143` |

Identity is positional: existing disks sorted by name and discovered disks sorted by name
(string order, so `Hard disk 10` sorts before `Hard disk 2`) are paired one by one; a pair is
updated in place, an extra discovered disk is created, an extra existing disk is **deleted**
(real `DELETE`, even with pruning off). Nothing happens when the VM reports no disk
(`module/sources/vmware/connection.py:1127-1148`, `module/netbox/connection.py:709-710`).

## 14. IP address

### 14.1 Where addresses come from

| Owner | vSphere property | Format handed on | Source |
|---|---|---|---|
| Host vmkernel | `config.network.vnic[].spec.ip.ipAddress` and `.subnetMask` | `<ip>/<dotted mask>`, normalised to `<ip>/<len>` | `module/sources/vmware/connection.py:2033-2036`, `module/sources/common/source_base.py:378-382`, `:542-545` |
| Host vmkernel, IPv6 | `spec.ip.ipV6Config.ipV6Address[].ipAddress` / `.prefixLength` | `<ip>/<len>` | `module/sources/vmware/connection.py:2041-2046` |
| VM | `guest.net[]` entries whose `macAddress` equals the MAC of a virtual NIC: `ipConfig.ipAddress[].ipAddress` / `.prefixLength` | `<ip>/<len>` | `module/sources/vmware/connection.py:2432-2451` |

Guest NICs whose MAC matches no virtual NIC (bridges, containers) are ignored
(`module/sources/vmware/connection.py:2435-2436`, `:2512`). For a VM, all IP handling is
skipped unless `guest.toolsRunningStatus == guestToolsRunning`
(`module/sources/common/source_base.py:363-375`).

### 14.2 `permitted_subnets`

In order: unparsable → rejected; link-local → rejected; loopback → rejected; inside an
excluded (`!`) subnet → rejected; inside a listed subnet → accepted; otherwise rejected
(`module/sources/common/permitted_subnets.py:83-117`). With only an IPv4 subnet listed, every
IPv6 address is rejected, so no IPv6 address and no `primary_ip6` is ever written.

### 14.3 Prefix and VRF

- The prefix is the longest NetBox prefix containing the address among prefixes scoped to the
  site of the device (for a VM: the scope site of its cluster), or scoped to the site group of
  that site; on equal length the last one in inventory order wins
  (`module/sources/common/source_base.py:284-289`, `:214-231`, `module/netbox/object_classes.py:1685-1710`).
- The intended fallback to "any prefix" is called without a site, and `matches_site(None)`
  returns `False` for every prefix: the fallback never finds anything. A prefix that is not
  scoped to the site (or its group) is invisible to the tool
  (`module/sources/common/source_base.py:396-398`, `:217-220`, `module/netbox/object_classes.py:1699-1710`).
- Prefixes are read-only: never created, modified or tagged (`module/netbox/object_classes.py:1639-1645`).
- VRF: if the matched prefix has a VRF, the IP's `vrf` is set to it (overwritten on every
  run); otherwise `vrf` is not sent, so never cleared (`module/sources/common/source_base.py:417`, `:576-577`).
- A mismatch between the prefix length and the address mask only logs a warning
  (`module/sources/common/source_base.py:411-415`).

### 14.4 Identity of an existing IP address

Candidates are all NetBox IPs whose `address` starts with `<ip>/` (the mask is ignored), in
inventory order (`module/sources/common/source_base.py:444-451`):

| Order | Situation of the candidate | Decision | Source |
|---|---|---|---|
| 1 | already assigned to this interface | reuse | `module/sources/common/source_base.py:456-459` |
| 2 | its `vrf` differs from the prefix VRF (including "one is empty") | warning, try the next candidate | `module/sources/common/source_base.py:465-477` |
| 3 | not assigned to any interface | reuse | `module/sources/common/source_base.py:479-482` |
| 4 | assigned to another interface of the same device/VM | reuse (the IP moves) | `module/sources/common/source_base.py:484-487` |
| 5 | assigned to an enabled interface of an active object, and this interface is disabled | this IP is not synced | `module/sources/common/source_base.py:489-502` |
| 6 | the other interface is disabled or its object is not active, and this interface is enabled | take it over, unless its role is `anycast` (then not synced); the scan does not stop here, a later candidate can still replace it or cancel the sync | `module/sources/common/source_base.py:504-515` |
| 7 | both enabled or both disabled | not synced now; the vSphere object is re-evaluated once at the end of the run, and if still tied the IP is skipped with a warning | `module/sources/common/source_base.py:517-537`, `module/sources/vmware/connection.py:403-413` |
| — | no candidate retained | a new IP address is created | `module/sources/common/source_base.py:581-584` |

For a VM, an IP currently on a sub-interface whose `parent` is this interface stays on the
sub-interface (`module/sources/common/source_base.py:547-560`).

### 14.5 Field mapping

| NetBox field | Value | Overwritten on every run? | Source |
|---|---|---|---|
| `address` | `<ip>/<len>` in compressed form, with the mask reported by vSphere | yes (the mask of a reused IP is rewritten) | `module/sources/common/source_base.py:542-545` |
| `assigned_object_type` / `assigned_object_id` | `dcim.interface` or `virtualization.vminterface` / the interface | yes | `module/sources/common/source_base.py:544`, `module/netbox/object_classes.py:2147-2160` |
| `tenant` | first non-empty of: tenant of the device/VM, tenant of the matched prefix. Here the device/VM tenant is always set, so always `Example FR` | yes | `module/sources/common/source_base.py:312-313`, `:562-579` |
| `vrf` | VRF of the matched prefix | only when the prefix has one | `module/sources/common/source_base.py:576-577` |
| `dns_name` | PTR record, section 14.6 | only when a record is found | `module/netbox/inventory.py:440-444` |

`status`, `role` and `description` are never written (`module/sources/common/source_base.py:542-579`).

An IP currently assigned in NetBox to an interface but no longer reported for it is
**unassigned** (`assigned_object_*` set to null), not deleted; if it was a primary IP, the
primary IP is unset first. Anycast addresses are left alone. The same unset of the primary IP
happens when an IP moves to another device/VM
(`module/sources/common/source_base.py:595-608`, `module/netbox/object_classes.py:2167-2176`, `:2205-2218`).

### 14.6 `dns_name`

For every IP address touched in the run, a reverse lookup is made with the system resolver
(`custom_dns_servers` unset). The name is written lower-cased when it only contains
`a-z0-9-.`; otherwise, or without a record, `dns_name` is left as it is
(`module/netbox/inventory.py:403-444`, `module/common/support.py:47-115`).

### 14.7 Primary IP

| Object | Candidate | Source |
|---|---|---|
| Host, IPv4 | The first vmkernel interface, in `config.network.vnic` order, that is "primary" and whose IPv4 is permitted. "Primary" = its description (section 15.2) contains `management` or `mgmt`, case-insensitive, **or** `spec.ipRouteSpec` is set | `module/sources/vmware/connection.py:2020-2039` |
| Host, IPv6 | first permitted IPv6 of a "primary" vmkernel interface | `module/sources/vmware/connection.py:2041-2052` |
| VM, IPv4 | default gateway = `gateway.ipAddress` of the last route with `prefixLength == 0` in `guest.ipStack[0].ipRouteConfig.ipRoute`; the candidate is the first permitted address (virtual NIC order, then guest NIC order, then address order) whose network contains that gateway | `module/sources/vmware/connection.py:2268-2289`, `:2453-2459` |
| VM, IPv6 | same with the IPv6 default route; then, if exactly one permitted IPv6 exists on the whole VM, that one replaces it | `module/sources/vmware/connection.py:2461-2465`, `:2552-2570` |

The candidate is applied only if it was actually synced on an interface in this run (same
address and mask) and the object's `primary_ip4`/`primary_ip6` is currently empty. A primary
IP changed by hand in NetBox is never corrected
(`module/sources/vmware/connection.py:1196-1200`, `:1228-1236`). It is written in the last
write pass (`module/netbox/connection.py:652-655`).

## 15. Interfaces

### 15.1 Host physical NICs (`config.network.pnic[]`)

| NetBox field | vSphere property | Transformation | Source |
|---|---|---|---|
| `name` | `device` (e.g. `vmnic0`) | URL-unquoted; truncated to 64 | `module/sources/vmware/connection.py:1781`, `:1856` |
| MAC | `mac` | upper case; see section 17 | `module/sources/vmware/connection.py:1839`, `module/common/support.py:19-44` |
| `enabled` | `linkSpeed` | `true` when a link speed object is present (link up) | `module/sources/vmware/connection.py:1859` |
| `type` | speed in Mb/s: `linkSpeed.speedMb`, else `spec.linkSpeed.speedMb`, else `validLinkSpecification[0].speedMb` | 100 → `100base-tx`, 1000 → `1000base-t`, 2500 → `2.5gbase-t`, 5000 → `5gbase-t`, 10000 → `10gbase-x-sfpp`, 25000 → `25gbase-x-sfp28`, 40000 → `40gbase-x-qsfpp`, 50000 → `50gbase-x-sfp28`, 100000 → `100gbase-x-qsfp28`, 200000 → `200gbase-x-qsfp56`, 400000 → `400gbase-x-qsfpdd`, anything else or no speed → `other` | `module/sources/vmware/connection.py:1786-1790`, `:1861`, `module/netbox/object_classes.py:64-76`, `:90-93`, `:179-193` |
| `speed` | same speed | `speedMb * 1000` (kbit/s); not sent without a speed | `module/sources/vmware/connection.py:1871-1872` |
| `duplex` | `linkSpeed.duplex`, same fallbacks | `true` → `full`, `false` → `half` | `module/sources/vmware/connection.py:1792-1796`, `:1873-1874` |
| `mtu` | `mtu` of the `config.network.vswitch[]` or `config.network.proxySwitch[]` whose `pnic` list contains this NIC's `key` | none | `module/sources/vmware/connection.py:1712-1744`, `:1813-1825`, `:1864-1865` |
| `description` | built | `"<N>Gb/s "` (speed ≥ 1000, integer division) or `"<N>Mb/s "` or empty, then `" pNIC"` (so two spaces after the speed, or one leading space without speed), then `" (<vSwitch name>)"` and/or `" (<dvSwitch name>)"`, then `" (conn: <systemName or devId> - <portId>)"` from the network hint; URL-unquoted; truncated to 200 | `module/sources/vmware/connection.py:1799-1806`, `:1816`, `:1824`, `:1841-1848`, `:1860` |
| `mode` | switch membership and port groups | `tagged-all` when the NIC is an uplink of a distributed switch. Then, if standard port groups list this NIC in their active or standby NIC order: `access` when all their VLAN IDs are 0, `tagged-all` when one is 4095, otherwise `tagged` | `module/sources/vmware/connection.py:1827`, `:1829-1837`, `:1876-1884` |
| `tagged_vlans` | those port groups, mode `tagged` only | one VLAN per port group with VLAN ID ≠ 0: name = port group name, `vid` = `spec.vlanId`, site = host site | `module/sources/vmware/connection.py:1886-1906` |

The switch-port hint comes from `configManager.networkSystem.QueryNetworkHint`; failures are
ignored (`module/sources/vmware/connection.py:1771-1777`).

netbox-omnisync does not write the hint into the description: it asks for it
only when the run also reads switches, and tells it to the cable step of the
network family, as the neighbour of the switch port (README, "Cables a host
hears"). A host whose hint fails is a warning.

### 15.2 Host vmkernel interfaces (`config.network.vnic[]`)

| NetBox field | vSphere property | Transformation | Source |
|---|---|---|---|
| `name` | `device` (e.g. `vmk0`) | URL-unquoted | `module/sources/vmware/connection.py:1918`, `:1970` |
| MAC | `spec.mac` | upper case | `module/sources/vmware/connection.py:1972` |
| `enabled` | constant | `true` | `module/sources/vmware/connection.py:1973` |
| `mtu` | `spec.mtu` | none | `module/sources/vmware/connection.py:1974` |
| `type` | constant | `virtual` | `module/sources/vmware/connection.py:1975` |
| `description`, `mode`, VLANs | see below | | `module/sources/vmware/connection.py:1930-2016` |

| Attachment | `description` | `mode` | VLAN | Source |
|---|---|---|---|---|
| Standard port group (`vnic.portgroup` found in `config.network.portgroup[].spec.name`) | `"<port group> (<vSwitch>, vlan ID: <id>)"` | `access` | if the ID ≠ 0: `untagged_vlan` named `"ESXi <port group> (ID: <id>) (<site>)"` | `module/sources/vmware/connection.py:1934-1939`, `:1986-1994` |
| Distributed port group (`spec.distributedVirtualPort.portgroupKey`), single ID 4095 | `"<dv port group> (<dvSwitch>, all vlans)"` | `tagged-all` | none | `module/sources/vmware/connection.py:1942-1949`, `:1961-1966` |
| Distributed port group, single ID 0 | `"<dv port group> (<dvSwitch>, vlan ID: 0)"` | `access` | none | `module/sources/vmware/connection.py:1951-1957` |
| Distributed port group, any other case (including **one** VLAN ID) | `"… vlan ID: <id>)"`, or `"… vlan IDs: <a>, <b-c>)"` for a trunk | `tagged` | `tagged_vlans`, one per ID ≠ 0, named `"<dv port group>-<id>"` | `module/sources/vmware/connection.py:1951-1959`, `:1996-2016` |
| Neither found | none | none | none | `module/sources/vmware/connection.py:1930-1931`, `:1978-1984` |

The `(<dvSwitch>, …)` part is only added when the host's proxy switch with
`spec.distributedVirtualPort.switchUuid` is known (`module/sources/vmware/connection.py:1961-1966`).

Distributed port groups are read once from `vim.dvs.DistributedVirtualPortgroup`
(`key`, `name`, `config.defaultPortConfig.vlan`): a trunk spec gives the list of IDs and
ranges (the range `0-4094` is recorded as the single ID 4095); a private VLAN spec gives
`pvlanId` and the flag "private"; otherwise `vlanId`
(`module/sources/vmware/connection.py:1481-1527`).

### 15.3 VM interfaces (`config.hardware.device[]` of type `VirtualEthernetCard`)

| NetBox field | vSphere property | Transformation | Source |
|---|---|---|---|
| `name` | `deviceInfo.label` and the network name | `"vNIC <last word of the label>"`, plus `" (<network name>)"` when a network name is known, e.g. `vNIC 1 (VM Network)`; URL-unquoted; truncated to 64 | `module/sources/vmware/connection.py:2404-2410`, `:2468` |
| network name | standard: `backing.deviceName`; distributed: name of the port group with key `backing.port.portgroupKey` | none for any other backing | `module/sources/vmware/connection.py:2365-2389` |
| MAC | `macAddress` | upper case | `module/sources/vmware/connection.py:2346` |
| `enabled` | `connectable.connected`, replaced by `guest.net[].connected` of the guest NIC with the same MAC | default `false` | `module/sources/vmware/connection.py:2403`, `:2438`, `:2472` |
| `mtu` | standard: `mtu` of the vSwitch of the port group on the VM's host; distributed: `mtu` of the host proxy switch `backing.port.switchUuid` | only when found | `module/sources/vmware/connection.py:2371-2380`, `:2397-2401`, `:2475-2476` |
| `description` | `deviceInfo.label`, device class, VLAN IDs | `"<label> (<class>)"`, e.g. `Network adapter 1 (VirtualVmxnet3)`, plus `" (vlan ID: <ids or ranges, comma separated>)"` or `" (all vlans)"`, with `" (private)"` inside for a private VLAN; truncated to 200 | `module/sources/vmware/connection.py:2412-2429`, `:2471` |
| `mode` | VLAN IDs of the port group | single 4095 → `tagged-all`; exactly one ID (0 included) → `access`; several → `tagged`; unknown network → not sent | `module/sources/vmware/connection.py:2413-2424`, `:2477-2478` |
| `untagged_vlan` | one ID ≠ 0 | VLAN named after the network, site = cluster site | `module/sources/vmware/connection.py:2480-2490` |
| `tagged_vlans` | several IDs | one VLAN per ID ≠ 0 named `"<network>-<id>"` | `module/sources/vmware/connection.py:2491-2507` |

### 15.4 Matching discovered interfaces to existing ones

Per device/VM, for each discovered interface, first match wins
(`module/sources/common/source_base.py:128-163`):

1. an existing interface with the same name;
2. same MAC and same class (virtual vs. physical, from `type`);
3. same MAC, any class, if not already matched.

Discovered interfaces still unmatched and existing interfaces still unmatched are then both
sorted by name and paired in order; a paired existing interface is **renamed** and reused.
Remaining discovered interfaces are created; remaining existing interfaces are not touched
and fall under 3.4 (orphan tag, no deletion) (`module/sources/common/source_base.py:165-180`).
Host physical and vmkernel interfaces are matched in one set (`module/sources/vmware/connection.py:1150-1157`).

All interface fields listed above are overwritten on every run when provided; `mtu`, `mode`,
`untagged_vlan` and `tagged_vlans` are not cleared when they stop being reported (3.3).

## 16. VLAN and VLAN group

Resolution of each VLAN wanted by an interface (`module/sources/common/source_base.py:610-683`):

| Step | Rule | Source |
|---|---|---|
| 1 | If a prefix matched by one of the interface's IPs has a VLAN: it becomes the untagged VLAN when the interface reported no untagged VLAN or the same VLAN ID. This also applies to an interface that reported **no VLAN at all**. It also replaces a tagged VLAN with the same ID | `module/sources/common/source_base.py:622-637`, `:641`, `:650-656` |
| 2 | Otherwise an existing NetBox VLAN with the same `vid`, scanned in inventory order: the scan stops at the first VLAN that is at the object's site **or** whose VLAN group is scoped to that site, its site group, the cluster or its cluster group, whichever NetBox returned first; else the last one with neither site nor group | `module/sources/common/source_base.py:873-918` |
| 3 | Otherwise a new VLAN is created, except for ID 4095 and IDs ≥ 4096 | `module/sources/common/source_base.py:920-967` |
| 4 | When the untagged VLAN was resolved and the interface has no `mode`, `mode` is set to `access` | `module/sources/common/source_base.py:654-658` |

| NetBox field of a created VLAN | Value | Source |
|---|---|---|
| `vid` | the VLAN ID | `module/sources/vmware/connection.py:1899`, `:1990`, `:2009`, `:2486`, `:2500` |
| `name` | the names given in sections 15.1–15.3; truncated to 64 | `module/netbox/object_classes.py:1504` |
| `site` | site of the host / of the VM's cluster | `module/sources/vmware/connection.py:1900-1902`, `:2487-2489` |

- An existing VLAN is never modified: its name is kept, no tenant, group or description is
  written. It only receives the sync tags (`module/netbox/object_classes.py:1550-1556`, 3.4).
- VLAN groups are read-only; none is created or assigned (no group relation configured)
  (`module/netbox/object_classes.py:1559-1565`, `module/sources/common/source_base.py:776-817`).

## 17. MAC address (NetBox ≥ 4.2)

`mac_address` is removed from the interface payload and handled as a separate object
(`module/sources/common/source_base.py:268-273`, `:324-361`).

| Step | Rule | Source |
|---|---|---|
| 1 | Existing interface: reuse its primary MAC object if the address is equal, else one of its assigned MAC objects with that address. Every other MAC object assigned to the interface is **unassigned** | `module/sources/common/source_base.py:335-344` |
| 2 | Else reuse the first MAC object in NetBox with that address and no assignment | `module/sources/common/source_base.py:347-352` |
| 3 | Else create one | `module/sources/common/source_base.py:355-357` |
| 4 | The interface's `primary_mac_address` is set to it (last write pass) | `module/sources/common/source_base.py:361`, `module/netbox/connection.py:652-655` |

Fields written: `mac_address` (upper case, colon separated), `assigned_object_type`,
`assigned_object_id` (`module/sources/common/source_base.py:327-331`). Unassigned MAC objects
are not deleted; they fall under 3.4.

## 18. Object types not written by the VMware source

Inventory items and power ports are not part of the VMware source at all (not in its
dependent object list): `module/sources/vmware/connection.py:55-79`. Prefixes, VLAN groups and
site groups are only read: `module/netbox/object_classes.py:1458-1464`, `:1559-1565`, `:1639-1645`.

## 19. Orphans and deletion

- Orphan tagging: section 3.4. In short, a device, VM, interface, VM interface, virtual disk,
  IP address or MAC address that carries `NetBox-synced` and was not touched in the run loses
  its `Source: <name>` tags and gets `NetBox-synced: Orphaned`; the tag is removed again as
  soon as the object is seen (`module/netbox/inventory.py:343-347`, `:351-390`).
- Deletion: `prune_enabled` is `false`, so no orphan is deleted, whatever its age
  (`module/netbox/connection.py:763-765`). (When enabled, deletion would happen once
  `last_updated` is at least `prune_delay_in_days` old: `module/netbox/connection.py:789-846`.)
- The only deletions made in this configuration are surplus virtual disks (section 13) and
  unused vSphere-derived tags (section 3.5).

## 20. vSphere API usage

### 20.1 SOAP (pyVmomi)

The tool does no explicit property collection: it creates one container view per type on
`rootFolder` (recursive) and reads properties lazily, object by object
(`module/sources/vmware/connection.py:366-401`). A client that wants the same data in few calls
needs one property retrieval per type with the property paths below.

| Managed object type | Properties read | Source |
|---|---|---|
| Session | `sessionManager.currentSession.key` before each view | `module/sources/vmware/connection.py:352-360` |
| `Datacenter` | `name` | `module/sources/vmware/connection.py:1318` |
| `ClusterComputeResource`, `ComputeResource` (two separate views) | `name`, `parent` (walked up to the `Datacenter`) | `module/sources/vmware/connection.py:1354-1358`, `:1240-1267` |
| `Folder` | `parent` (walk only) | `module/sources/vmware/connection.py:1257` |
| `dvs.DistributedVirtualPortgroup` | `key`, `name`, `config.defaultPortConfig.vlan` | `module/sources/vmware/connection.py:1491-1520` |
| `HostSystem` | `name`, `parent`, `summary.hardware.vendor`, `.model`, `.otherIdentifyingInfo`, `.numCpuCores`, `.cpuModel`, `.memorySize`, `summary.config.product.name`, `.version`, `summary.runtime.connectionState`, `config.network.vswitch`, `.proxySwitch`, `.portgroup`, `.pnic`, `.vnic`, `availableField`, `configManager.networkSystem` | `module/sources/vmware/connection.py:1553-1646`, `:795-797`, `:828`, `:1712-1779`, `:1916` |
| `HostNetworkSystem` (one call per host) | method `QueryNetworkHint` | `module/sources/vmware/connection.py:1774` |
| `VirtualMachine` (view iterated twice) | `name`, `parent`, `config.instanceUuid`, `config.template`, `config.guestFullName`, `config.extraConfig`, `config.annotation`, `config.hardware.device`, `.memoryMB`, `.numCPU`, `runtime.powerState`, `runtime.host`, `guest.guestFullName`, `guest.ipStack`, `guest.net`, `guest.toolsRunningStatus`, `availableField` | `module/sources/vmware/connection.py:2088-2228`, `:2269`, `:2432`, `:828`, `module/sources/common/source_base.py:365` |

### 20.2 REST (vSphere Automation SDK, tagging)

| Call (SDK name) | When | Source |
|---|---|---|
| `create_vsphere_client(server, username, password, session)` | once per source | `module/sources/vmware/connection.py:249-254` |
| `tagging.TagAssociation.list_attached_tags(DynamicID(type, id))` | once per VM for the VM, once per VM for its datacenter, and for the cluster if found; no cache | `module/sources/vmware/connection.py:674-675`, `:738-759` |
| `tagging.Tag.get(tag_id)` | **twice** per attached tag (name, then description); no cache | `module/sources/vmware/connection.py:684-685` |

The HTTP endpoints behind these SDK calls are not in the clone: not established (section 22).

## 21. Disabled here

Present in v1.8.0 but inactive with the production settings; not described above.

- Include/exclude filters for clusters, hosts and VMs; `vm_exclude_by_tag_filter`.
- `host_tag_source`, `cluster_tag_source`, tag sources `parent_folder_1` / `parent_folder_2`.
- `cluster_tag_relation`, `host_tag_relation`, `vm_tag_relation`.
- `host_platform_relation`, `vm_platform_relation`.
- `sync_custom_attributes` (`vcsa_*` custom fields), `custom_attribute_exclude`,
  `host_custom_object_attributes`, `vm_custom_object_attributes`.
- `set_source_name_as_cluster_group` (and its `vcsa_datacenter_name` custom field).
- `sync_vm_dummy_interfaces` (`vNIC Dummy-…` interfaces).
- `disable_vlan_sync`, `vlan_sync_exclude_by_name`, `vlan_sync_exclude_by_id`,
  `vlan_group_relation_by_name`, `vlan_group_relation_by_id`.
- `host_nic_exclude_by_mac_list`.
- `skip_offline_vms`, `skip_srm_placeholder_vms`.
- `strip_host_domain_name`, `strip_vm_domain_name`.
- `custom_dns_servers`.
- `set_primary_ip = always` / `never`; `overwrite_*` set to `false`; `sync_vm_interface_mtu = false`.
- `ip_tenant_inheritance_order = disabled`; the `<NONE>` site keyword.
- `proxy_host` / `proxy_port`.
- Pruning (`prune_enabled`), `ignore_unknown_source_object_pruning`, the `--purge` mode.
- The default site `vCenter: <name>` and the default role `Server` as assigned values.
- The `check_redfish` source (inventory items, power ports, hardware details).
- Code paths for NetBox older than 4.2.

## 22. Not established

1. How the three vCenters are run in production: one configuration with three sources, or
   three separate runs. With separate runs, objects of the other vCenters carry `NetBox-synced`
   but no tag of a configured source and are orphan-tagged (3.4).
2. Whether the `vsphere-automation-sdk` is installed in production. Without it no vSphere tag
   is synced (section 4).
3. (Established since: walking `VirtualMachine.parent` never reaches a cluster, section 4.)
4. Whether a container view on `vim.ComputeResource` also returns cluster objects (the tool
   handles both views with the same idempotent handler).
5. Whether vCenter 6.7 exposes `guestOS.detailed.data` in `config.extraConfig` (third platform
   rule, section 12.2).
6. The HTTP endpoints and payloads behind the REST SDK calls, and the SOAP requests pyVmomi
   emits for lazy property access.
7. (Established since: NetBox 4.5 to 4.7 return `mac_address` on interfaces,
   `dcim/api/serializers_/device_components.py:253` in 4.5.10 and 4.6.10, `:350` in 4.7.5, and
   `virtualization/api/serializers_/virtualmachines.py:103`, `:136`, `:137`; the MAC-based
   matching of devices, VMs and interfaces reads that attribute, sections 11.2, 12.3, 15.4.)
8. The order in which NetBox returns objects: it decides every "first one wins" tie
   (clusters with the same name, equal-length prefixes, IP candidates, unassigned MAC objects).
9. Whether NetBox trims the leading/double spaces of the physical NIC description (15.1).
10. The DNS resolver seen by the production host, which determines `dns_name`.
