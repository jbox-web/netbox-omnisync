//! The collection, against the recorded answers of real clusters.
//!
//! Every expected value below was read in `tests/fixtures/<version>/api.json`
//! (the line is quoted above the assertion) or comes from the requirements;
//! none was copied from what the code returns.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use omnisync_proxmox::{
    ClientError, CollectError, Container, ContainerInterface, Credentials, Disk, DiskBus, GuestAddress, GuestInterface,
    GuestNic, GuestNics, GuestOsInfo, NodeNetwork, NodeVlan, ProxmoxClient, ProxmoxCluster, Vm, collect,
};
use serde_json::{Value, json};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;

use omnisync_proxmox::neighbors::{CardNeighbor, read_neighbors};

use common::{API, Answers, Delay, Pace, TICKET, client, collected, fixture, serve, serve_as};

const TOKEN: &str = "sync@pve!netbox=0b0e0f00-0000-4000-8000-000000000001";

/// (method, API path) of every request the mock received, in order of arrival.
async fn received(server: &MockServer) -> Vec<(String, String)> {
    let requests = server.received_requests().await.unwrap();
    requests
        .iter()
        .map(|request| {
            let api_path = request.url.path().strip_prefix(API).unwrap_or(request.url.path());
            (request.method.to_string(), api_path.to_owned())
        })
        .collect()
}

fn vms(cluster: &ProxmoxCluster) -> Vec<&Vm> {
    cluster.nodes.iter().flat_map(|node| &node.vms).collect()
}

fn vm(cluster: &ProxmoxCluster, node: &str, vmid: u64) -> Vm {
    let node = cluster.nodes.iter().find(|candidate| candidate.name == node).unwrap();
    node.vms.iter().find(|candidate| candidate.vmid == vmid).unwrap().clone()
}

fn network(cluster: &ProxmoxCluster, node: &str, name: &str) -> NodeNetwork {
    let node = cluster.nodes.iter().find(|candidate| candidate.name == node).unwrap();
    node.networks.iter().find(|candidate| candidate.name == name).unwrap().clone()
}

fn disk(bus: DiskBus, index: u32, name: &str, size_mib: u64) -> Disk {
    Disk { bus, index, name: name.to_owned(), size_mib, cdrom: false }
}

fn cdrom(bus: DiskBus, index: u32, name: &str, size_mib: u64) -> Disk {
    Disk { bus, index, name: name.to_owned(), size_mib, cdrom: true }
}

fn interface(name: &str, mac: &str, addresses: &[(&str, &str, u8)]) -> GuestInterface {
    let addresses = addresses
        .iter()
        .map(|(address, family, prefix)| GuestAddress {
            address: (*address).to_owned(),
            family: (*family).to_owned(),
            prefix: *prefix,
        })
        .collect();
    GuestInterface { name: name.to_owned(), mac: Some(mac.to_owned()), addresses }
}

/// A network card on `vmbr0` whose VLAN is `tag`, as every `netN` line of the 9.2 fixture.
fn nic(key: &str, mac: &str, tag: u16) -> GuestNic {
    GuestNic {
        key: key.to_owned(),
        mac: mac.to_owned(),
        bridge: Some("vmbr0".to_owned()),
        tag: Some(tag),
        trunks: vec![],
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// What each node of a cluster holds, for the counts read in the fixtures.
#[derive(Debug, PartialEq)]
struct NodeCounts {
    name: &'static str,
    cpus: u64,
    memory_total_bytes: u64,
    networks: usize,
    vms: usize,
    containers: usize,
}

fn node_counts(cluster: &ProxmoxCluster) -> Vec<(String, u64, u64, usize, usize, usize)> {
    cluster
        .nodes
        .iter()
        .map(|node| {
            let sizes = (node.networks.len(), node.vms.len(), node.containers.len());
            (node.name.clone(), node.cpus, node.memory_total_bytes, sizes.0, sizes.1, sizes.2)
        })
        .collect()
}

fn expected_counts(nodes: &[NodeCounts]) -> Vec<(String, u64, u64, usize, usize, usize)> {
    nodes
        .iter()
        .map(|node| {
            (node.name.to_owned(), node.cpus, node.memory_total_bytes, node.networks, node.vms, node.containers)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The whole collection of each fixture
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_8_4_cluster_is_collected_whole() {
    let cluster = collected(fixture("8.4")).await;

    // "/version": "data": { "release": "8.4", "version": "8.4.21" }
    assert_eq!(cluster.version.version, "8.4.21");
    assert_eq!(cluster.version.release, "8.4");
    assert_eq!(cluster.version.major(), Some(8));
    // "/cluster/status": { "id": "cluster", "name": "pve-cluster-a", "nodes": 3, …, "type": "cluster" }
    assert_eq!(cluster.name, "pve-cluster-a");

    // "/nodes" lists pve03, pve02, pve01 in that order: the result is sorted by name.
    // "/nodes/pve01/status": "cpuinfo": { "cores": 16, "cpus": 32, "sockets": 2 }, "memory": { "total": 236538687488 }
    // "/nodes/pve02/status": "cpus": 32, "memory": { "total": 270393266176 }
    // "/nodes/pve03/status": "cpus": 32, "memory": { "total": 270361522176 }
    // "/nodes/pve01/network" has 17 entries, pve02 19, pve03 17 (9 bonds, 9 bridges, 20 eth, 15 vlans in all).
    // "/nodes/pve01/qemu" has 29 entries, pve02 25, pve03 11; every "/nodes/<node>/lxc" is "data": [].
    assert_eq!(
        node_counts(&cluster),
        expected_counts(&[
            NodeCounts {
                name: "pve01",
                cpus: 32,
                memory_total_bytes: 236_538_687_488,
                networks: 17,
                vms: 29,
                containers: 0
            },
            NodeCounts {
                name: "pve02",
                cpus: 32,
                memory_total_bytes: 270_393_266_176,
                networks: 19,
                vms: 25,
                containers: 0
            },
            NodeCounts {
                name: "pve03",
                cpus: 32,
                memory_total_bytes: 270_361_522_176,
                networks: 17,
                vms: 11,
                containers: 0
            },
        ])
    );

    let vms = vms(&cluster);
    assert_eq!(vms.len(), 65);
    // "template": 1 on five entries of "/nodes/pve01/qemu": 111, 115, 132, 150 and 156.
    let templates: Vec<u64> = vms.iter().filter(|vm| vm.template).map(|vm| vm.vmid).collect();
    assert_eq!(templates, [111, 115, 132, 150, 156]);
    // "status": "running" on 18 entries of pve01, 20 of pve02 and 9 of pve03; the 18 others are "stopped".
    assert_eq!(vms.iter().filter(|vm| vm.is_running()).count(), 47);
    assert_eq!(vms.iter().filter(|vm| vm.status == "stopped").count(), 18);
    // 47 ".../agent/network-get-interfaces" entries, of which 2 have "status": 500 (pve02, 151 and 153).
    assert_eq!(vms.iter().filter(|vm| vm.interfaces.is_some()).count(), 45);
    // Unknown interfaces: the 18 stopped VMs and the 2 whose agent answered 500.
    assert_eq!(vms.iter().filter(|vm| vm.interfaces.is_none()).count(), 20);
    // 47 ".../agent/get-osinfo" entries, of which the same 2 have "status": 500 and 5 are
    // "result": {"error": {"class": "CommandNotFound", ...}}: an agent too old for the command.
    assert_eq!(vms.iter().filter(|vm| vm.os_info.is_some()).count(), 40);
    // Every one of those 40 carries a "pretty-name".
    let named = vms.iter().filter(|vm| vm.os_info.as_ref().is_some_and(|os| os.pretty_name.is_some())).count();
    assert_eq!(named, 40);
    // The 45 answers list 444 interfaces, 37 of them named "lo".
    let interfaces: usize = vms.iter().filter_map(|vm| vm.interfaces.as_ref()).map(Vec::len).sum();
    assert_eq!(interfaces, 444 - 37);
}

#[tokio::test]
async fn the_9_2_cluster_is_collected_whole() {
    let cluster = collected(fixture("9.2")).await;

    // "/version": "data": { "release": "9.2", "version": "9.2.11" }
    assert_eq!(cluster.version.version, "9.2.11");
    assert_eq!(cluster.version.release, "9.2");
    assert_eq!(cluster.version.major(), Some(9));
    // "/cluster/status": { "id": "cluster", "name": "pve-cluster-b", "nodes": 2, …, "type": "cluster" }
    assert_eq!(cluster.name, "pve-cluster-b");

    // "/nodes/pve01/status": "cpuinfo": { "cores": 16, "cpus": 32, "sockets": 2 }, "memory": { "total": 270357209088 }
    // "/nodes/pve02/status": "cpuinfo": { "cores": 28, "cpus": 56, "sockets": 2 }, "memory": { "total": 540888895488 }
    // "/nodes/pve01/network" has 18 entries, pve02 17; "/nodes/pve01/qemu" and "/nodes/pve02/qemu" 9 each.
    assert_eq!(
        node_counts(&cluster),
        expected_counts(&[
            NodeCounts {
                name: "pve01",
                cpus: 32,
                memory_total_bytes: 270_357_209_088,
                networks: 18,
                vms: 9,
                containers: 0
            },
            NodeCounts {
                name: "pve02",
                cpus: 56,
                memory_total_bytes: 540_888_895_488,
                networks: 17,
                vms: 9,
                containers: 0
            },
        ])
    );

    let vms = vms(&cluster);
    assert_eq!(vms.len(), 18);
    // "template": 1 on 100 and 101 of pve01, and on 111, 114 and 115 of pve02.
    let templates: Vec<u64> = vms.iter().filter(|vm| vm.template).map(|vm| vm.vmid).collect();
    assert_eq!(templates, [100, 101, 111, 114, 115]);
    // "status": "running" on 7 entries of pve01 and 6 of pve02; the 5 templates are "stopped".
    assert_eq!(vms.iter().filter(|vm| vm.is_running()).count(), 13);
    // 13 ".../agent/network-get-interfaces" entries, all "status": 200.
    assert_eq!(vms.iter().filter(|vm| vm.interfaces.is_some()).count(), 13);
    assert_eq!(vms.iter().filter(|vm| vm.interfaces.is_none()).count(), 5);
    // 13 ".../agent/get-osinfo" entries, all "status": 200, of which 4 are
    // "result": {"error": {"class": "CommandNotFound", ...}}.
    assert_eq!(vms.iter().filter(|vm| vm.os_info.is_some()).count(), 9);
    let named = vms.iter().filter(|vm| vm.os_info.as_ref().is_some_and(|os| os.pretty_name.is_some())).count();
    assert_eq!(named, 9);
    // The 13 answers list 38 interfaces, 13 of them named "lo".
    let interfaces: usize = vms.iter().filter_map(|vm| vm.interfaces.as_ref()).map(Vec::len).sum();
    assert_eq!(interfaces, 38 - 13);
    // The 18 ".../config" entries hold 28 "netN" keys (10 VMs have "net0" and "net1", 8 "net0" alone),
    // each "virtio=<MAC>,bridge=vmbr0,tag=<10 or 11>": 13 "tag=10", 15 "tag=11".
    let nics: Vec<&GuestNic> = vms.iter().flat_map(|vm| &vm.nics.read).collect();
    assert_eq!(nics.len(), 28);
    assert_eq!(nics.iter().filter(|nic| nic.tag == Some(10)).count(), 13);
    assert_eq!(nics.iter().filter(|nic| nic.tag == Some(11)).count(), 15);
    assert!(nics.iter().all(|nic| nic.bridge.as_deref() == Some("vmbr0") && nic.trunks.is_empty()));
    assert!(vms.iter().all(|vm| vm.nics.unread.is_empty()));
}

// ---------------------------------------------------------------------------
// A few guests, field by field
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_running_linux_vm_of_8_4_field_by_field() {
    let cluster = collected(fixture("8.4")).await;
    // "/nodes/pve01/qemu": { "cpus": 4, "maxdisk": 26843545600, "maxmem": 8589934592,
    //   "name": "vm001.example", "status": "running", "vmid": 107 }  (no "tags", no "template")
    // "/nodes/pve01/qemu/107/config": "ostype": "l26",
    //   "virtio0": "store2:vm-disk-0.qcow2,size=25G", "virtio1": "store2:vm-disk-1.qcow2,size=20G"
    // "/nodes/pve01/qemu/107/agent/network-get-interfaces": "result": [
    //   { "hardware-address": "00:00:00:00:00:00", …, "name": "lo" },
    //   { "hardware-address": "02:00:00:00:00:32", "ip-addresses": [
    //       { "ip-address": "198.18.0.3", "ip-address-type": "ipv4", "prefix": 26 },
    //       { "ip-address": "fe80::30", "ip-address-type": "ipv6", "prefix": 64 } ], "name": "ens18" } ]
    // "/nodes/pve01/qemu/107/agent/get-osinfo": "result": { "id": "debian",
    //   "kernel-release": "5.10.0-35-amd64", "machine": "x86_64", "name": "Debian GNU/Linux",
    //   "pretty-name": "Debian GNU/Linux 11 (bullseye)", "version": "11 (bullseye)", "version-id": "11" }
    assert_eq!(
        vm(&cluster, "pve01", 107),
        Vm {
            vmid: 107,
            name: "vm001.example".to_owned(),
            status: "running".to_owned(),
            template: false,
            cpus: 4,
            max_memory_bytes: 8_589_934_592,
            tags: vec![],
            os_type: Some("l26".to_owned()),
            // 25G = 25 * 1024 MiB, 20G = 20 * 1024 MiB.
            disks: vec![
                disk(DiskBus::Virtio, 0, "store2:vm-disk-0.qcow2", 25_600),
                disk(DiskBus::Virtio, 1, "store2:vm-disk-1.qcow2", 20_480),
            ],
            // No "netN" key: the 8.4 fixture was recorded without them.
            nics: GuestNics::default(),
            interfaces: Some(vec![interface(
                "ens18",
                "02:00:00:00:00:32",
                &[("198.18.0.3", "ipv4", 26), ("fe80::30", "ipv6", 64)]
            )]),
            os_info: Some(GuestOsInfo {
                id: Some("debian".to_owned()),
                name: Some("Debian GNU/Linux".to_owned()),
                pretty_name: Some("Debian GNU/Linux 11 (bullseye)".to_owned()),
                version: Some("11 (bullseye)".to_owned()),
                version_id: Some("11".to_owned()),
                kernel_release: Some("5.10.0-35-amd64".to_owned()),
                machine: Some("x86_64".to_owned()),
            }),
        }
    );
}

#[tokio::test]
async fn a_stopped_windows_vm_of_8_4_field_by_field() {
    let cluster = collected(fixture("8.4")).await;
    // "/nodes/pve01/qemu": { "cpus": 4, "maxdisk": 107374182400, "maxmem": 17179869184,
    //   "name": "vm024.example", "status": "stopped", "vmid": 167 }
    // "/nodes/pve01/qemu/167/config": "ide0": "store1:vm-disk-1.qcow2,size=100G",
    //   "ide2": "store1:Win11_French_x64.iso,media=cdrom,size=5384344K", "ostype": "win11"
    // No ".../qemu/167/agent/..." entry: the VM is stopped.
    assert_eq!(
        vm(&cluster, "pve01", 167),
        Vm {
            vmid: 167,
            name: "vm024.example".to_owned(),
            status: "stopped".to_owned(),
            template: false,
            cpus: 4,
            max_memory_bytes: 17_179_869_184,
            tags: vec![],
            os_type: Some("win11".to_owned()),
            // 100G = 102400 MiB; 5384344K / 1024 = 5258.14 MiB, rounded down.
            disks: vec![
                disk(DiskBus::Ide, 0, "store1:vm-disk-1.qcow2", 102_400),
                cdrom(DiskBus::Ide, 2, "store1:Win11_French_x64.iso", 5258),
            ],
            // No "netN" key: the 8.4 fixture was recorded without them.
            nics: GuestNics::default(),
            interfaces: None,
            os_info: None,
        }
    );
}

#[tokio::test]
async fn a_running_vm_of_8_4_whose_agent_fails_field_by_field() {
    let cluster = collected(fixture("8.4")).await;
    // "/nodes/pve02/qemu": { "cpus": 4, "maxdisk": 85899345920, "maxmem": 8589934592,
    //   "name": "vm053.example", "status": "running", "vmid": 151 }
    // "/nodes/pve02/qemu/151/config": "ide0": "none,media=cdrom", "ide2": "none,media=cdrom",
    //   "ostype": "win11", "scsi0": "store1:vm-disk-0.raw,size=80G"
    // "/nodes/pve02/qemu/151/agent/network-get-interfaces": { "body": { "data": null, "message": "error" }, "status": 500 }
    // "/nodes/pve02/qemu/151/agent/get-osinfo": { "body": { "data": null, "message": "error" }, "status": 500 }
    assert_eq!(
        vm(&cluster, "pve02", 151),
        Vm {
            vmid: 151,
            name: "vm053.example".to_owned(),
            status: "running".to_owned(),
            template: false,
            cpus: 4,
            max_memory_bytes: 8_589_934_592,
            tags: vec![],
            os_type: Some("win11".to_owned()),
            // 80G = 81920 MiB; the two empty CD-ROM drives have no size.
            disks: vec![disk(DiskBus::Scsi, 0, "store1:vm-disk-0.raw", 81_920)],
            // No "netN" key: the 8.4 fixture was recorded without them.
            nics: GuestNics::default(),
            interfaces: None,
            os_info: None,
        }
    );
}

#[tokio::test]
async fn a_tagged_docker_host_of_8_4() {
    let cluster = collected(fixture("8.4")).await;
    let host = vm(&cluster, "pve02", 141);
    // "/nodes/pve02/qemu": { "cpus": 16, …, "maxmem": 8589934592, "name": "vm042.example",
    //   "status": "running", "tags": "service-oom", "vmid": 141 }
    assert_eq!((host.name.as_str(), host.cpus, host.max_memory_bytes), ("vm042.example", 16, 8_589_934_592));
    assert_eq!(host.tags, ["service-oom"]);
    // "/nodes/pve02/qemu/141/config": "ide2": "store1:debian-12.9.0-amd64-netinst.iso,media=cdrom,size=632M",
    //   "scsi0": "store2:vm-disk-1.qcow2,size=70G", "scsi1": "store2:vm-disk-0.qcow2,size=50G"
    assert_eq!(
        host.disks,
        [
            disk(DiskBus::Scsi, 0, "store2:vm-disk-1.qcow2", 71_680),
            disk(DiskBus::Scsi, 1, "store2:vm-disk-0.qcow2", 51_200),
            cdrom(DiskBus::Ide, 2, "store1:debian-12.9.0-amd64-netinst.iso", 632),
        ]
    );
    // ".../141/agent/network-get-interfaces" lists 31 interfaces: "lo", "ens18", eight "br-…",
    // "docker0" (seventh) and 21 "veth…" (hardware addresses …:aa to …:be).
    let interfaces = host.interfaces.unwrap();
    assert_eq!(interfaces.len(), 30);
    // { "hardware-address": "02:00:00:00:00:a1", "ip-addresses": [
    //   { "ip-address": "198.18.0.70", "ip-address-type": "ipv4", "prefix": 26 },
    //   { "ip-address": "fe80::96", "ip-address-type": "ipv6", "prefix": 64 } ], "name": "ens18" }
    assert_eq!(
        interfaces[0],
        interface("ens18", "02:00:00:00:00:a1", &[("198.18.0.70", "ipv4", 26), ("fe80::96", "ipv6", 64)])
    );
    // The order of the agent is kept: "docker0" is the sixth once "lo" is left out.
    // { "hardware-address": "02:00:00:00:00:a6", "ip-addresses": [
    //   { "ip-address": "198.18.2.1", "ip-address-type": "ipv4", "prefix": 16 },
    //   { "ip-address": "fe80::9b", "ip-address-type": "ipv6", "prefix": 64 } ], "name": "docker0" }
    assert_eq!(
        interfaces[5],
        interface("docker0", "02:00:00:00:00:a6", &[("198.18.2.1", "ipv4", 16), ("fe80::9b", "ipv6", 64)])
    );
    // { "hardware-address": "02:00:00:00:00:be", "ip-addresses": [
    //   { "ip-address": "fe80::b3", "ip-address-type": "ipv6", "prefix": 64 } ], "name": "veth75354c3" }
    assert_eq!(interfaces[29], interface("veth75354c3", "02:00:00:00:00:be", &[("fe80::b3", "ipv6", 64)]));
    // "/nodes/pve01/qemu": { …, "tags": "service-docker;service-seeq-queue", "vmid": 164 }
    assert_eq!(vm(&cluster, "pve01", 164).tags, ["service-docker", "service-seeq-queue"]);
}

#[tokio::test]
async fn a_running_vm_of_9_2_field_by_field() {
    let cluster = collected(fixture("9.2")).await;
    // "/nodes/pve01/qemu": { "cpus": 8, "maxdisk": 16106127360, "maxmem": 17179869184,
    //   "name": "vm002.example", "status": "running", "tags": "tag-1;service-apache;tag-2", "vmid": 105 }
    // "/nodes/pve01/qemu/105/config": "ide1": "store1:vm-105-cloudinit.raw,media=cdrom,size=4M",
    //   "ostype": "l26", "scsi0": "store1:vm-disk-0.qcow2,size=15G"
    // "/nodes/pve01/qemu/105/agent/network-get-interfaces": "result": [ { …, "name": "lo" },
    //   { "hardware-address": "02:00:00:00:00:08", "ip-addresses": [
    //       { "ip-address": "198.18.0.177", "ip-address-type": "ipv4", "prefix": 24 },
    //       { "ip-address": "fe80::7", "ip-address-type": "ipv6", "prefix": 64 } ], "name": "eth0" },
    //   { "hardware-address": "02:00:00:00:00:09", "ip-addresses": [
    //       { "ip-address": "198.18.1.177", "ip-address-type": "ipv4", "prefix": 24 },
    //       { "ip-address": "fe80::8", "ip-address-type": "ipv6", "prefix": 64 } ], "name": "eth1" } ]
    // "/nodes/pve01/qemu/105/agent/get-osinfo": "data": { "result": {} }
    assert_eq!(
        vm(&cluster, "pve01", 105),
        Vm {
            vmid: 105,
            name: "vm002.example".to_owned(),
            status: "running".to_owned(),
            template: false,
            cpus: 8,
            max_memory_bytes: 17_179_869_184,
            tags: strings(&["tag-1", "service-apache", "tag-2"]),
            os_type: Some("l26".to_owned()),
            // 15G = 15360 MiB; the cloud-init drive is a 4 MiB CD-ROM.
            disks: vec![
                disk(DiskBus::Scsi, 0, "store1:vm-disk-0.qcow2", 15_360),
                cdrom(DiskBus::Ide, 1, "store1:vm-105-cloudinit.raw", 4),
            ],
            // "net0": "virtio=02:00:00:00:00:08,bridge=vmbr0,tag=10",
            // "net1": "virtio=02:00:00:00:00:09,bridge=vmbr0,tag=11"
            nics: GuestNics {
                read: vec![nic("net0", "02:00:00:00:00:08", 10), nic("net1", "02:00:00:00:00:09", 11)],
                unread: vec![],
            },
            interfaces: Some(vec![
                interface("eth0", "02:00:00:00:00:08", &[("198.18.0.177", "ipv4", 24), ("fe80::7", "ipv6", 64)]),
                interface("eth1", "02:00:00:00:00:09", &[("198.18.1.177", "ipv4", 24), ("fe80::8", "ipv6", 64)]),
            ]),
            // "result": {"error": {"class": "CommandNotFound", ...}}: the agent does not
            // know the command, which says nothing of the system.
            os_info: None,
        }
    );
}

#[tokio::test]
async fn a_template_of_9_2_field_by_field() {
    let cluster = collected(fixture("9.2")).await;
    // "/nodes/pve02/qemu": { "cpus": 4, "maxdisk": 26843545600, "maxmem": 4294967296,
    //   "name": "vm013.example", "status": "stopped", "template": 1, "vmid": 114 }  (no "tags")
    // "/nodes/pve02/qemu/114/config": "ostype": "l26", "virtio0": "store1:vm-disk-0.qcow2,size=25G"
    assert_eq!(
        vm(&cluster, "pve02", 114),
        Vm {
            vmid: 114,
            name: "vm013.example".to_owned(),
            status: "stopped".to_owned(),
            template: true,
            cpus: 4,
            max_memory_bytes: 4_294_967_296,
            tags: vec![],
            os_type: Some("l26".to_owned()),
            disks: vec![disk(DiskBus::Virtio, 0, "store1:vm-disk-0.qcow2", 25_600)],
            // "net0": "virtio=02:00:00:00:00:1F,bridge=vmbr0,tag=10": read though the VM is stopped.
            nics: GuestNics { read: vec![nic("net0", "02:00:00:00:00:1F", 10)], unread: vec![] },
            interfaces: None,
            os_info: None,
        }
    );
    // "/nodes/pve01/qemu/113/config": "ide2": "store1:vm-113-cloudinit.qcow2,media=cdrom",
    //   "virtio0": "store1:vm-disk-0.qcow2,size=25G", "virtio1": "store1:vm-disk-1.qcow2,size=40G",
    //   "virtio2": "store1:vm-disk-2.qcow2,size=20G"
    assert_eq!(
        vm(&cluster, "pve01", 113).disks,
        [
            disk(DiskBus::Virtio, 0, "store1:vm-disk-0.qcow2", 25_600),
            disk(DiskBus::Virtio, 1, "store1:vm-disk-1.qcow2", 40_960),
            disk(DiskBus::Virtio, 2, "store1:vm-disk-2.qcow2", 20_480),
        ]
    );
}

#[tokio::test]
async fn node_networks_come_from_the_list_alone() {
    let cluster = collected(fixture("8.4")).await;
    // "/nodes/pve01/network": { "active": 1, …, "iface": "bond0", …, "slaves": "eno1 eno2", "type": "bond" }
    assert_eq!(
        network(&cluster, "pve01", "bond0"),
        NodeNetwork {
            name: "bond0".to_owned(),
            kind: "bond".to_owned(),
            active: true,
            bond_members: strings(&["eno1", "eno2"]),
            vlan: None
        }
    );
    // "/nodes/pve02/network": { "active": 1, …, "iface": "bond2", …, "slaves": "enp5s0 enp5s0d1", "type": "bond" }
    assert_eq!(network(&cluster, "pve02", "bond2").bond_members, ["enp5s0", "enp5s0d1"]);
    // { "active": 1, …, "bridge_ports": "bond0", "iface": "vmbr0", …, "type": "bridge" }
    assert_eq!(
        network(&cluster, "pve01", "vmbr0"),
        NodeNetwork {
            name: "vmbr0".to_owned(),
            kind: "bridge".to_owned(),
            active: true,
            bond_members: vec![],
            vlan: None
        }
    );
    // { "active": 1, …, "iface": "vmbr1.2714", …, "type": "vlan", "vlan-id": "2714", "vlan-raw-device": "vmbr1" }
    assert_eq!(
        network(&cluster, "pve01", "vmbr1.2714"),
        NodeNetwork {
            name: "vmbr1.2714".to_owned(),
            kind: "vlan".to_owned(),
            active: true,
            bond_members: vec![],
            vlan: Some(NodeVlan { id: 2714, raw_device: Some("vmbr1".to_owned()) })
        }
    );
    // { "active": 1, …, "iface": "bond2.2702", …, "type": "vlan", "vlan-id": "2702", "vlan-raw-device": "bond2" }
    assert_eq!(
        network(&cluster, "pve02", "bond2.2702").vlan,
        Some(NodeVlan { id: 2702, raw_device: Some("bond2".to_owned()) })
    );
    // A bond, a bridge or a card carries no VLAN of its own: 5 entries of type "vlan" among the 17 of pve01.
    assert_eq!(cluster.nodes[0].networks.iter().filter(|network| network.vlan.is_some()).count(), 5);
    // { "active": 1, "autostart": 1, "iface": "eno1", "method": "manual", "method6": "manual", "type": "eth" }
    assert_eq!(
        network(&cluster, "pve01", "eno1"),
        NodeNetwork { name: "eno1".to_owned(), kind: "eth".to_owned(), active: true, bond_members: vec![], vlan: None }
    );
    // The networks of a node are sorted by name; the 17 "iface" of "/nodes/pve01/network", sorted by hand.
    let names: Vec<&str> = cluster.nodes[0].networks.iter().map(|network| network.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "bond0",
            "bond1",
            "bond2",
            "bond2.2702",
            "bond2.2703",
            "eno1",
            "eno2",
            "eno3",
            "eno4",
            "enp130s0f0",
            "enp130s0f1",
            "vmbr0",
            "vmbr1",
            "vmbr1.2713",
            "vmbr1.2714",
            "vmbr2",
            "vmbr2.2701"
        ]
    );
}

#[tokio::test]
async fn an_interface_without_active_is_down() {
    let cluster = collected(fixture("9.2")).await;
    // "/nodes/pve01/network": { "iface": "idrac", "method": "manual", "method6": "manual", "type": "eth" }
    // — the only entry of both fixtures without "active".
    assert_eq!(
        network(&cluster, "pve01", "idrac"),
        NodeNetwork {
            name: "idrac".to_owned(),
            kind: "eth".to_owned(),
            active: false,
            bond_members: vec![],
            vlan: None
        }
    );
    let down: usize = cluster.nodes.iter().flat_map(|node| &node.networks).filter(|network| !network.active).count();
    assert_eq!(down, 1);
}

// ---------------------------------------------------------------------------
// Hand-written clusters, for what the fixtures do not hold
// ---------------------------------------------------------------------------

fn ok(data: Value) -> (u16, Value) {
    (200, json!({ "data": data }))
}

fn failed(status: u16) -> (u16, Value) {
    (status, json!({"data": null, "message": "boom"}))
}

/// A node `pve` alone, without guest; the shapes are those of the fixtures.
fn standalone() -> Answers {
    let mut answers = Answers::new();
    answers.insert("/version".to_owned(), ok(json!({"release": "8.4", "version": "8.4.21"})));
    // A standalone node has no entry of type "cluster".
    answers.insert(
        "/cluster/status".to_owned(),
        ok(json!([{"id": "node/pve", "local": 1, "name": "pve", "nodeid": 0, "online": 1, "type": "node"}])),
    );
    answers.insert("/nodes".to_owned(), ok(json!([{"node": "pve", "status": "online", "type": "node"}])));
    answers.insert(
        "/nodes/pve/status".to_owned(),
        ok(json!({"cpuinfo": {"cores": 4, "cpus": 8, "sockets": 1}, "memory": {"total": 34_359_738_368_u64}})),
    );
    answers.insert("/nodes/pve/network".to_owned(), ok(json!([])));
    answers.insert("/nodes/pve/qemu".to_owned(), ok(json!([])));
    answers.insert("/nodes/pve/lxc".to_owned(), ok(json!([])));
    answers
}

/// `standalone()` with one VM `101`, in the given status.
fn one_vm(status: &str) -> Answers {
    let mut answers = standalone();
    answers.insert(
        "/nodes/pve/qemu".to_owned(),
        ok(json!([{"cpus": 2, "maxmem": 2_147_483_648_u64, "name": "vm", "status": status, "vmid": 101}])),
    );
    answers.insert("/nodes/pve/qemu/101/config".to_owned(), ok(json!({"ostype": "l26"})));
    answers
}

const VM_INTERFACES: &str = "/nodes/pve/qemu/101/agent/network-get-interfaces";
const VM_OS_INFO: &str = "/nodes/pve/qemu/101/agent/get-osinfo";

#[tokio::test]
async fn a_standalone_node_has_an_empty_cluster_name() {
    let cluster = collected(standalone()).await;
    assert_eq!(cluster.name, "");
    assert_eq!(node_counts(&cluster), [("pve".to_owned(), 8, 34_359_738_368, 0, 0, 0)]);
}

#[tokio::test]
async fn a_vm_that_is_not_running_has_unknown_interfaces_and_its_agent_is_not_asked() {
    for status in ["stopped", "paused"] {
        let mut answers = one_vm(status);
        // An agent that would answer, were it asked.
        answers.insert(VM_INTERFACES.to_owned(), ok(json!({"result": []})));
        answers.insert(VM_OS_INFO.to_owned(), ok(json!({"result": {"pretty-name": "Debian"}})));
        let server = serve(answers).await;
        let cluster = collect(&client(&server)).await.unwrap();
        let guest = vm(&cluster, "pve", 101);
        assert_eq!((guest.interfaces, guest.os_info), (None, None), "{status}");
        let asked = received(&server).await;
        assert!(!asked.iter().any(|(_, api_path)| api_path.contains("/agent/")), "{asked:?}");
    }
}

#[tokio::test]
async fn an_agent_that_fails_leaves_the_interfaces_unknown_never_empty() {
    // 500 is what both fixtures hold; a missing entry is answered 404 by the mock.
    for failure in [Some(failed(500)), Some(failed(596)), None] {
        let mut answers = one_vm("running");
        if let Some(failure) = failure.clone() {
            answers.insert(VM_INTERFACES.to_owned(), failure.clone());
            answers.insert(VM_OS_INFO.to_owned(), failure);
        }
        let guest = vm(&collected(answers).await, "pve", 101);
        assert_eq!(guest.interfaces, None, "{failure:?}");
        assert_eq!(guest.os_info, None, "{failure:?}");
    }
}

#[tokio::test]
async fn an_agent_answer_without_result_is_unknown() {
    for answer in [json!({}), json!({"result": null}), json!(null), json!({"result": "unsupported"})] {
        let mut answers = one_vm("running");
        answers.insert(VM_INTERFACES.to_owned(), ok(answer.clone()));
        answers.insert(VM_OS_INFO.to_owned(), ok(answer.clone()));
        let guest = vm(&collected(answers).await, "pve", 101);
        assert_eq!((guest.interfaces, guest.os_info), (None, None), "{answer}");
    }
}

#[tokio::test]
async fn an_agent_that_reports_no_interface_gives_an_empty_list_not_unknown() {
    let only_loopback = json!({"result": [{"hardware-address": "00:00:00:00:00:00", "name": "lo"}]});
    for answer in [json!({"result": []}), only_loopback] {
        let mut answers = one_vm("running");
        answers.insert(VM_INTERFACES.to_owned(), ok(answer.clone()));
        answers.insert(VM_OS_INFO.to_owned(), ok(json!({"result": {}})));
        let guest = vm(&collected(answers).await, "pve", 101);
        assert_eq!(guest.interfaces, Some(vec![]), "{answer}");
        assert_eq!(guest.os_info, Some(GuestOsInfo::default()), "{answer}");
    }
}

#[tokio::test]
async fn the_two_agent_calls_fail_separately() {
    let mut answers = one_vm("running");
    answers.insert(VM_INTERFACES.to_owned(), failed(500));
    answers.insert(VM_OS_INFO.to_owned(), ok(json!({"result": {"id": "debian", "pretty-name": "Debian 13"}})));
    let guest = vm(&collected(answers).await, "pve", 101);
    assert_eq!(guest.interfaces, None);
    assert_eq!(
        guest.os_info,
        Some(GuestOsInfo {
            id: Some("debian".to_owned()),
            pretty_name: Some("Debian 13".to_owned()),
            ..GuestOsInfo::default()
        })
    );

    let mut answers = one_vm("running");
    answers.insert(VM_INTERFACES.to_owned(), ok(json!({"result": [{"name": "Ethernet"}]})));
    answers.insert(VM_OS_INFO.to_owned(), failed(500));
    let guest = vm(&collected(answers).await, "pve", 101);
    // An interface the agent gives neither address nor "ip-addresses" for, as one of the 8.4 fixture.
    assert_eq!(
        guest.interfaces,
        Some(vec![GuestInterface { name: "Ethernet".to_owned(), mac: None, addresses: vec![] }])
    );
    assert_eq!(guest.os_info, None);
}

#[tokio::test]
async fn an_ovs_bond_lists_its_members_in_ovs_bonds() {
    let mut answers = standalone();
    answers.insert(
        "/nodes/pve/network".to_owned(),
        ok(json!([
            {"active": 1, "iface": "vmbr0", "ovs_ports": "bond0", "type": "OVSBridge"},
            {"active": 1, "iface": "bond0", "ovs_bonds": "enp1s0 enp2s0", "ovs_bridge": "vmbr0", "type": "OVSBond"},
            {"iface": "enp1s0", "type": "eth"},
        ])),
    );
    let cluster = collected(answers).await;
    assert_eq!(
        cluster.nodes[0].networks,
        [
            NodeNetwork {
                name: "bond0".to_owned(),
                kind: "OVSBond".to_owned(),
                active: true,
                bond_members: strings(&["enp1s0", "enp2s0"]),
                vlan: None
            },
            NodeNetwork {
                name: "enp1s0".to_owned(),
                kind: "eth".to_owned(),
                active: false,
                bond_members: vec![],
                vlan: None
            },
            NodeNetwork {
                name: "vmbr0".to_owned(),
                kind: "OVSBridge".to_owned(),
                active: true,
                bond_members: vec![],
                vlan: None
            },
        ]
    );
}

/// `standalone()` with three containers; the fields are those the Go structs
/// `Container` and `ContainerInterface` read. Proxmox gives the `vmid` of a
/// container as a string or as a number (`StringOrUint64` in the Go client).
fn with_containers() -> Answers {
    let mut answers = standalone();
    answers.insert(
        "/nodes/pve/lxc".to_owned(),
        ok(json!([
            {"cpus": 2, "maxdisk": 8_589_934_592_u64, "maxmem": 1_073_741_824_u64, "name": "ct-web",
             "status": "running", "tags": "web;prod", "vmid": "202"},
            {"cpus": 1, "maxdisk": 4_294_967_296_u64, "maxmem": 536_870_912_u64, "name": "ct-old",
             "status": "stopped", "vmid": 201},
            {"cpus": 4, "maxdisk": 0, "maxmem": 2_147_483_648_u64, "name": "ct-db",
             "status": "running", "vmid": 203},
        ])),
    );
    answers.insert(
        "/nodes/pve/lxc/202/interfaces".to_owned(),
        ok(json!([
            {"hwaddr": "00:00:00:00:00:00", "inet": "127.0.0.1/8", "inet6": "::1/128", "name": "lo"},
            {"hwaddr": "bc:24:11:00:00:01", "inet": "192.0.2.10/24", "inet6": "2001:db8::10/64", "name": "eth0"},
            {"hwaddr": "bc:24:11:00:00:02", "name": "eth1"},
        ])),
    );
    // A stopped container that would answer an empty list, were it asked.
    answers.insert("/nodes/pve/lxc/201/interfaces".to_owned(), ok(json!([])));
    answers.insert("/nodes/pve/lxc/203/interfaces".to_owned(), failed(500));
    // The `netN` lines as `man pct` writes them (`net[n]: name=<string>[,bridge=<bridge>]…
    // [,hwaddr=<XX:XX:XX:XX:XX:XX>]…[,tag=<integer>][,trunks=<vlanid[;vlanid...]>]`): no
    // container was ever observed.
    answers.insert(
        "/nodes/pve/lxc/202/config".to_owned(),
        ok(json!({
            "hostname": "ct-web", "memory": 1024,
            "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=192.0.2.10/24,tag=30,type=veth",
            "net1": "name=eth1,bridge=vmbr1,hwaddr=BC:24:11:00:00:02,trunks=40;50-52,type=veth",
        })),
    );
    answers.insert("/nodes/pve/lxc/201/config".to_owned(), ok(json!({"hostname": "ct-old"})));
    answers.insert("/nodes/pve/lxc/203/config".to_owned(), failed(500));
    answers
}

#[tokio::test]
async fn containers_are_collected_with_their_interfaces() {
    let server = serve(with_containers()).await;
    let cluster = collect(&client(&server)).await.unwrap();
    let container_interface = |name: &str, mac: &str, inet: Option<&str>, inet6: Option<&str>| ContainerInterface {
        name: name.to_owned(),
        mac: Some(mac.to_owned()),
        inet: inet.map(str::to_owned),
        inet6: inet6.map(str::to_owned),
    };
    assert_eq!(
        cluster.nodes[0].containers,
        [
            Container {
                vmid: 201,
                name: "ct-old".to_owned(),
                status: "stopped".to_owned(),
                cpus: 1,
                max_memory_bytes: 536_870_912,
                max_disk_bytes: 4_294_967_296,
                tags: vec![],
                // Not running: unknown, whatever it would have answered.
                interfaces: None,
                nics: None,
            },
            Container {
                vmid: 202,
                name: "ct-web".to_owned(),
                status: "running".to_owned(),
                cpus: 2,
                max_memory_bytes: 1_073_741_824,
                max_disk_bytes: 8_589_934_592,
                tags: strings(&["web", "prod"]),
                interfaces: Some(vec![
                    container_interface("eth0", "bc:24:11:00:00:01", Some("192.0.2.10/24"), Some("2001:db8::10/64")),
                    container_interface("eth1", "bc:24:11:00:00:02", None, None),
                ]),
                nics: Some(GuestNics {
                    read: vec![
                        GuestNic {
                            key: "net0".to_owned(),
                            mac: "BC:24:11:00:00:01".to_owned(),
                            bridge: Some("vmbr0".to_owned()),
                            tag: Some(30),
                            trunks: vec![],
                        },
                        GuestNic {
                            key: "net1".to_owned(),
                            mac: "BC:24:11:00:00:02".to_owned(),
                            bridge: Some("vmbr1".to_owned()),
                            tag: None,
                            trunks: vec![(40, 40), (50, 52)],
                        },
                    ],
                    unread: vec![],
                }),
            },
            Container {
                vmid: 203,
                name: "ct-db".to_owned(),
                status: "running".to_owned(),
                cpus: 4,
                max_memory_bytes: 2_147_483_648,
                max_disk_bytes: 0,
                tags: vec![],
                // The call failed: unknown.
                interfaces: None,
                // Its configuration could not be read either: unknown, and the collection goes on.
                nics: None,
            },
        ]
    );
    let asked = received(&server).await;
    assert!(!asked.contains(&("GET".to_owned(), "/nodes/pve/lxc/201/interfaces".to_owned())), "{asked:?}");
    // Nor is the configuration of a container that has no interface to put a VLAN on.
    assert!(!asked.contains(&("GET".to_owned(), "/nodes/pve/lxc/201/config".to_owned())), "{asked:?}");
    assert!(asked.contains(&("GET".to_owned(), "/nodes/pve/lxc/202/config".to_owned())), "{asked:?}");
}

#[tokio::test]
async fn the_vlan_of_a_node_sub_interface_is_read_from_the_list() {
    let cluster = collected(fixture("9.2")).await;
    // "/nodes/pve01/network": { "active": 1, …, "iface": "bond2.25", …, "type": "vlan", "vlan-id": "25",
    //   "vlan-raw-device": "bond2" } and { …, "iface": "vmbr1.19", …, "vlan-id": "19", "vlan-raw-device": "vmbr1" }
    assert_eq!(
        network(&cluster, "pve01", "bond2.25").vlan,
        Some(NodeVlan { id: 25, raw_device: Some("bond2".to_owned()) })
    );
    assert_eq!(
        network(&cluster, "pve01", "vmbr1.19").vlan,
        Some(NodeVlan { id: 19, raw_device: Some("vmbr1".to_owned()) })
    );
    // { "active": 1, "autostart": 1, "bridge_ports": "bond0", "iface": "vmbr0", …, "type": "bridge" }: a bridge
    // is in no VLAN, whatever VLANs it lets through.
    assert_eq!(network(&cluster, "pve01", "vmbr0").vlan, None);
}

#[tokio::test]
async fn a_vlan_id_that_is_not_one_leaves_the_vlan_of_the_interface_unknown() {
    let mut answers = standalone();
    answers.insert(
        "/nodes/pve/network".to_owned(),
        ok(json!([
            // The id as a number, were a version to write it so, and without its raw device.
            {"active": 1, "iface": "vlan30", "type": "vlan", "vlan-id": 30},
            {"active": 1, "iface": "eno1.0", "type": "vlan", "vlan-id": "0", "vlan-raw-device": "eno1"},
            {"active": 1, "iface": "eno1.x", "type": "vlan", "vlan-id": "x", "vlan-raw-device": "eno1"},
            {"active": 1, "iface": "eno1.9", "type": "vlan", "vlan-raw-device": "eno1"},
            // Not of type "vlan": whatever it carries is not read.
            {"active": 1, "iface": "eno1", "type": "eth", "vlan-id": "7"},
        ])),
    );
    let cluster = collected(answers).await;
    let vlans: Vec<(&str, Option<&NodeVlan>)> =
        cluster.nodes[0].networks.iter().map(|network| (network.name.as_str(), network.vlan.as_ref())).collect();
    assert_eq!(
        vlans,
        [
            ("eno1", None),
            ("eno1.0", None),
            ("eno1.9", None),
            ("eno1.x", None),
            ("vlan30", Some(&NodeVlan { id: 30, raw_device: None })),
        ]
    );
}

#[tokio::test]
async fn a_network_card_that_cannot_be_read_is_named_and_does_not_fail_the_collection() {
    let mut answers = one_vm("stopped");
    answers.insert(
        "/nodes/pve/qemu/101/config".to_owned(),
        ok(json!({"net0": "virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=banana", "net1": "virtio=BC:24:11:00:00:02"})),
    );
    let guest = vm(&collected(answers).await, "pve", 101);
    assert_eq!(guest.nics.unread, ["net0"]);
    assert_eq!(
        guest.nics.read,
        [GuestNic {
            key: "net1".to_owned(),
            mac: "BC:24:11:00:00:02".to_owned(),
            bridge: None,
            tag: None,
            trunks: vec![]
        }]
    );
}

#[tokio::test]
async fn a_running_container_without_interface_gives_an_empty_list() {
    let mut answers = with_containers();
    answers.insert("/nodes/pve/lxc/203/interfaces".to_owned(), ok(json!([])));
    let cluster = collected(answers).await;
    assert_eq!(cluster.nodes[0].containers[2].interfaces, Some(vec![]));
}

// ---------------------------------------------------------------------------
// Failures: a partial cluster is never returned
// ---------------------------------------------------------------------------

async fn failure_of(answers: Answers) -> CollectError {
    let server = serve(answers).await;
    collect(&client(&server)).await.unwrap_err()
}

#[tokio::test]
async fn any_failed_call_but_the_agent_fails_the_whole_collection_naming_its_path() {
    for failing in [
        "/version",
        "/cluster/status",
        "/nodes",
        "/nodes/pve02/status",
        "/nodes/pve03/network",
        "/nodes/pve01/qemu",
        "/nodes/pve02/lxc",
        // A stopped VM, a running one, a template.
        "/nodes/pve01/qemu/167/config",
        "/nodes/pve03/qemu/116/config",
        "/nodes/pve01/qemu/156/config",
    ] {
        let mut answers = fixture("8.4");
        assert!(answers.insert(failing.to_owned(), failed(500)).is_some(), "{failing} is not in the fixture");
        let error = failure_of(answers).await;
        assert!(
            matches!(&error, CollectError::Client(ClientError::Status { status: 500, path, .. }) if path == failing),
            "{failing}: {error:?}"
        );
        assert_eq!(error.to_string(), format!("GET {failing} answered 500: boom"));
    }
}

#[tokio::test]
async fn a_failed_container_list_fails_the_collection() {
    let mut answers = with_containers();
    answers.insert("/nodes/pve/lxc".to_owned(), failed(403));
    assert_eq!(failure_of(answers).await.to_string(), "GET /nodes/pve/lxc answered 403: boom");
}

#[tokio::test]
async fn an_answer_of_another_shape_fails_the_collection_naming_its_path() {
    for (failing, answer) in [
        ("/version", json!({"release": "8.4"})),
        ("/cluster/status", json!({"name": "pve-cluster-a"})),
        ("/nodes", json!([{"status": "online"}])),
        ("/nodes/pve01/status", json!({"cpuinfo": {"cores": 16}, "memory": {"total": 1}})),
        ("/nodes/pve01/network", json!([{"type": "eth"}])),
        ("/nodes/pve01/qemu", json!([{"name": "vm", "status": "running"}])),
        ("/nodes/pve01/qemu", json!([{"name": "vm", "status": "running", "vmid": "abc", "cpus": 1, "maxmem": 1}])),
        ("/nodes/pve01/qemu", json!([{"name": "vm", "status": "running", "vmid": 1, "maxmem": 1}])),
        ("/nodes/pve01/lxc", json!({"vmid": 1})),
        ("/nodes/pve01/qemu/107/config", json!(null)),
        ("/nodes/pve01/qemu/107/config", json!("locked")),
    ] {
        let mut answers = fixture("8.4");
        answers.insert(failing.to_owned(), ok(answer.clone()));
        let error = failure_of(answers).await;
        assert!(
            matches!(&error, CollectError::Client(ClientError::Decode { path, .. }) if path == failing),
            "{failing} {answer}: {error:?}"
        );
        assert!(error.to_string().starts_with(&format!("GET {failing}: unexpected answer")), "{error}");
    }
}

#[tokio::test]
async fn a_failed_login_fails_the_collection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(401).set_body_json(json!({"data": null, "message": "authentication failure"})),
        )
        .mount(&server)
        .await;
    let error = collect(&client(&server)).await.unwrap_err();
    assert_eq!(error.to_string(), "POST /access/ticket answered 401: authentication failure");
    assert_eq!(received(&server).await, [("POST".to_owned(), "/access/ticket".to_owned())]);
}

#[tokio::test]
async fn a_version_the_collection_was_not_written_for_is_refused_before_reading_anything_else() {
    for version in ["7.4-17", "10.0.1", "beta"] {
        let mut answers = fixture("8.4");
        answers.insert("/version".to_owned(), ok(json!({"release": "x", "version": version})));
        let server = serve(answers).await;
        let error = collect(&client(&server)).await.unwrap_err();
        assert!(matches!(&error, CollectError::UnsupportedVersion { version: refused, .. } if refused == version));
        assert_eq!(
            error.to_string(),
            format!("Proxmox VE {version} is not supported (supported major versions: 8, 9)")
        );
        let asked = received(&server).await;
        assert_eq!(
            asked,
            [("POST".to_owned(), "/access/ticket".to_owned()), ("GET".to_owned(), "/version".to_owned())]
        );
    }
}

// ---------------------------------------------------------------------------
// Read-only, call counts, parallelism, determinism
// ---------------------------------------------------------------------------

/// Collects `version` and checks every request the mock received: one login,
/// then nothing but the GETs the collection is allowed.
async fn requests_of_a_collection(version: &str) -> usize {
    let answers = fixture(version);
    let recorded: Vec<String> = answers.keys().cloned().collect();
    let server = serve(answers).await;
    collect(&client(&server)).await.unwrap();
    let asked = received(&server).await;

    assert_eq!(asked[0], ("POST".to_owned(), "/access/ticket".to_owned()));
    let not_get: Vec<_> = asked[1..].iter().filter(|(verb, _)| verb != "GET").collect();
    assert_eq!(not_get, Vec::<&(String, String)>::new());

    let gets: Vec<&str> = asked[1..].iter().map(|(_, api_path)| api_path.as_str()).collect();
    for api_path in &gets {
        assert!(recorded.iter().any(|known| known == api_path), "{api_path} is not in the fixture");
        // The lists already carry what these would repeat.
        assert!(!api_path.ends_with("/status/current"), "{api_path}");
        let parts: Vec<&str> = api_path.split('/').collect();
        assert!(!(parts.len() == 5 && parts[3] == "network"), "{api_path}");
    }
    let mut distinct = gets.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), gets.len(), "a path was asked twice");
    gets.len()
}

#[tokio::test]
async fn the_collection_only_ever_reads() {
    // 8.4: /version, /cluster/status and /nodes (3); status, network, qemu and lxc of 3 nodes (12);
    // the config of 65 VMs (65); the two agent calls of the 47 running VMs (94).
    assert_eq!(requests_of_a_collection("8.4").await, 3 + 12 + 65 + 94);
    // 9.2: 3; 4 calls for each of 2 nodes (8); 18 configs; the two agent calls of 13 running VMs (26).
    assert_eq!(requests_of_a_collection("9.2").await, 3 + 8 + 18 + 26);
}

#[tokio::test]
async fn with_an_api_token_the_collection_sends_no_login() {
    let credential = ("authorization", format!("PVEAPIToken={TOKEN}"));
    let server = serve_as(fixture("9.2"), credential, Pace::default()).await;
    let proxmox = ProxmoxClient::new(&server.uri(), Credentials::api_token(TOKEN)).unwrap();
    let cluster = collect(&proxmox).await.unwrap();
    assert_eq!(vms(&cluster).len(), 18);
    let asked = received(&server).await;
    assert_eq!(asked.len(), 55);
    assert!(asked.iter().all(|(verb, _)| verb == "GET"), "{asked:?}");
}

/// The most requests the server held at once: each is held from its arrival for `delay`.
fn most_in_flight(arrivals: &[Instant], delay: Duration) -> usize {
    let held = |at: &Instant| arrivals.iter().filter(|start| *start <= at && *at < **start + delay).count();
    arrivals.iter().map(held).max().unwrap_or(0)
}

#[tokio::test]
async fn the_collection_runs_in_parallel_within_the_request_cap() {
    let delay = Duration::from_millis(40);
    for (cap, expected) in [(None, 8), (Some(3), 3)] {
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let pace = Pace { delay: Some(Arc::new(move |_| delay)), arrivals: Some(Arc::clone(&arrivals)) };
        let server = serve_as(fixture("9.2"), ("cookie", format!("PVEAuthCookie={TICKET}")), pace).await;
        let mut builder = ProxmoxClient::builder(&server.uri(), Credentials::password("sync@pve", "the-password"));
        if let Some(cap) = cap {
            builder = builder.max_in_flight(cap);
        }
        let started = Instant::now();
        collect(&builder.build().unwrap()).await.unwrap();
        let arrivals = arrivals.lock().unwrap();
        // Never more than the cap, and the cap is reached: nodes and VMs are read at the same time.
        assert_eq!(most_in_flight(&arrivals, delay), expected);
        // One after the other, the 55 calls would take 55 * 40 ms = 2.2 s.
        if cap.is_none() {
            assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
        }
    }
}

/// The most requests in flight while `answers` is collected, each answer taking 100 ms.
async fn most_in_flight_collecting(answers: Answers) -> usize {
    let delay = Duration::from_millis(100);
    let arrivals = Arc::new(Mutex::new(Vec::new()));
    let pace = Pace { delay: Some(Arc::new(move |_| delay)), arrivals: Some(Arc::clone(&arrivals)) };
    let server = serve_as(answers, ("cookie", format!("PVEAuthCookie={TICKET}")), pace).await;
    collect(&client(&server)).await.unwrap();
    let arrivals = arrivals.lock().unwrap();
    most_in_flight(&arrivals, delay)
}

#[tokio::test]
async fn the_vms_of_a_node_are_read_at_the_same_time() {
    // Twelve stopped VMs: one call each. One after the other, no more than the four
    // calls of the node itself would ever be in flight.
    let mut answers = standalone();
    let rows: Vec<Value> = (101..=112)
        .map(|vmid| json!({"cpus": 1, "maxmem": 1_073_741_824, "name": format!("vm{vmid}"), "status": "stopped", "vmid": vmid}))
        .collect();
    answers.insert("/nodes/pve/qemu".to_owned(), ok(json!(rows)));
    for vmid in 101..=112 {
        answers.insert(format!("/nodes/pve/qemu/{vmid}/config"), ok(json!({"ostype": "l26"})));
    }
    assert_eq!(most_in_flight_collecting(answers).await, 8);
}

#[tokio::test]
async fn the_nodes_are_read_at_the_same_time() {
    // Five nodes without guest: four calls each. One node after the other, four would be in flight at most.
    let mut answers = standalone();
    let names = ["pve1", "pve2", "pve3", "pve4", "pve5"];
    let rows: Vec<Value> = names.iter().map(|name| json!({"node": name})).collect();
    answers.insert("/nodes".to_owned(), ok(json!(rows)));
    for name in names {
        for (call, answer) in [
            ("status", json!({"cpuinfo": {"cpus": 8}, "memory": {"total": 1_073_741_824}})),
            ("network", json!([])),
            ("qemu", json!([])),
            ("lxc", json!([])),
        ] {
            answers.insert(format!("/nodes/{name}/{call}"), ok(answer));
        }
    }
    assert_eq!(most_in_flight_collecting(answers).await, 8);
}

/// A delay that depends on the path and on the seed only: another seed, another order of answers.
fn shuffled(seed: u64) -> Delay {
    Arc::new(move |api_path: &str| {
        // FNV-1a over the seed then the path.
        let bytes = seed.to_le_bytes().into_iter().chain(api_path.bytes());
        let hash =
            bytes.fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3));
        Duration::from_millis(hash % 25)
    })
}

#[tokio::test]
async fn the_result_is_the_same_whatever_the_order_of_the_answers() {
    let reference = collected(fixture("8.4")).await;

    // Sorted by node name, then by VMID: checked on the reference itself.
    let names: Vec<&str> = reference.nodes.iter().map(|node| node.name.as_str()).collect();
    assert_eq!(names, ["pve01", "pve02", "pve03"]);
    for node in &reference.nodes {
        let vmids: Vec<u64> = node.vms.iter().map(|vm| vm.vmid).collect();
        assert!(vmids.windows(2).all(|pair| pair[0] < pair[1]), "{}: {vmids:?}", node.name);
    }
    // "/nodes/pve03/qemu" lists 116, 113, 160, 124, 105, 114, 170, 162, 165, 117, 166.
    let vmids: Vec<u64> = reference.nodes[2].vms.iter().map(|vm| vm.vmid).collect();
    assert_eq!(vmids, [105, 113, 114, 116, 117, 124, 160, 162, 165, 166, 170]);

    let mut orders = Vec::new();
    for seed in [1, 2, 3] {
        let pace = Pace { delay: Some(shuffled(seed)), arrivals: None };
        let server = serve_as(fixture("8.4"), ("cookie", format!("PVEAuthCookie={TICKET}")), pace).await;
        let cluster = collect(&client(&server)).await.unwrap();
        assert_eq!(cluster, reference, "seed {seed}");
        orders.push(received(&server).await);
    }
    // The delays did change the order in which the calls were made.
    assert_ne!(orders[0], orders[1]);
    assert_ne!(orders[1], orders[2]);
}

// "/nodes" of 9.2 lists pve01 and pve02, both `"status": "online"`. Proxmox VE
// lists a node that is down with `"status": "offline"` (enum of `GET /nodes`,
// pve-manager `PVE/API2/Nodes.pm`), and pveproxy answers 595 for the calls it
// relays to it: that node is left out and named, the others are read.
#[tokio::test]
async fn a_node_proxmox_says_is_offline_is_left_out_and_named_and_the_others_are_read() {
    let mut answers = fixture("9.2");
    let (_, nodes) = answers.get_mut("/nodes").unwrap();
    for entry in nodes["data"].as_array_mut().unwrap() {
        if entry["node"] == "pve02" {
            entry["status"] = json!("offline");
        }
    }
    for (api_path, answer) in answers.iter_mut() {
        if api_path.starts_with("/nodes/pve02/") {
            *answer = (595, json!({"data": null, "message": "No route to host"}));
        }
    }
    let server = serve(answers).await;
    let cluster = collect(&client(&server)).await.expect("the online node is read");
    let names: Vec<&str> = cluster.nodes.iter().map(|node| node.name.as_str()).collect();
    assert_eq!(names, ["pve01"]);
    assert_eq!(cluster.offline, ["pve02"]);
    let asked = received(&server).await;
    assert!(asked.iter().all(|(_, target)| !target.contains("/nodes/pve02/")), "{asked:?}");
}

// The same enum has a third value, `"unknown"`: the cluster cannot tell
// whether the node is up. It is no more read than an offline one.
#[tokio::test]
async fn a_node_whose_status_proxmox_does_not_know_is_left_out_as_an_offline_one() {
    let mut answers = fixture("9.2");
    let (_, nodes) = answers.get_mut("/nodes").unwrap();
    for entry in nodes["data"].as_array_mut().unwrap() {
        if entry["node"] == "pve02" {
            entry["status"] = json!("unknown");
        }
    }
    for (api_path, answer) in answers.iter_mut() {
        if api_path.starts_with("/nodes/pve02/") {
            *answer = (595, json!({"data": null, "message": "No route to host"}));
        }
    }
    let server = serve(answers).await;
    let cluster = collect(&client(&server)).await.expect("the online node is read");
    let names: Vec<&str> = cluster.nodes.iter().map(|node| node.name.as_str()).collect();
    assert_eq!(names, ["pve01"]);
    assert_eq!(cluster.offline, ["pve02"]);
}

// Without `current=1`, `GET /nodes/{node}/qemu/{vmid}/config` gives the
// configuration "with pending configuration changes applied" (qemu-server,
// `PVE/API2/Qemu.pm`): a disk resize waiting for a restart would be written as done.
#[tokio::test]
async fn the_configuration_of_a_vm_is_the_current_one_not_the_pending_one() {
    let server = serve(fixture("9.2")).await;
    collect(&client(&server)).await.expect("a cluster");
    let requests = server.received_requests().await.unwrap();
    let configs: Vec<_> = requests.iter().filter(|request| request.url.path().ends_with("/config")).collect();
    assert!(!configs.is_empty());
    for request in configs {
        assert_eq!(request.url.query(), Some("current=1"), "{}", request.url);
    }
}

/// A shell that answers each node from the recorded output of lldpcli, and
/// remembers what it was asked to run.
struct Recorded {
    answers: Vec<(&'static str, Result<String, String>)>,
    ran: Mutex<Vec<String>>,
}

impl Recorded {
    fn new(answers: Vec<(&'static str, Result<String, String>)>) -> Self {
        Recorded { answers, ran: Mutex::new(Vec::new()) }
    }
}

impl omnisync_proxmox::neighbors::Shell for Recorded {
    async fn run(&self, node: &str, command: &str) -> Result<String, String> {
        self.ran.lock().unwrap().push(format!("{node}: {command}"));
        let found = self.answers.iter().find(|(name, _)| *name == node);
        found.map_or_else(|| Err("no answer recorded".to_owned()), |(_, answer)| answer.clone())
    }
}

fn lldpd(name: &str) -> String {
    let file = format!("{}/tests/fixtures/lldpd/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&file).unwrap_or_else(|error| panic!("{file}: {error}"))
}

fn harbor_shell() -> Recorded {
    Recorded::new(vec![
        ("pve01", Ok(lldpd("pve01.json"))),
        ("pve02", Ok(lldpd("pve02.json"))),
        ("pve03", Ok(lldpd("pve03.json"))),
    ])
}

#[tokio::test]
async fn only_the_lldpcli_command_is_ever_run() {
    let cluster = collected(fixture("8.4")).await;
    let shell = harbor_shell();
    read_neighbors(&cluster, &shell).await;
    let mut ran = shell.ran.lock().unwrap().clone();
    ran.sort();
    assert_eq!(
        ran,
        [
            "pve01: lldpcli -f json show neighbors",
            "pve02: lldpcli -f json show neighbors",
            "pve03: lldpcli -f json show neighbors",
        ]
    );
    assert_eq!(omnisync_proxmox::neighbors::check("lldpcli -f json show neighbors"), Ok(()));
    assert!(omnisync_proxmox::neighbors::check("lldpcli -f json show neighbors; reboot").is_err());
    assert!(omnisync_proxmox::neighbors::check("lldpcli show configuration").is_err());
}

#[tokio::test]
async fn a_node_whose_neighbours_cannot_be_read_is_a_warning_and_the_others_are_read() {
    let cluster = collected(fixture("8.4")).await;
    let shell = Recorded::new(vec![
        ("pve01", Ok(lldpd("pve01.json"))),
        ("pve02", Err("exit status 127: bash: lldpcli: command not found".to_owned())),
        ("pve03", Ok(lldpd("pve03.json"))),
    ]);
    let read = read_neighbors(&cluster, &shell).await;
    assert_eq!(read.by_node.keys().collect::<Vec<_>>(), ["pve01", "pve03"]);
    assert_eq!(
        read.warnings,
        ["node pve02: what its cards hear cannot be read: exit status 127: bash: lldpcli: command not found"]
    );
}

#[tokio::test]
async fn a_neighbour_heard_on_a_bridge_is_left_out() {
    let cluster = collected(fixture("8.4")).await;
    let read = read_neighbors(&cluster, &harbor_shell()).await;
    // pve02.json: six cards hear a Nexus, six interfaces of guest firewalls
    // (fwpr141p0, fwln141i0…) hear the node itself; /nodes/pve02/network has
    // the six cards as `eth` (eno1, eno2, enp5s0, enp5s0d1, enp66s0, enp66s0d1).
    let cards: Vec<&str> = read.by_node["pve02"].iter().map(|heard| heard.card.as_str()).collect();
    assert_eq!(cards, ["eno1", "eno2", "enp5s0", "enp5s0d1", "enp66s0", "enp66s0d1"]);
    assert_eq!(
        read.by_node["pve02"][0],
        CardNeighbor {
            card: "eno1".to_owned(),
            switch: "nexus03.lab.example".to_owned(),
            port: "Ethernet1/41".to_owned()
        }
    );
    // A card Proxmox does not list as physical is left out, whatever it hears.
    let mut cluster = cluster;
    let pve02 = cluster.nodes.iter_mut().find(|node| node.name == "pve02").unwrap();
    pve02.networks.iter_mut().find(|network| network.name == "eno1").unwrap().kind = "bond".to_owned();
    let read = read_neighbors(&cluster, &harbor_shell()).await;
    assert!(read.by_node["pve02"].iter().all(|heard| heard.card != "eno1"), "{:?}", read.by_node["pve02"]);
}

#[tokio::test]
async fn the_switch_port_of_each_card_of_a_node_is_reported_under_its_netbox_name() {
    let cluster = collected(fixture("8.4")).await;
    let read = read_neighbors(&cluster, &harbor_shell()).await;
    let settings = omnisync_proxmox::Settings {
        domain: ".lab.example".to_owned(),
        ..omnisync_proxmox::Settings::new("pve", "Harbor")
    };
    let heard = omnisync_proxmox::translate::heard(&read, &settings);
    // pve03.json: "enp3s0f0" ... "chassis": {"nexus03.lab.example" ... "value": "Ethernet1/10"
    let first = omnisync_core::network::hosts::Heard {
        host: "pve03.lab.example".to_owned(),
        card: "enp3s0f0".to_owned(),
        switch: "nexus03.lab.example".to_owned(),
        port: "Ethernet1/10".to_owned(),
    };
    assert!(heard.contains(&first), "{heard:?}");
    // Six physical cards on each of the three nodes.
    assert_eq!(heard.len(), 18);
    assert!(heard.iter().all(|heard| heard.host.ends_with(".lab.example")));
}

#[tokio::test]
async fn a_card_the_interface_filter_leaves_out_is_not_reported() {
    let cluster = collected(fixture("8.4")).await;
    let read = read_neighbors(&cluster, &harbor_shell()).await;
    let filter = omnisync_proxmox::Settings::interface_filter("^enp").unwrap();
    let settings = omnisync_proxmox::Settings {
        domain: ".lab.example".to_owned(),
        interface_filter: filter,
        ..omnisync_proxmox::Settings::new("pve", "Harbor")
    };
    let heard = omnisync_proxmox::translate::heard(&read, &settings);
    // pve01.json: eno1 to eno4 and enp130s0f0, enp130s0f1; the filter leaves the latter two out,
    // as the translation leaves their interfaces out.
    assert!(heard.iter().all(|heard| !heard.card.starts_with("enp")), "{heard:?}");
    assert_eq!(heard.iter().filter(|heard| heard.host == "pve01.lab.example").count(), 4);
}
