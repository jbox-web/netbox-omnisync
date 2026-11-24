# Redfish fixtures

Answers observed on the BMCs of real servers, read with `GET` only, then
anonymised: service tags, serial numbers, part numbers, UUIDs, MAC addresses,
host names, addresses and timestamps are replaced by fictitious values of the
same shape; everything else, structure and key order included, is what the BMC
sent. One directory per BMC family and firmware, each holding one BMC:

| Directory | BMC | Firmware | Redfish | Server |
|---|---|---|---|---|
| `idrac7-2.65.65.65` | Dell iDRAC 7 (`12G Monolithic`) | 2.65.65.65 | 1.4.0 | PowerEdge R620, 6 cards |
| `idrac8-2.83.83.83` | Dell iDRAC 8 (`13G Modular`, a blade) | 2.83.83.83 | 1.4.0 | PowerEdge FC430, 2 cards |
| `idrac8-2.86.86.86` | Dell iDRAC 8 (`13G Monolithic`) | 2.86.86.86 | 1.4.0 | PowerEdge R630, 6 cards |
| `idrac9-7.00.00.174` | Dell iDRAC 9 (`14G Monolithic`) | 7.00.00.174 | 1.17.0 | PowerEdge R640, 4 cards |
| `idrac9-7.10.90.00` | Dell iDRAC 9 (`15G Monolithic`) | 7.10.90.00 | 1.20.1 | PowerEdge R650, 4 cards |
| `ilo4-2.82` | HPE iLO 4 | 2.82 | 1.0.0 | ProLiant DL360 Gen9 |
| `ilo4-2.82-blank-serial` | HPE iLO 4 | 2.82 | 1.0.0 | ProLiant DL360 Gen9 whose serial is blank |

`api.json` is one JSON object: request path to
`{"status": <HTTP status>, "body": <answer>}`. A body that was empty is `""`.
`tests/common/mod.rs` serves it from a mock BMC, which the end-to-end tests of
the command line (`crates/cli`) use as well.

Expected values of the tests are written by hand from these files, never from
what the code returns.

## What is read, and nothing else

Every request is a `GET` with HTTP Basic authentication. The client refuses
any other path (`Call` in `src/client.rs`).

| Call | iDRAC | iLO 4 |
|---|---|---|
| The service root | `/redfish/v1/` | `/redfish/v1/` |
| The systems | `/redfish/v1/Systems` | `/redfish/v1/Systems` answers `308`; `/redfish/v1/Systems/` is asked next |
| The first system | `/redfish/v1/Systems/System.Embedded.1` | `/redfish/v1/Systems/1/` |
| The manager the system links to | `Links.ManagedBy`: `/redfish/v1/Managers/iDRAC.Embedded.1` | `links.ManagedBy` (`href`): `/redfish/v1/Managers/1/` |
| The Ethernet interfaces of the system | `/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces` | not asked: the system gives the addresses itself |
| Each Ethernet interface | `…/EthernetInterfaces/<card>` | not asked |

That is five requests plus one per card on an iDRAC, and five on an iLO 4
(four answers and the `308`).

Read in the answers: `RedfishVersion` of the root; `Manufacturer`, `Model`,
`SKU`, `SerialNumber`, `HostName`, `EthernetInterfaces`, `Links.ManagedBy` (or
`links.ManagedBy`) and `HostCorrelation.HostMACAddress` of the system; `Model`
and `FirmwareVersion` of the manager; `MACAddress` of a card.

## Things the fixtures show

- **Dell**: the service tag, which is the serial NetBox and vCenter hold, is
  in `SKU`. `SerialNumber` is another identifier (fourteen characters) and is
  never written. The same in every iDRAC generation recorded.
- **HPE**: the serial is in `SerialNumber`; `SKU` is the product reference
  (`939544-P69` here, a fictitious value of the shape of the real one).
- **A blank serial** (`ilo4-2.82-blank-serial`): `SKU` and `SerialNumber` are
  sixteen spaces each, `HostName` is empty. A blank value is unknown, never
  written, and never clears what NetBox has.
- **The `308` of iLO 4**: `/redfish/v1/Systems` answers `308` with an empty
  body; every path of an iLO 4 ends with `/`. The `Location` header of that
  answer was not recorded, and the client does not read it.
- **`MACAddress` and `PermanentMACAddress` may differ** (`idrac8-2.83.83.83`,
  both cards of a blade): the address in use is the one compared with NetBox.
- **The host name** is whatever the operating system told the BMC: the full
  name (`pve01.lab01`), the short one (`sitea-esx01`), another one
  (`corp-siteb-pve02`), or nothing.
- The root is answered without authentication; everything else needs the
  account. The root of an iDRAC shows the service tag to anybody
  (`Oem.Dell.ServiceTag`), which is why it is anonymised there too.

## Never observed, and so not guessed

- **The Ethernet interfaces of an iLO 4** (`/redfish/v1/Systems/1/EthernetInterfaces/`)
  were never recorded: the MAC addresses of an iLO 4 come from
  `HostCorrelation.HostMACAddress` of its system, which is what was matched
  against NetBox on the real servers. A system that gives that list is not
  asked for its cards.
- **The collection of managers** (`/redfish/v1/Managers`) of an iLO 4 was only
  seen answering `308` with an empty body, never read with its final `/`. The
  manager is found through the link of the system instead, on every family,
  which costs one request less.
- **An iLO 5 or later, an iDRAC 6, a BMC of another vendor** (Supermicro,
  Lenovo XCC): no answer was recorded. The rules for an unknown vendor
  (`SerialNumber` is the serial) follow the Redfish schema, not an
  observation.
- **A BMC with several systems or several managers**: every one recorded has
  one of each. The first is read.
- **A refused login**: the status of a real BMC for a wrong account (`401`
  here) was not recorded; the mock answers it.
- **Session authentication** (`/redfish/v1/SessionService/Sessions`, a
  `POST`): not used. Each request carries the account, and the BMC logs one
  connection per request.
