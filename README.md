# 📡 Device Scanner

**Device Scanner** is a high-performance network reconnaissance tool written in Rust. It discovers active devices within a local network and retrieves detailed metadata using various network protocols and Layer 2 packet inspection.

---

## ✨ Key Features

* **Multi-Protocol Discovery**: Goes beyond simple IP pings to identify the true identity of devices.
* **L2 Precision**: Uses `pnet` to extract MAC addresses directly from Ethernet headers for 100% accuracy.
* **Background DHCP Sniffing**: Passively listens for DHCP requests to capture device hostnames (Option 12) as they connect or reconnect to the network.
* **Detailed Metadata**: Extracts "Friendly Names" from Android (Google Cast), Windows (NetBIOS), and Apple devices.
* **UPnP/SSDP XML Parsing**: Discovers smart devices (TVs, NAS, Speakers) and fetches detailed manufacturer/model info by parsing XML device descriptions.

---

## 🚀 Supported Protocols

| Protocol | Purpose | Target Devices |
| --- | --- | --- |
| **ARP** | Active host discovery & MAC mapping | All IPv4 Devices |
| **DHCP Sniffer** | Real-time hostname capture (Option 12) | Connecting/Reconnecting Devices |
| **mDNS** | Multicast hostname & service discovery | Apple, Linux, Android (Google Cast) |
| **SSDP** | UPnP service discovery & XML metadata | Smart TVs, Printers, NAS, IoT |
| **LLMNR** | Local name resolution | Windows & Legacy Devices |
| **NetBIOS** | Legacy Windows naming & Workgroups | Windows, Samba Servers |
| **rDNS** | PTR record lookup via Gateway | Router-registered Devices |

---

## 🛠 Installation

### Prerequisites

System libraries for packet capturing must be installed:

* **Linux**: `libpcap-dev`
* **Windows**: `Npcap` or `WinPcap`

### Build

```bash
git clone https://github.com/n3t7a1k/device-scanner.git
cd device-scanner
cargo build --release

```

---

## 💻 Usage

### Basic Scan (Auto-detect Interface)

```bash
sudo ./target/release/device-scanner

```

### Scan Specific Subnet (CIDR)

```bash
sudo ./target/release/device-scanner 192.168.1.0/24

```

### Scan IP Range & Save Output

```bash
sudo ./target/release/device-scanner -o result.json 192.168.1.10-50

```

### List Available Interfaces

```bash
./target/release/device-scanner --list

```

> **Note**: Raw socket access is required. On Linux, use `sudo` or grant capabilities: `sudo setcap cap_net_raw+ep ./target/release/device-scanner`. On Windows, run the terminal as Administrator.

---

## 📝 Output Format (JSONL)

Results are saved as JSON lines for easy parsing and integration:

```json
{"method":"dhcp","ip":"172.17.104.64","mac":"b8:c6:aa:73:ed:d0","result":{"hostname":"HongE"}}
{"method":"mdns","ip":"172.17.100.153","mac":"B8:C6:AA:8B:52:62","result":{"hostname":"Living Room TV","meta":{"fn":"Living Room TV","md":"Chromecast"}}}
{"method":"ssdp","ip":"192.168.1.15","mac":"AA:BB:CC:DD:EE:FF","result":{"server":"UPnP/1.0","details":{"friendly_name":"Kitchen Speaker","manufacturer":"Sonos","model":"Sonos One","url":"http://192.168.1.15:1400/xml/device_description.xml"}}}

```

---

## 🗺 Roadmap

### 🏁 Completed

* [x] **ARP Scan**: L2 active host discovery and MAC mapping.
* [x] **mDNS/DNS-SD**: Apple/Android friendly name and service extraction.
* [x] **SSDP (UPnP)**: IoT device discovery and XML metadata parsing.
* [x] **DHCP Sniffing**: Passive real-time hostname capture (Option 12).
* [x] **NetBIOS/LLMNR**: Legacy Windows naming and workgroup discovery.

### 🚀 Up Next (In Development)

* [ ] **Web-based Identification**:
* Port 80, 443, 8080 title & header grabbing.


* [ ] **SNMP (Simple Network Management Protocol)**:
* Querying `sysDescr` and `sysName` via Public community string.
* Target: Enterprise switches, routers, and network printers.


* [ ] **SMB/RPC Fingerprinting**:
* Precise Windows version detection.
* Domain/Workgroup membership identification.


* [ ] **Banner Grabbing**:
* **SSH (22)**, **FTP (21)**, **Telnet (23)** version string extraction.

---

## ⚖ License

Distributed under the MIT License.
