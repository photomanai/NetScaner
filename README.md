# NetScanner

A lightweight Python network scanner to discover devices on a local network.
Built with **Scapy**, it performs **ARP scans**, shows **IP & MAC addresses**, **vendor info**, and optional **hostnames**.

---

## Features

- Scan a specific IP range (e.g., `192.168.1.0/24`)
- Display IP, MAC, Vendor, and Hostname of each device
- Configurable **timeout** and **retry** options
- Cross-platform terminal clearing (Linux / Windows)
- ASCII art banner at startup

---

## Requirements

- Python 3.8+

- Modules:

  ```bash
  pip install scapy manuf
  ```

- Linux / Windows terminal

- Optional: sudo/root privileges (for raw packet sending)

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/photomanai/NetScanner.git
cd NetScanner
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

`requirements.txt`:

```
scapy
manuf
```

---

## Usage

```bash
python3 netScanner.py -r <IP_RANGE> [-R <RETRY>] [-t <TIMEOUT>]
```

### Options:

| Option          | Description                             | Default |
| --------------- | --------------------------------------- | ------- |
| `-r, --range`   | IP range to scan (e.g., 192.168.1.0/24) | None    |
| `-R, --retry`   | Retry count for unanswered packets      | 2       |
| `-t, --timeout` | Timeout in seconds for packet response  | 3       |

---

### Example:

```bash
python3 netScanner.py -r 192.168.1.0/24 -R 3 -t 5
```

**Sample Output:**

```
Currently scanning: 192.168.1.0/24

Received 256 packets, got 9 answers, remaining 247 packets

IP              MAC                  Vendor                        Hostname
--------------------------------------------------------------------------------
192.168.1.1     a4:7b:9d:12:34:56   TP-Link Technologies Co.,Ltd  router.local
192.168.1.5     3c:52:82:11:22:33   Apple, Inc.                   iPhone.local
192.168.1.10    08:00:27:aa:bb:cc   Oracle VirtualBox             ubuntu.local
```

---

## Notes

- Some devices may not respond immediately. Consider increasing timeout or retry count.
- Requires root privileges for sending raw ARP packets.
- Works on both Linux and Windows terminals.

---

## License

This project is open source. Use responsibly and at your own risk.
