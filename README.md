# NetFingerprint — Network Behavior Profiler

A real packet capture and analysis tool that generates unique behavioral fingerprints for websites based on live network traffic.

---

## Requirements

- Python 3.8+
- **Root/Admin privileges** (required for raw packet capture via Scapy)
- Linux, macOS, or Windows (with Npcap installed)

---

## Installation

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# On Linux/macOS you may need:
sudo pip install -r requirements.txt

# On Windows: install Npcap first from https://npcap.com/
# then: pip install -r requirements.txt
```

---

## Running the App

```bash
# Linux / macOS — MUST run as root for packet capture:
sudo python app.py

# Windows — run terminal as Administrator:
python app.py
```

Then open your browser at: **http://localhost:5000**

---

## Features

### Capture Tab
1. Enter any website URL (e.g. `google.com` or `https://github.com`)
2. Set capture duration (3–30 seconds)
3. Click **CAPTURE TRAFFIC** — the app will:
   - Resolve the hostname to IP addresses
   - Start live packet sniffing (Scapy)
   - Simultaneously trigger real HTTP requests to the site
   - Analyze all captured packets
4. View the fingerprint, stats, and charts

### Compare Tab
1. Enter two different websites
2. Capture each one separately
3. Click **COMPARE FINGERPRINTS** to see:
   - Similarity score (0–100%)
   - Side-by-side stats
   - Protocol distribution comparison

---

## How It Works

1. **DNS Resolution**: The hostname is resolved to IP(s) using `socket.getaddrinfo`
2. **Packet Sniffing**: Scapy sniffs raw packets filtered by the resolved IP(s)
3. **Traffic Generation**: `requests` library fetches the website to generate real traffic
4. **Feature Extraction**: Extracts packet size, protocol, ports, TTL, TCP flags, timing
5. **Fingerprint Generation**: SHA-256 hash of behavioral features → 16-char hex fingerprint
6. **Classification**: Rule-based behavior labeling from traffic patterns

---

## Output Explained

| Field | Description |
|-------|-------------|
| Fingerprint | 16-char SHA-256 hash of behavioral features |
| Behavior | Traffic pattern classification |
| Total Packets | Raw packets captured |
| Total Bytes | Total data transferred |
| Avg Packet Size | Mean packet size in bytes |
| Packets/sec | Capture rate |
| Avg IAT | Average inter-arrival time (ms) |
| Unique Ports | Number of distinct ports observed |

---

## Troubleshooting

**"No packets captured"** → Make sure you're running with sudo/root/admin privileges

**"Could not resolve hostname"** → Check your internet connection and the URL format

**Windows users** → Install [Npcap](https://npcap.com/) before running

**Firewall blocking** → Some networks block raw packet capture; try on a local network
