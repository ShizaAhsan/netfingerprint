"""
capture.py — Real packet capture using Scapy + requests
Requires: pip install scapy requests
Requires root/admin privileges for raw packet capture
"""

import time
import hashlib
import socket
import threading
import json
from collections import defaultdict, Counter

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, conf
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class PacketCapture:
    def __init__(self, url: str, duration: int = 10):
        self.url = url
        self.duration = duration
        self.packets_data = []
        self.lock = threading.Lock()
        self._resolved_ips = set()

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def _resolve_host(self, url: str) -> set:
        """Resolve hostname to IPs for filtering"""
        ips = set()
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname
            if host:
                results = socket.getaddrinfo(host, None)
                for r in results:
                    ips.add(r[4][0])
        except Exception:
            pass
        return ips

    def _packet_handler(self, pkt):
        """Called for each captured packet"""
        try:
            if not pkt.haslayer(IP):
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Only capture packets related to our resolved IPs
            if self._resolved_ips:
                if src_ip not in self._resolved_ips and dst_ip not in self._resolved_ips:
                    return

            info = {
                'timestamp': time.time(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'length': len(pkt),
                'protocol': 'OTHER',
                'sport': None,
                'dport': None,
                'flags': None,
                'ttl': pkt[IP].ttl,
            }

            if pkt.haslayer(TCP):
                info['protocol'] = 'TCP'
                info['sport'] = pkt[TCP].sport
                info['dport'] = pkt[TCP].dport
                info['flags'] = str(pkt[TCP].flags)
                # Classify common ports
                for port in [info['sport'], info['dport']]:
                    if port == 443:
                        info['protocol'] = 'HTTPS/TLS'
                        break
                    elif port == 80:
                        info['protocol'] = 'HTTP'
                        break
                    elif port == 53:
                        info['protocol'] = 'DNS'
                        break

            elif pkt.haslayer(UDP):
                info['protocol'] = 'UDP'
                info['sport'] = pkt[UDP].sport
                info['dport'] = pkt[UDP].dport
                if pkt.haslayer(DNS):
                    info['protocol'] = 'DNS'

            elif pkt.haslayer(ICMP):
                info['protocol'] = 'ICMP'

            with self.lock:
                self.packets_data.append(info)

        except Exception:
            pass

    def _trigger_traffic(self, url: str):
        """Trigger actual HTTP/HTTPS traffic to the website"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            }
            # Main page request
            resp = requests.get(url, timeout=15, headers=headers, allow_redirects=True)
            # Follow links in the page briefly
            time.sleep(1)
            # Try some common subpaths to generate more traffic
            for path in ['/favicon.ico', '/robots.txt']:
                try:
                    requests.get(url.rstrip('/') + path, timeout=5, headers=headers)
                except Exception:
                    pass
        except Exception:
            pass

    def run(self) -> dict:
        if not SCAPY_AVAILABLE:
            return {'error': 'Scapy is not installed. Run: pip install scapy'}

        if not REQUESTS_AVAILABLE:
            return {'error': 'requests is not installed. Run: pip install requests'}

        url = self._normalize_url(self.url)

        # Resolve target IPs
        self._resolved_ips = self._resolve_host(url)
        if not self._resolved_ips:
            return {'error': f'Could not resolve hostname for: {url}'}

        self.packets_data = []

        # Start traffic generation in background
        traffic_thread = threading.Thread(target=self._trigger_traffic, args=(url,), daemon=True)

        # Start sniffing
        sniff_done = threading.Event()
        captured_packets = []

        def do_sniff():
            try:
                pkts = sniff(
                    filter=f"host {' or host '.join(self._resolved_ips)}",
                    timeout=self.duration,
                    prn=self._packet_handler,
                    store=False
                )
            except Exception as e:
                with self.lock:
                    self.packets_data.append({'_error': str(e)})
            finally:
                sniff_done.set()

        sniff_thread = threading.Thread(target=do_sniff, daemon=True)
        sniff_thread.start()

        # Small delay then trigger traffic
        time.sleep(0.5)
        traffic_thread.start()

        # Wait for sniff to complete
        sniff_thread.join(timeout=self.duration + 5)

        # Check for errors
        errors = [p for p in self.packets_data if '_error' in p]
        if errors:
            return {'error': f"Capture error: {errors[0]['_error']}. Make sure you run with sudo/admin privileges."}

        real_packets = [p for p in self.packets_data if '_error' not in p]

        if not real_packets:
            return {'error': 'No packets captured. Ensure you have admin/root privileges and the website is reachable.'}

        return self._analyze(url, real_packets)

    def _analyze(self, url: str, packets: list) -> dict:
        """Analyze captured packets and generate fingerprint"""
        total = len(packets)
        sizes = [p['length'] for p in packets]
        protocols = Counter(p['protocol'] for p in packets)
        ports = []
        for p in packets:
            if p.get('dport'):
                ports.append(p['dport'])
            if p.get('sport'):
                ports.append(p['sport'])

        port_counter = Counter(ports)
        unique_ports = len(set(ports))
        total_bytes = sum(sizes)
        avg_size = round(total_bytes / total, 2) if total else 0
        min_size = min(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0

        # Packet size distribution buckets
        size_buckets = {'0-100': 0, '101-500': 0, '501-1000': 0, '1001-1500': 0, '1500+': 0}
        for s in sizes:
            if s <= 100:
                size_buckets['0-100'] += 1
            elif s <= 500:
                size_buckets['101-500'] += 1
            elif s <= 1000:
                size_buckets['501-1000'] += 1
            elif s <= 1500:
                size_buckets['1001-1500'] += 1
            else:
                size_buckets['1500+'] += 1

        # Timing analysis
        timestamps = sorted(p['timestamp'] for p in packets)
        inter_arrival = []
        if len(timestamps) > 1:
            inter_arrival = [round((timestamps[i+1] - timestamps[i]) * 1000, 3)
                             for i in range(len(timestamps) - 1)]
        avg_iat = round(sum(inter_arrival) / len(inter_arrival), 3) if inter_arrival else 0

        # Behavior classification
        behavior = self._classify_behavior(protocols, avg_size, total, port_counter)

        # Generate fingerprint hash
        fp_data = {
            'protocols': dict(protocols.most_common(5)),
            'avg_size': avg_size,
            'top_ports': dict(port_counter.most_common(5)),
            'behavior': behavior
        }
        fp_hash = hashlib.sha256(json.dumps(fp_data, sort_keys=True).encode()).hexdigest()[:16].upper()

        # TCP flags analysis
        flag_counts = Counter()
        for p in packets:
            if p.get('flags'):
                flag_counts[p['flags']] += 1

        return {
            'url': url,
            'fingerprint': fp_hash,
            'behavior': behavior,
            'stats': {
                'total_packets': total,
                'total_bytes': total_bytes,
                'avg_packet_size': avg_size,
                'min_packet_size': min_size,
                'max_packet_size': max_size,
                'unique_ports': unique_ports,
                'avg_inter_arrival_ms': avg_iat,
                'capture_duration_s': self.duration,
                'packets_per_second': round(total / self.duration, 2),
                'top_ports': dict(port_counter.most_common(10)),
                'tcp_flags': dict(flag_counts.most_common(10)),
            },
            'charts': {
                'protocols': dict(protocols),
                'size_distribution': size_buckets,
                'top_ports': dict(port_counter.most_common(8)),
            },
            'resolved_ips': list(self._resolved_ips),
        }

    def _classify_behavior(self, protocols, avg_size, total_packets, port_counter) -> str:
        proto_set = set(protocols.keys())
        top_ports = {p for p, _ in port_counter.most_common(5)}

        if 'HTTPS/TLS' in proto_set and avg_size > 800:
            return 'Encrypted Heavy Content (HTTPS)'
        elif 'HTTPS/TLS' in proto_set:
            return 'Encrypted Light Traffic (HTTPS)'
        elif 'HTTP' in proto_set and avg_size > 600:
            return 'HTTP Heavy Content'
        elif 'DNS' in proto_set and total_packets < 30:
            return 'DNS-Heavy / Lightweight'
        elif total_packets > 200 and avg_size > 1000:
            return 'High-Bandwidth Streaming'
        elif total_packets > 100:
            return 'Moderate Web Traffic'
        elif total_packets < 20:
            return 'Minimal / Static Site'
        else:
            return 'Standard Web Application'
