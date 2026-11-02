"""
NetShield-NIDS - Packet Monitoring Engine
Provides live interface sniffing via Scapy, offline PCAP file parsing,
and a realistic simulated traffic generator for controlled testing and demo environments.
"""
import threading
import time
import random
from collections import deque
from datetime import datetime, timezone

from config import Config
from database.db import insert_event, insert_alert
from detection.engine import engine_instance

class PacketMonitor:
    """Manages packet capture threads, parsing, and pipeline orchestration."""
    
    def __init__(self):
        self.is_running = False
        self.mode = "stopped"  # "stopped", "live", "pcap", "simulation"
        self.interface = "default"
        self.packets_captured = 0
        self.alerts_triggered = 0
        self.start_time = None
        self.last_error = None
        
        # In-memory rolling buffer for instant live UI feed
        self.recent_buffer = deque(maxlen=200)
        self._thread = None
        self._lock = threading.Lock()

    def get_available_interfaces(self):
        """Query host network interfaces safely via Scapy."""
        interfaces = []
        try:
            from scapy.all import conf
            for iface_id, iface_obj in conf.ifaces.items():
                name = getattr(iface_obj, "name", str(iface_id))
                desc = getattr(iface_obj, "description", "")
                ip = getattr(iface_obj, "ip", "")
                interfaces.append({
                    "id": str(iface_id),
                    "name": name,
                    "description": desc or name,
                    "ip": ip or "N/A"
                })
        except Exception:
            import socket
            try:
                hostname = socket.gethostname()
                host_ip = socket.gethostbyname(hostname)
                interfaces.append({
                    "id": "default",
                    "name": f"Default ({hostname})",
                    "description": "Default System Interface",
                    "ip": host_ip
                })
            except Exception:
                interfaces.append({
                    "id": "default",
                    "name": "Default Interface",
                    "description": "Primary Loopback/Ethernet",
                    "ip": "127.0.0.1"
                })
        return interfaces

    def get_status(self):
        """Return current monitoring telemetry and operational mode."""
        with self._lock:
            uptime_seconds = 0
            if self.is_running and self.start_time:
                uptime_seconds = int((datetime.now(timezone.utc) - self.start_time).total_seconds())
                
            return {
                "is_running": self.is_running,
                "mode": self.mode,
                "interface": self.interface,
                "packets_captured": self.packets_captured,
                "alerts_triggered": self.alerts_triggered,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "uptime_seconds": uptime_seconds,
                "last_error": self.last_error
            }

    def get_recent_buffer(self, limit=50):
        """Retrieve latest captured packets from memory buffer."""
        with self._lock:
            items = list(self.recent_buffer)
            return items[-limit:] if limit else items

    def clear_buffer(self):
        """Clear memory buffer."""
        with self._lock:
            self.recent_buffer.clear()

    def _process_packet_dict(self, packet_dict):
        """Pass packet through detection engine and persist records to SQLite."""
        is_suspicious, alerts = engine_instance.analyze_packet(packet_dict)
        packet_dict["is_suspicious"] = is_suspicious

        with self._lock:
            self.packets_captured += 1
            if alerts:
                self.alerts_triggered += len(alerts)
            self.recent_buffer.append(packet_dict)

        try:
            insert_event(packet_dict)
            for alert in alerts:
                alert["timestamp"] = packet_dict["timestamp"]
                insert_alert(alert)
        except Exception:
            pass

    def _parse_scapy_packet(self, pkt):
        """Extract network metadata from raw Scapy packet."""
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6

        timestamp = datetime.now(timezone.utc).isoformat()
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        protocol = "OTHER"
        src_port = None
        dst_port = None
        flags = ""
        info = ""
        size = len(pkt)

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            flags = str(pkt[TCP].flags)
            info = f"TCP {src_port} -> {dst_port} [{flags}]"
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            info = f"UDP {src_port} -> {dst_port}"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
            icmp_type = pkt[ICMP].type
            flags = f"Type-{icmp_type}"
            info = f"ICMP Type {icmp_type} Code {pkt[ICMP].code}"

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_size": size,
            "flags": flags,
            "info": info
        }

    def start_live_capture(self, interface=None, bpf_filter=None):
        """Start live packet capture using Scapy with graceful error handling."""
        if self.is_running:
            self.stop_capture()

        self.last_error = None
        self.is_running = True
        self.mode = "live"
        self.interface = interface or "default"
        self.start_time = datetime.now(timezone.utc)
        self.packets_captured = 0
        self.alerts_triggered = 0

        def capture_worker():
            try:
                from scapy.all import sniff
                kwargs = {
                    "prn": lambda p: self._process_packet_dict(self._parse_scapy_packet(p)),
                    "store": False,
                    "stop_filter": lambda p: not self.is_running
                }
                if interface and interface != "default":
                    kwargs["iface"] = interface
                if bpf_filter:
                    kwargs["filter"] = bpf_filter

                sniff(**kwargs)
            except Exception as e:
                err_msg = str(e)
                if "libpcap" in err_msg.lower() or "winpcap" in err_msg.lower() or "npcap" in err_msg.lower():
                    self.last_error = (
                        "Npcap / libpcap driver missing or raw socket permission denied. "
                        "Install Npcap for Windows, or use Simulation / PCAP mode."
                    )
                else:
                    self.last_error = f"Capture error: {err_msg}"
                self.is_running = False
                self.mode = "stopped"

        self._thread = threading.Thread(target=capture_worker, daemon=True, name="NetShield-LiveSniff")
        self._thread.start()
        return True

    def start_simulation(self):
        """
        Start synthetic SOC network stream generator.
        Produces realistic baseline traffic interleaved with scheduled intrusion patterns.
        Clearly labeled as Simulation Mode.
        """
        if self.is_running:
            self.stop_capture()

        self.last_error = None
        self.is_running = True
        self.mode = "simulation"
        self.interface = "Virtual Simulation Interface (SOC Lab Mode)"
        self.start_time = datetime.now(timezone.utc)
        self.packets_captured = 0
        self.alerts_triggered = 0

        def simulation_worker():
            benign_ips = ["192.168.1.102", "192.168.1.115", "10.0.0.45", "172.16.0.12"]
            gateways = ["192.168.1.1", "8.8.8.8", "1.1.1.1", "142.250.190.46"]
            common_ports = [80, 443, 53, 123, 8080]
            
            counter = 0
            while self.is_running:
                counter += 1
                now_str = datetime.now(timezone.utc).isoformat()
                
                # Periodically inject controlled attack patterns for demonstration
                if counter % 18 == 0:
                    # Simulated Port Scan from 198.51.100.99
                    scan_ports = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389]
                    for p in scan_ports:
                        if not self.is_running:
                            break
                        pkt = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "src_ip": "198.51.100.99",
                            "dst_ip": "192.168.1.50",
                            "src_port": 40000 + p,
                            "dst_port": p,
                            "protocol": "TCP",
                            "packet_size": 48,
                            "flags": "S",
                            "info": f"SYN Reconnaissance to port {p}"
                        }
                        self._process_packet_dict(pkt)
                        time.sleep(0.04)
                    time.sleep(1.0)
                    continue

                elif counter % 28 == 0:
                    # Simulated SYN Flood Burst from 203.0.113.72
                    for s in range(26):
                        if not self.is_running:
                            break
                        pkt = {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "src_ip": "203.0.113.72",
                            "dst_ip": "192.168.1.10",
                            "src_port": 35000 + s,
                            "dst_port": 80,
                            "protocol": "TCP",
                            "packet_size": 60,
                            "flags": "S",
                            "info": "Volumetric SYN handshake burst"
                        }
                        self._process_packet_dict(pkt)
                        time.sleep(0.02)
                    time.sleep(1.0)
                    continue

                elif counter % 35 == 0:
                    # Stealth XMAS Scan attempt from 185.220.101.5
                    pkt = {
                        "timestamp": now_str,
                        "src_ip": "185.220.101.5",
                        "dst_ip": "192.168.1.10",
                        "src_port": 51234,
                        "dst_port": 445,
                        "protocol": "TCP",
                        "packet_size": 52,
                        "flags": "FPU",
                        "info": "Stealth XMAS probe with FIN+PSH+URG flags"
                    }
                    self._process_packet_dict(pkt)
                    time.sleep(0.5)
                    continue

                # Standard Benign Packet
                src = random.choice(benign_ips)
                dst = random.choice(gateways)
                port = random.choice(common_ports)
                proto = "UDP" if port in (53, 123) else "TCP"
                size = random.randint(64, 1420)
                flags = "PA" if proto == "TCP" else ""
                
                pkt = {
                    "timestamp": now_str,
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": random.randint(49152, 65535),
                    "dst_port": port,
                    "protocol": proto,
                    "packet_size": size,
                    "flags": flags,
                    "info": f"Standard {proto} Application Data Exchange"
                }
                self._process_packet_dict(pkt)
                time.sleep(random.uniform(0.3, 0.7))

        self._thread = threading.Thread(target=simulation_worker, daemon=True, name="NetShield-SimWorker")
        self._thread.start()
        return True

    def analyze_pcap_file(self, filepath):
        """Process an offline PCAP / PCAPNG packet capture file using Scapy."""
        self.last_error = None
        self.mode = "pcap"
        self.interface = f"PCAP: {filepath}"
        
        try:
            from scapy.all import rdpcap
            packets = rdpcap(filepath)
            total_read = len(packets)
            alerts_before = self.alerts_triggered
            
            for pkt in packets:
                parsed = self._parse_scapy_packet(pkt)
                self._process_packet_dict(parsed)
                
            alerts_found = self.alerts_triggered - alerts_before
            self.mode = "stopped"
            return {
                "success": True,
                "total_packets": total_read,
                "alerts_triggered": alerts_found,
                "message": f"Successfully parsed {total_read} packets from PCAP. Triggered {alerts_found} alerts."
            }
        except Exception as e:
            self.last_error = f"PCAP parsing failed: {str(e)}"
            self.mode = "stopped"
            return {
                "success": False,
                "error": str(e)
            }

    def stop_capture(self):
        """Halt active live sniffing or simulation loop gracefully."""
        self.is_running = False
        self.mode = "stopped"
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        return True

# Global shared instance
packet_monitor = PacketMonitor()

