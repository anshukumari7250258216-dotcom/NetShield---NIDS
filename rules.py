"""
NetShield-NIDS - Intrusion Detection Rules Module
Implements rule-based intrusion detection logic with sliding time windows,
stateful connection tracking, and actionable mitigation playbooks.
"""
import time
from collections import defaultdict, deque
from config import Config

class BaseRule:
    """Base class for all intrusion detection rules."""
    def __init__(self, name, description, severity="MEDIUM"):
        self.name = name
        self.description = description
        self.severity = severity
        self.enabled = True
        self.last_alert_time = {}  # ip -> timestamp (cooldown tracker)
        self.cooldown_period = 20.0  # seconds between repeated alerts for same IP

    def can_alert(self, ip, current_time=None):
        """Check if cooldown has elapsed for this source IP to prevent alert fatigue."""
        now = current_time or time.time()
        last = self.last_alert_time.get(ip, 0)
        if now - last >= self.cooldown_period:
            self.last_alert_time[ip] = now
            return True
        return False

    def evaluate(self, packet):
        """Evaluate packet dict. Returns alert dict or None."""
        raise NotImplementedError

class PortScanRule(BaseRule):
    """
    Detects horizontal and vertical port scans by tracking the number of
    distinct destination ports contacted by a single source IP within a sliding window.
    """
    def __init__(self, threshold=Config.PORT_SCAN_THRESHOLD, window_seconds=Config.PORT_SCAN_WINDOW):
        super().__init__(
            name="Port Scan Detected",
            description="Reconnaissance activity scanning multiple ports",
            severity="HIGH"
        )
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.history = defaultdict(deque)

    def evaluate(self, packet):
        if not self.enabled:
            return None
            
        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")
        dst_ip = packet.get("dst_ip")
        
        if not src_ip or dst_port is None:
            return None
            
        now = time.time()
        dq = self.history[src_ip]
        dq.append((now, dst_port))
        
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()
            
        distinct_ports = {item[1] for item in dq}
        
        if len(distinct_ports) >= self.threshold:
            if self.can_alert(src_ip, now):
                sample_ports = sorted(list(distinct_ports))[:6]
                return {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip or "Multiple",
                    "detection_type": self.name,
                    "severity": self.severity,
                    "is_confirmed_attack": True,
                    "description": (
                        f"Host {src_ip} scanned {len(distinct_ports)} distinct ports "
                        f"(e.g., {sample_ports}...) within {self.window_seconds}s."
                    ),
                    "recommendation": (
                        f"Enforce dynamic border block rule: 'iptables -A INPUT -s {src_ip} -j DROP'. "
                        "Audit target services for unauthorized exposures."
                    )
                }
        return None

class SynFloodRule(BaseRule):
    """
    Detects TCP SYN Flood DoS attacks by tracking excessive SYN-only packets
    without ACK completion from a single source IP within a sliding window.
    """
    def __init__(self, threshold=Config.SYN_FLOOD_THRESHOLD, window_seconds=Config.SYN_FLOOD_WINDOW):
        super().__init__(
            name="SYN Flood / Connection Burst",
            description="High frequency TCP SYN connection requests without handshake completion",
            severity="CRITICAL"
        )
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.history = defaultdict(deque)

    def evaluate(self, packet):
        if not self.enabled:
            return None
            
        if packet.get("protocol") != "TCP":
            return None
            
        flags = str(packet.get("flags", "")).upper()
        if "S" in flags and "A" not in flags:
            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            dst_port = packet.get("dst_port", 0)
            now = time.time()
            
            dq = self.history[src_ip]
            dq.append(now)
            
            cutoff = now - self.window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
                
            if len(dq) >= self.threshold:
                if self.can_alert(src_ip, now):
                    return {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip or "Multiple",
                        "detection_type": self.name,
                        "severity": self.severity,
                        "is_confirmed_attack": True,
                        "description": (
                            f"Potential SYN flood from {src_ip}: {len(dq)} SYN packets "
                            f"observed in {self.window_seconds}s targeting port {dst_port}."
                        ),
                        "recommendation": (
                            "Enable TCP SYN cookies on target host (sysctl -w net.ipv4.tcp_syncookies=1). "
                            f"Rate-limit or blackhole source IP {src_ip} on edge firewall."
                        )
                    }
        return None

class IcmpFloodRule(BaseRule):
    """
    Detects ICMP ping floods and oversized ICMP payloads (Ping of Death indicators).
    """
    def __init__(self, threshold=Config.ICMP_FLOOD_THRESHOLD, window_seconds=Config.ICMP_FLOOD_WINDOW, max_size=Config.ICMP_MAX_PAYLOAD_SIZE):
        super().__init__(
            name="Unusual ICMP Activity",
            description="High rate of ICMP echo requests or abnormally oversized ICMP payload",
            severity="MEDIUM"
        )
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.max_size = max_size
        self.history = defaultdict(deque)

    def evaluate(self, packet):
        if not self.enabled:
            return None
            
        if packet.get("protocol") != "ICMP":
            return None
            
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        packet_size = packet.get("packet_size", 0)
        now = time.time()
        
        # Check oversized payload anomaly
        if packet_size > self.max_size:
            if self.can_alert(src_ip, now):
                return {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip or "Multiple",
                    "detection_type": "Oversized ICMP Anomaly",
                    "severity": "HIGH",
                    "is_confirmed_attack": True,
                    "description": (
                        f"Host {src_ip} transmitted oversized ICMP packet ({packet_size} bytes), "
                        f"exceeding standard ceiling of {self.max_size} bytes."
                    ),
                    "recommendation": (
                        "Drop fragmented/oversized ICMP packets at boundary firewall. "
                        "Inspect for ICMP tunnel or exfiltration tools."
                    )
                }
                
        # Check flood rate
        dq = self.history[src_ip]
        dq.append(now)
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()
            
        if len(dq) >= self.threshold:
            if self.can_alert(src_ip, now):
                return {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip or "Multiple",
                    "detection_type": "ICMP Ping Flood Detected",
                    "severity": "MEDIUM",
                    "is_confirmed_attack": True,
                    "description": (
                        f"Host {src_ip} generated {len(dq)} ICMP echo requests "
                        f"in {self.window_seconds}s."
                    ),
                    "recommendation": (
                        "Throttle ICMP Echo responses: 'iptables -A INPUT -p icmp --icmp-type echo-request "
                        "-m limit --limit 1/s -j ACCEPT'."
                    )
                }
        return None

class SuspiciousPortRule(BaseRule):
    """
    Detects connection attempts against known vulnerable / high-risk target ports
    (SMB 445, RDP 3389, Telnet 23, VNC 5900, Redis 6379, etc.).
    """
    def __init__(self, suspicious_ports=Config.SUSPICIOUS_PORTS):
        super().__init__(
            name="Suspicious Port Probe",
            description="Probe against critical administrative or exploit-prone service port",
            severity="HIGH"
        )
        self.suspicious_ports = suspicious_ports

    def evaluate(self, packet):
        if not self.enabled:
            return None
            
        dst_port = packet.get("dst_port")
        if not dst_port or dst_port not in self.suspicious_ports:
            return None
            
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        service_desc = self.suspicious_ports[dst_port]
        
        now = time.time()
        if self.can_alert(src_ip, now):
            severity = "CRITICAL" if dst_port in (445, 23, 3389) else "HIGH"
            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip or "Target",
                "detection_type": f"Suspicious Port Probe ({dst_port})",
                "severity": severity,
                "is_confirmed_attack": False,
                "description": (
                    f"Traffic from {src_ip} initiated contact with protected service "
                    f"port {dst_port} [{service_desc}]."
                ),
                "recommendation": (
                    f"Verify if port {dst_port} must be reachable from {src_ip}. "
                    "Restrict inbound access using Security Group / Host Firewall."
                )
            }
        return None

class StealthScanRule(BaseRule):
    """
    Detects classic Nmap stealth scans based on TCP flag combinations:
    - NULL Scan: No flags set (flags = "")
    - XMAS Scan: FIN, PSH, URG all set
    - FIN Scan: Only FIN set without ACK/SYN
    """
    def __init__(self):
        super().__init__(
            name="Stealth TCP Scan Detected",
            description="Abnormal TCP flag combination indicative of Nmap stealth reconnaissance",
            severity="HIGH"
        )

    def evaluate(self, packet):
        if not self.enabled or packet.get("protocol") != "TCP":
            return None
            
        flags = str(packet.get("flags", "")).upper()
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        dst_port = packet.get("dst_port", 0)
        
        scan_type = None
        if flags == "" or flags == "0":
            scan_type = "NULL Scan (No TCP Flags Set)"
        elif "F" in flags and "P" in flags and "U" in flags:
            scan_type = "XMAS Scan (FIN+PSH+URG Flags Set)"
        elif flags == "F":
            scan_type = "FIN Scan (Unsolicited FIN Flag)"
            
        if scan_type:
            now = time.time()
            if self.can_alert(src_ip, now):
                return {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip or "Target",
                    "detection_type": f"Stealth Scan: {scan_type}",
                    "severity": self.severity,
                    "is_confirmed_attack": True,
                    "description": (
                        f"Detected abnormal TCP signature from {src_ip} targeting port {dst_port}. "
                        f"Pattern matches {scan_type} designed to bypass stateless packet filters."
                    ),
                    "recommendation": (
                        "Drop TCP packets with invalid flag combinations at network perimeter. "
                        f"Investigate source {src_ip} for active port scanning activity."
                    )
                }
        return None

class BlocklistRule(BaseRule):
    """Matches traffic against active threat blocklist."""
    def __init__(self, blocklist_set=None):
        super().__init__(
            name="Threat Blocklist Match",
            description="Connection with known malicious / blacklisted IP address",
            severity="CRITICAL"
        )
        self.blocklist_set = set(blocklist_set or [])

    def update_blocklist(self, ip_set):
        self.blocklist_set = set(ip_set)

    def evaluate(self, packet):
        if not self.enabled or not self.blocklist_set:
            return None
            
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        
        matched_ip = None
        if src_ip in self.blocklist_set:
            matched_ip = src_ip
        elif dst_ip in self.blocklist_set:
            matched_ip = dst_ip
            
        if matched_ip:
            now = time.time()
            if self.can_alert(matched_ip, now):
                return {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "detection_type": self.name,
                    "severity": self.severity,
                    "is_confirmed_attack": True,
                    "description": (
                        f"Observed network exchange involving blocked threat IP {matched_ip}. "
                        "Host matches active blacklist / cyber threat intelligence feed."
                    ),
                    "recommendation": (
                        f"Immediately terminate session and drop all packets for {matched_ip}. "
                        "Inspect internal endpoint for signs of compromise or C2 beaconing."
                    )
                }
        return None

class ConnectionFrequencyRule(BaseRule):
    """Detects abnormal overall connection frequency / packet bursts from a single IP."""
    def __init__(self, threshold=Config.CONN_FREQ_THRESHOLD, window_seconds=Config.CONN_FREQ_WINDOW):
        super().__init__(
            name="Unusual Connection Frequency",
            description="Excessive volumetric packet rate from single origin",
            severity="MEDIUM"
        )
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.history = defaultdict(deque)

    def evaluate(self, packet):
        if not self.enabled:
            return None
            
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        if not src_ip:
            return None
            
        now = time.time()
        dq = self.history[src_ip]
        dq.append(now)
        
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()
            
        if len(dq) >= self.threshold:
            if self.can_alert(src_ip, now):
                return {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip or "Multiple",
                    "detection_type": self.name,
                    "severity": self.severity,
                    "is_confirmed_attack": False,
                    "description": (
                        f"Origin {src_ip} generated {len(dq)} packets in {self.window_seconds}s, "
                        f"surpassing rate threshold of {self.threshold}."
                    ),
                    "recommendation": (
                        "Implement connection throttling at web server/proxy layer (e.g. nginx limit_req). "
                        "Investigate user-agent and requested URIs."
                    )
                }
        return None

