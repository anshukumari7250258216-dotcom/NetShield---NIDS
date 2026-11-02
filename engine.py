"""
NetShield-NIDS - Detection Engine Core
Coordinates rule evaluation, sliding-window state tracking,
and dynamic threshold configuration.
"""
import threading
from detection.rules import (
    PortScanRule,
    SynFloodRule,
    IcmpFloodRule,
    SuspiciousPortRule,
    StealthScanRule,
    BlocklistRule,
    ConnectionFrequencyRule
)
from database.db import get_settings, get_blocklist

class DetectionEngine:
    """Central engine orchestrating all rule-based intrusion checks."""
    
    def __init__(self, init_from_db=True):
        self._lock = threading.Lock()
        self.port_scan_rule = PortScanRule()
        self.syn_flood_rule = SynFloodRule()
        self.icmp_flood_rule = IcmpFloodRule()
        self.suspicious_port_rule = SuspiciousPortRule()
        self.stealth_scan_rule = StealthScanRule()
        self.blocklist_rule = BlocklistRule()
        self.conn_freq_rule = ConnectionFrequencyRule()
        
        self.rules = [
            self.blocklist_rule,
            self.stealth_scan_rule,
            self.port_scan_rule,
            self.syn_flood_rule,
            self.icmp_flood_rule,
            self.suspicious_port_rule,
            self.conn_freq_rule
        ]
        
        if init_from_db:
            try:
                self.reload_from_db()
            except Exception:
                pass

    def reload_from_db(self):
        """Sync thresholds and active threat blocklist with SQLite store."""
        with self._lock:
            try:
                settings = get_settings()
                if "port_scan_threshold" in settings:
                    self.port_scan_rule.threshold = int(settings["port_scan_threshold"])
                if "port_scan_window" in settings:
                    self.port_scan_rule.window_seconds = int(settings["port_scan_window"])
                    
                if "syn_flood_threshold" in settings:
                    self.syn_flood_rule.threshold = int(settings["syn_flood_threshold"])
                if "syn_flood_window" in settings:
                    self.syn_flood_rule.window_seconds = int(settings["syn_flood_window"])
                    
                if "icmp_flood_threshold" in settings:
                    self.icmp_flood_rule.threshold = int(settings["icmp_flood_threshold"])
                if "icmp_flood_window" in settings:
                    self.icmp_flood_rule.window_seconds = int(settings["icmp_flood_window"])
                    
                if "conn_freq_threshold" in settings:
                    self.conn_freq_rule.threshold = int(settings["conn_freq_threshold"])
                if "conn_freq_window" in settings:
                    self.conn_freq_rule.window_seconds = int(settings["conn_freq_window"])
                    
                # Update blocklist
                bl_entries = get_blocklist()
                ip_set = {entry["ip"] for entry in bl_entries}
                self.blocklist_rule.update_blocklist(ip_set)
            except Exception:
                pass

    def update_blocklist(self, ip_set):
        """Update active blocklist memory cache."""
        with self._lock:
            self.blocklist_rule.update_blocklist(ip_set)

    def analyze_packet(self, packet):
        """
        Evaluate an incoming packet dictionary against all configured detection rules.
        Returns: (is_suspicious: bool, triggered_alerts: list[dict])
        """
        triggered_alerts = []
        with self._lock:
            for rule in self.rules:
                try:
                    alert = rule.evaluate(packet)
                    if alert:
                        triggered_alerts.append(alert)
                except Exception:
                    continue
                    
        is_suspicious = len(triggered_alerts) > 0
        return is_suspicious, triggered_alerts

# Global shared instance
engine_instance = DetectionEngine()

