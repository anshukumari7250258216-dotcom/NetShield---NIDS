"""
NetShield-NIDS - Unit Tests for Intrusion Detection Rules
Validates stateful sliding-window logic and attack signature detection.
"""
import pytest
import time
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detection.rules import (
    PortScanRule,
    SynFloodRule,
    IcmpFloodRule,
    SuspiciousPortRule,
    StealthScanRule,
    BlocklistRule,
    ConnectionFrequencyRule
)

def test_port_scan_detection():
    """Verify that scanning >= threshold distinct ports triggers a high-severity alert."""
    rule = PortScanRule(threshold=5, window_seconds=10)
    src_ip = "192.168.1.80"
    dst_ip = "192.168.1.10"
    
    alert = None
    for port in [80, 443, 22, 21]:
        packet = {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": port, "protocol": "TCP"}
        alert = rule.evaluate(packet)
    assert alert is None, "Should not alert before threshold is crossed"

    packet = {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": 8080, "protocol": "TCP"}
    alert = rule.evaluate(packet)
    
    assert alert is not None
    assert alert["severity"] == "HIGH"
    assert alert["src_ip"] == src_ip
    assert alert["is_confirmed_attack"] is True
    assert "Port Scan Detected" in alert["detection_type"]

def test_syn_flood_detection():
    """Verify TCP SYN packet flood triggers critical alert."""
    rule = SynFloodRule(threshold=10, window_seconds=5)
    src_ip = "10.0.0.99"
    dst_ip = "10.0.0.1"

    alert = None
    for _ in range(9):
        packet = {
            "src_ip": src_ip, "dst_ip": dst_ip, "protocol": "TCP",
            "dst_port": 80, "flags": "S"
        }
        alert = rule.evaluate(packet)
    assert alert is None

    packet = {
        "src_ip": src_ip, "dst_ip": dst_ip, "protocol": "TCP",
        "dst_port": 80, "flags": "S"
    }
    alert = rule.evaluate(packet)
    assert alert is not None
    assert alert["severity"] == "CRITICAL"
    assert "SYN Flood" in alert["detection_type"]

def test_icmp_flood_and_oversized():
    """Verify ICMP flood and oversized ICMP anomaly detection."""
    rule = IcmpFloodRule(threshold=5, window_seconds=5, max_size=500)
    src_ip = "172.16.0.40"
    dst_ip = "172.16.0.1"

    huge_packet = {
        "src_ip": src_ip, "dst_ip": dst_ip, "protocol": "ICMP",
        "packet_size": 1500
    }
    alert = rule.evaluate(huge_packet)
    assert alert is not None
    assert "Oversized ICMP" in alert["detection_type"]

    rule.cooldown_period = 0
    rule.last_alert_time.clear()
    
    alert = None
    for _ in range(5):
        pkt = {"src_ip": "172.16.0.99", "dst_ip": dst_ip, "protocol": "ICMP", "packet_size": 64}
        alert = rule.evaluate(pkt)
    assert alert is not None
    assert "ICMP Ping Flood" in alert["detection_type"]

def test_suspicious_port_probe():
    """Verify detection of probes to known exploit vectors like SMB 445."""
    rule = SuspiciousPortRule()
    packet = {
        "src_ip": "203.0.113.5",
        "dst_ip": "192.168.1.10",
        "dst_port": 445,
        "protocol": "TCP"
    }
    alert = rule.evaluate(packet)
    assert alert is not None
    assert alert["severity"] == "CRITICAL"
    assert "445" in alert["detection_type"]

def test_stealth_scans():
    """Verify detection of Nmap NULL, XMAS, and FIN scans."""
    rule = StealthScanRule()

    null_pkt = {
        "src_ip": "198.51.100.12", "dst_ip": "10.0.0.5",
        "dst_port": 80, "protocol": "TCP", "flags": ""
    }
    alert = rule.evaluate(null_pkt)
    assert alert is not None
    assert "NULL Scan" in alert["detection_type"]

    rule.last_alert_time.clear()
    xmas_pkt = {
        "src_ip": "198.51.100.12", "dst_ip": "10.0.0.5",
        "dst_port": 80, "protocol": "TCP", "flags": "FPU"
    }
    alert = rule.evaluate(xmas_pkt)
    assert alert is not None
    assert "XMAS Scan" in alert["detection_type"]

def test_blocklist_rule():
    """Verify traffic from blacklisted IP immediately triggers critical alert."""
    rule = BlocklistRule(blocklist_set=["198.51.100.23", "203.0.113.88"])
    
    clean_pkt = {"src_ip": "192.168.1.50", "dst_ip": "8.8.8.8", "protocol": "UDP"}
    assert rule.evaluate(clean_pkt) is None

    bad_pkt = {"src_ip": "198.51.100.23", "dst_ip": "192.168.1.10", "protocol": "TCP"}
    alert = rule.evaluate(bad_pkt)
    assert alert is not None
    assert alert["severity"] == "CRITICAL"
    assert "Blocklist" in alert["detection_type"]

