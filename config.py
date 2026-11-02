"""
NetShield-NIDS - Configuration Module
Defines runtime configurations, detection thresholds, security policies, and path definitions.
"""
import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("NETSHIELD_SECRET_KEY") or secrets.token_hex(32)
    
    # SQLite Database File
    DATABASE_PATH = os.environ.get(
        "NETSHIELD_DB_PATH",
        os.path.join(BASE_DIR, "database", "netshield.db")
    )
    
    # Offline PCAP Upload Configuration
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max PCAP upload
    
    # Intrusion Detection Sliding Window Thresholds (Configurable via Settings / DB)
    PORT_SCAN_THRESHOLD = int(os.environ.get("NETSHIELD_PORT_SCAN_THRESHOLD", 10))
    PORT_SCAN_WINDOW = int(os.environ.get("NETSHIELD_PORT_SCAN_WINDOW", 15))  # seconds
    
    SYN_FLOOD_THRESHOLD = int(os.environ.get("NETSHIELD_SYN_FLOOD_THRESHOLD", 25))
    SYN_FLOOD_WINDOW = int(os.environ.get("NETSHIELD_SYN_FLOOD_WINDOW", 5))    # seconds
    
    ICMP_FLOOD_THRESHOLD = int(os.environ.get("NETSHIELD_ICMP_FLOOD_THRESHOLD", 15))
    ICMP_FLOOD_WINDOW = int(os.environ.get("NETSHIELD_ICMP_FLOOD_WINDOW", 5))   # seconds
    ICMP_MAX_PAYLOAD_SIZE = int(os.environ.get("NETSHIELD_ICMP_MAX_SIZE", 1024)) # bytes
    
    CONN_FREQ_THRESHOLD = int(os.environ.get("NETSHIELD_CONN_FREQ_THRESHOLD", 60))
    CONN_FREQ_WINDOW = int(os.environ.get("NETSHIELD_CONN_FREQ_WINDOW", 10))  # seconds
    
    # Sensitive Target Service Ports
    SUSPICIOUS_PORTS = {
        21: "FTP (File Transfer)",
        22: "SSH (Secure Shell Brute Force Target)",
        23: "Telnet (Insecure Remote Access)",
        25: "SMTP (Mail Relay)",
        53: "DNS (Potential Tunneling/Amplification)",
        110: "POP3 (Mail)",
        135: "MS-RPC (Endpoint Mapper)",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        445: "SMB (EternalBlue / WannaCry Exploit Vector)",
        1433: "MS SQL Server",
        1521: "Oracle DB",
        3306: "MySQL Database",
        3389: "RDP (Remote Desktop / BlueKeep Vector)",
        5432: "PostgreSQL Database",
        5900: "VNC Remote Desktop",
        6379: "Redis (Unauthorized Access Target)",
        8080: "HTTP Proxy / Alternative Web Server",
        9200: "Elasticsearch REST API",
        27017: "MongoDB Database"
    }
    
    # Default Threat Intelligence Blocklist (RFC 5737 Documentation IPs)
    DEFAULT_BLOCKLIST = [
        {"ip": "198.51.100.23", "reason": "Known Tor Exit Node / Scanner"},
        {"ip": "203.0.113.88", "reason": "Automated Botnet Command & Control"},
        {"ip": "192.0.2.44", "reason": "Persistent Credential Stuffing Origin"},
        {"ip": "185.220.101.5", "reason": "Reported Malicious Reconnaissance Node"}
    ]
    
    # System Metadata
    PROJECT_NAME = "NetShield-NIDS"
    PROJECT_FULL_NAME = "Network Intrusion Detection System"
    VERSION = "2.0.0 SOC Edition"
    DESCRIPTION = "Enterprise-Grade Network Intrusion Detection & Real-Time Monitoring System"

