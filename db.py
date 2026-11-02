"""
NetShield-NIDS - Database Management Module
Handles SQLite schema creation, thread-safe connection pooling,
user authentication records, packet event telemetry, and SOC analytics.
"""
import sqlite3
import os
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config

def get_db_path():
    """Retrieve the configured database path and ensure parent directory exists."""
    db_path = Config.DATABASE_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    return db_path

@contextmanager
def get_db():
    """Context manager for thread-safe SQLite database connections."""
    conn = sqlite3.connect(
        get_db_path(),
        timeout=15.0,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initialize database tables, indexes, default configuration, and default admin user."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Users Table (Authentication & Access Control)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT DEFAULT 'Analyst',
                created_at TEXT NOT NULL,
                last_login TEXT
            );
        """)
        
        # 2. Events Table (Network Traffic Telemetry)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                packet_size INTEGER DEFAULT 0,
                flags TEXT DEFAULT '',
                info TEXT DEFAULT '',
                is_suspicious INTEGER DEFAULT 0
            );
        """)
        
        # 3. Alerts Table (Detected Security Incidents)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                detection_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                is_confirmed_attack INTEGER DEFAULT 0,
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                status TEXT DEFAULT 'New',
                notes TEXT DEFAULT ''
            );
        """)
        
        # 4. Settings Table (Key-Value Dynamic Configuration)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        
        # 5. Threat Intelligence Blocklist Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                reason TEXT NOT NULL,
                added_at TEXT NOT NULL
            );
        """)
        
        # Performance Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_suspicious ON events(is_suspicious);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_ip ON blocklist(ip);")
        
        # Default Settings
        now_str = datetime.now(timezone.utc).isoformat()
        default_settings = {
            "port_scan_threshold": str(Config.PORT_SCAN_THRESHOLD),
            "port_scan_window": str(Config.PORT_SCAN_WINDOW),
            "syn_flood_threshold": str(Config.SYN_FLOOD_THRESHOLD),
            "syn_flood_window": str(Config.SYN_FLOOD_WINDOW),
            "icmp_flood_threshold": str(Config.ICMP_FLOOD_THRESHOLD),
            "icmp_flood_window": str(Config.ICMP_FLOOD_WINDOW),
            "conn_freq_threshold": str(Config.CONN_FREQ_THRESHOLD),
            "conn_freq_window": str(Config.CONN_FREQ_WINDOW),
            "theme": "dark"
        }
        for k, v in default_settings.items():
            cursor.execute("""
                INSERT OR IGNORE INTO settings (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (k, v, now_str))
            
        # Default Blocklist
        cursor.execute("SELECT COUNT(*) as count FROM blocklist;")
        if cursor.fetchone()["count"] == 0:
            for item in Config.DEFAULT_BLOCKLIST:
                cursor.execute("""
                    INSERT OR IGNORE INTO blocklist (ip, reason, added_at)
                    VALUES (?, ?, ?)
                """, (item["ip"], item["reason"], now_str))
                
        # Default Admin User
        cursor.execute("SELECT COUNT(*) as count FROM users;")
        if cursor.fetchone()["count"] == 0:
            admin_hash = generate_password_hash("Admin@123")
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, full_name, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ("admin", "admin@netshield.local", admin_hash, "SOC Security Administrator", "Admin", now_str))

# ============================================================================
# USER AUTHENTICATION & PROFILE OPERATIONS
# ============================================================================

def create_user(username, email, password, full_name, role="Analyst"):
    """
    Create a new user record with securely hashed password.
    Returns (user_id, error_message).
    """
    username = username.strip().lower()
    email = email.strip().lower()
    full_name = full_name.strip()
    
    if len(password) < 6:
        return None, "Password must be at least 6 characters long."
        
    password_hash = generate_password_hash(password)
    now_str = datetime.now(timezone.utc).isoformat()
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            return None, "A user with this username or email already exists."
            
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, email, password_hash, full_name, role, now_str))
        return cursor.lastrowid, None

def authenticate_user(identifier, password):
    """
    Authenticate a user by username or email.
    Returns user dictionary (without password_hash) on success, or None on failure.
    """
    identifier = identifier.strip().lower()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1
        """, (identifier, identifier))
        row = cursor.fetchone()
        
        if row and check_password_hash(row["password_hash"], password):
            user_dict = dict(row)
            user_dict.pop("password_hash", None)
            
            # Update last_login
            now_str = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_str, user_dict["id"]))
            user_dict["last_login"] = now_str
            return user_dict
            
    return None

def get_user_by_id(user_id):
    """Retrieve user dictionary by primary key."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, full_name, role, created_at, last_login FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_username(username):
    """Retrieve user dictionary by username."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, full_name, role, created_at, last_login FROM users WHERE username = ?", (username.strip().lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_all_users():
    """Retrieve list of all registered users."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, full_name, role, created_at, last_login FROM users ORDER BY id ASC")
        return [dict(r) for r in cursor.fetchall()]

# ============================================================================
# EVENT OPERATIONS (NETWORK TRAFFIC)
# ============================================================================

def insert_event(event_dict):
    """Insert a single network packet event with parameterized query."""
    timestamp = event_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO events (
                timestamp, src_ip, dst_ip, src_port, dst_port,
                protocol, packet_size, flags, info, is_suspicious
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            str(event_dict.get("src_ip", "")),
            str(event_dict.get("dst_ip", "")),
            event_dict.get("src_port"),
            event_dict.get("dst_port"),
            str(event_dict.get("protocol", "OTHER")).upper(),
            int(event_dict.get("packet_size", 0)),
            str(event_dict.get("flags", "")),
            str(event_dict.get("info", "")),
            1 if event_dict.get("is_suspicious") else 0
        ))
        return cursor.lastrowid

def insert_events_batch(events_list):
    """Insert multiple packet events in a single batch transaction."""
    if not events_list:
        return
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.executemany("""
            INSERT INTO events (
                timestamp, src_ip, dst_ip, src_port, dst_port,
                protocol, packet_size, flags, info, is_suspicious
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            (
                e.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                str(e.get("src_ip", "")),
                str(e.get("dst_ip", "")),
                e.get("src_port"),
                e.get("dst_port"),
                str(e.get("protocol", "OTHER")).upper(),
                int(e.get("packet_size", 0)),
                str(e.get("flags", "")),
                str(e.get("info", "")),
                1 if e.get("is_suspicious") else 0
            )
            for e in events_list
        ])

def get_events(limit=100, offset=0, filter_ip=None, filter_protocol=None, filter_suspicious=None, search=None):
    """Retrieve filtered events with pagination."""
    query = "SELECT * FROM events WHERE 1=1"
    params = []
    
    if filter_ip:
        query += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
        params.extend([f"%{filter_ip}%", f"%{filter_ip}%"])
        
    if filter_protocol and filter_protocol.upper() != "ALL":
        query += " AND protocol = ?"
        params.append(filter_protocol.upper())
        
    if filter_suspicious is not None:
        query += " AND is_suspicious = ?"
        params.append(1 if filter_suspicious else 0)
        
    if search:
        query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR info LIKE ? OR flags LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term])
        
    count_query = query.replace("SELECT *", "SELECT COUNT(*) as count", 1)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(count_query, params[:-2])
        total = cursor.fetchone()["count"]
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        
    return {"total": total, "events": rows, "limit": limit, "offset": offset}

# ============================================================================
# ALERT OPERATIONS (INTRUSION INCIDENTS)
# ============================================================================

def insert_alert(alert_dict):
    """Insert a security alert record with parameterized query."""
    timestamp = alert_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (
                timestamp, src_ip, dst_ip, detection_type, severity,
                is_confirmed_attack, description, recommendation, status, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            str(alert_dict.get("src_ip", "")),
            str(alert_dict.get("dst_ip", "")),
            str(alert_dict.get("detection_type", "Unknown Anomaly")),
            str(alert_dict.get("severity", "MEDIUM")).upper(),
            1 if alert_dict.get("is_confirmed_attack") else 0,
            str(alert_dict.get("description", "")),
            str(alert_dict.get("recommendation", "")),
            str(alert_dict.get("status", "New")),
            str(alert_dict.get("notes", ""))
        ))
        return cursor.lastrowid

def get_alerts(limit=50, offset=0, severity=None, status=None, search=None):
    """Retrieve alerts with multi-criteria filtering and pagination."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    
    if severity and severity.upper() != "ALL":
        query += " AND severity = ?"
        params.append(severity.upper())
        
    if status and status.upper() != "ALL":
        query += " AND status = ?"
        params.append(status)
        
    if search:
        query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR detection_type LIKE ? OR description LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term])
        
    count_query = query.replace("SELECT *", "SELECT COUNT(*) as count", 1)
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(count_query, params[:-2])
        total = cursor.fetchone()["count"]
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        
    return {"total": total, "alerts": rows, "limit": limit, "offset": offset}

def get_alert_by_id(alert_id):
    """Retrieve a single alert by primary key."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def update_alert_status(alert_id, status, notes=None):
    """Update alert triage status and optional analyst investigation notes."""
    valid_statuses = {"New", "Investigating", "Resolved"}
    if status not in valid_statuses:
        raise ValueError(f"Invalid status: {status}. Must be one of {valid_statuses}")
        
    with get_db() as conn:
        cursor = conn.cursor()
        if notes is not None:
            cursor.execute("""
                UPDATE alerts SET status = ?, notes = ? WHERE id = ?
            """, (status, notes, alert_id))
        else:
            cursor.execute("""
                UPDATE alerts SET status = ? WHERE id = ?
            """, (status, alert_id))
        return cursor.rowcount > 0

# ============================================================================
# SOC DASHBOARD & ANALYTICS AGGREGATION
# ============================================================================

def get_dashboard_stats():
    """Aggregate statistics, KPIs, and time-series metrics for the SOC dashboard."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Total Events
        cursor.execute("SELECT COUNT(*) as total FROM events;")
        total_events = cursor.fetchone()["total"]
        
        # Suspicious Events
        cursor.execute("SELECT COUNT(*) as total FROM events WHERE is_suspicious = 1;")
        suspicious_events = cursor.fetchone()["total"]
        
        # Critical Alerts
        cursor.execute("SELECT COUNT(*) as total FROM alerts WHERE severity = 'CRITICAL';")
        critical_alerts = cursor.fetchone()["total"]
        
        # Total Alerts
        cursor.execute("SELECT COUNT(*) as total FROM alerts;")
        total_alerts = cursor.fetchone()["total"]
        
        # Unique Source IPs
        cursor.execute("SELECT COUNT(DISTINCT src_ip) as total FROM events;")
        unique_ips = cursor.fetchone()["total"]
        
        # Severity Distribution
        cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
        severity_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for row in cursor.fetchall():
            sev = row["severity"].upper()
            if sev in severity_dist:
                severity_dist[sev] = row["count"]
                
        # Threat Category Distribution
        cursor.execute("""
            SELECT detection_type, COUNT(*) as count
            FROM alerts
            GROUP BY detection_type
            ORDER BY count DESC
            LIMIT 6
        """)
        threat_dist = [dict(r) for r in cursor.fetchall()]
        
        # Top Targeted Destination Ports
        cursor.execute("""
            SELECT dst_port, COUNT(*) as count
            FROM events
            WHERE dst_port IS NOT NULL AND dst_port > 0
            GROUP BY dst_port
            ORDER BY count DESC
            LIMIT 6
        """)
        top_ports = [dict(r) for r in cursor.fetchall()]
        
        # Top Attacker IPs
        cursor.execute("""
            SELECT src_ip, COUNT(*) as count
            FROM alerts
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 5
        """)
        top_attackers = [dict(r) for r in cursor.fetchall()]
        
        # Recent Alerts (latest 5)
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5;")
        recent_alerts = [dict(r) for r in cursor.fetchall()]
        
        # Recent Events (latest 10)
        cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 10;")
        recent_events = [dict(r) for r in cursor.fetchall()]
        
        # Traffic Velocity Timeline (recent 12 segments)
        cursor.execute("""
            SELECT 
                SUBSTR(timestamp, 12, 5) as time_slot,
                COUNT(*) as total_count,
                SUM(is_suspicious) as suspicious_count
            FROM events
            GROUP BY SUBSTR(timestamp, 1, 16)
            ORDER BY id DESC
            LIMIT 12
        """)
        raw_timeline = cursor.fetchall()
        timeline = []
        for r in reversed(raw_timeline):
            timeline.append({
                "time": r["time_slot"] or "00:00",
                "normal": (r["total_count"] or 0) - (r["suspicious_count"] or 0),
                "suspicious": r["suspicious_count"] or 0
            })
            
    return {
        "kpis": {
            "total_events": total_events,
            "suspicious_events": suspicious_events,
            "critical_alerts": critical_alerts,
            "total_alerts": total_alerts,
            "unique_ips": unique_ips
        },
        "severity_dist": severity_dist,
        "threat_dist": threat_dist,
        "top_ports": top_ports,
        "top_attackers": top_attackers,
        "timeline": timeline,
        "recent_alerts": recent_alerts,
        "recent_events": recent_events
    }

# ============================================================================
# IP HISTORY CORRELATION
# ============================================================================

def get_ip_history(ip):
    """Retrieve full activity history and alert records for a specific IP."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total_packets,
                SUM(CASE WHEN src_ip = ? THEN 1 ELSE 0 END) as outbound_count,
                SUM(CASE WHEN dst_ip = ? THEN 1 ELSE 0 END) as inbound_count,
                SUM(is_suspicious) as suspicious_count,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM events
            WHERE src_ip = ? OR dst_ip = ?
        """, (ip, ip, ip, ip))
        stats = dict(cursor.fetchone() or {})
        
        cursor.execute("""
            SELECT * FROM alerts
            WHERE src_ip = ? OR dst_ip = ?
            ORDER BY id DESC LIMIT 20
        """, (ip, ip))
        alerts = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute("""
            SELECT dst_port, COUNT(*) as count
            FROM events
            WHERE src_ip = ? AND dst_port IS NOT NULL
            GROUP BY dst_port
            ORDER BY count DESC LIMIT 10
        """, (ip,))
        targeted_ports = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute("""
            SELECT protocol, COUNT(*) as count
            FROM events
            WHERE src_ip = ? OR dst_ip = ?
            GROUP BY protocol
        """, (ip, ip))
        protocols = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute("""
            SELECT * FROM events
            WHERE src_ip = ? OR dst_ip = ?
            ORDER BY id DESC LIMIT 15
        """, (ip, ip))
        recent_packets = [dict(r) for r in cursor.fetchall()]
        
    return {
        "ip": ip,
        "stats": stats,
        "alerts": alerts,
        "targeted_ports": targeted_ports,
        "protocols": protocols,
        "recent_packets": recent_packets
    }

# ============================================================================
# SETTINGS & BLOCKLIST OPERATIONS
# ============================================================================

def get_settings():
    """Retrieve application settings dictionary."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM settings;")
        return {row["key"]: row["value"] for row in cursor.fetchall()}

def save_setting(key, value):
    """Upsert a setting entry."""
    now_str = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """, (key, str(value), now_str))

def get_blocklist():
    """Retrieve all blocked IPs."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocklist ORDER BY id DESC;")
        return [dict(r) for r in cursor.fetchall()]

def add_to_blocklist(ip, reason="Manual Block / Threat Intelligence"):
    """Add an IP to the blocklist."""
    now_str = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO blocklist (ip, reason, added_at)
            VALUES (?, ?, ?)
        """, (ip.strip(), reason.strip(), now_str))

def remove_from_blocklist(ip):
    """Remove an IP from the blocklist."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blocklist WHERE ip = ?", (ip.strip(),))
        return cursor.rowcount > 0

def is_ip_blocked(ip):
    """Check if an IP is currently listed in the blocklist."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM blocklist WHERE ip = ? LIMIT 1;", (ip.strip(),))
        return cursor.fetchone() is not None

# ============================================================================
# MAINTENANCE & DEMO DATA SEEDING
# ============================================================================

def clear_database():
    """Clear network events and alerts."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM events;")
        cursor.execute("DELETE FROM alerts;")
        cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('events', 'alerts');")

def seed_demo_data():
    """
    Populate realistic SOC baseline events and detected intrusion attacks.
    Demonstrates port scanning, SYN floods, ICMP storms, exploit probing,
    and threat blocklist hits.
    """
    now = datetime.now(timezone.utc)
    events_to_insert = []
    alerts_to_insert = []
    
    # 1. Normal Benign Traffic Samples (Web, DNS, TLS, NTP)
    normal_ips = ["192.168.1.15", "192.168.1.42", "192.168.1.108", "10.0.0.55"]
    gateway = "192.168.1.1"
    dns_server = "8.8.8.8"
    
    for i in range(40):
        t = (now - timedelta(minutes=45 - i)).isoformat()
        src = normal_ips[i % len(normal_ips)]
        port = [443, 80, 53, 123][i % 4]
        dst = "142.250.190.46" if port in (80, 443) else dns_server
        proto = "UDP" if port in (53, 123) else "TCP"
        size = 120 + (i * 37) % 800
        flags = "PA" if proto == "TCP" else ""
        info = f"Standard {proto} Application Exchange"
        events_to_insert.append({
            "timestamp": t,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": 50000 + i,
            "dst_port": port,
            "protocol": proto,
            "packet_size": size,
            "flags": flags,
            "info": info,
            "is_suspicious": False
        })
        
    # 2. Attack Scenario: Horizontal Port Scan (Attacker: 45.33.32.156)
    attacker_1 = "45.33.32.156"
    target_server = "192.168.1.10"
    scan_ports = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080]
    scan_start = now - timedelta(minutes=25)
    for idx, p in enumerate(scan_ports):
        t = (scan_start + timedelta(seconds=idx * 0.8)).isoformat()
        events_to_insert.append({
            "timestamp": t,
            "src_ip": attacker_1,
            "dst_ip": target_server,
            "src_port": 41234 + idx,
            "dst_port": p,
            "protocol": "TCP",
            "packet_size": 44,
            "flags": "S",
            "info": f"SYN probe to port {p}",
            "is_suspicious": True
        })
    alerts_to_insert.append({
        "timestamp": (scan_start + timedelta(seconds=12)).isoformat(),
        "src_ip": attacker_1,
        "dst_ip": target_server,
        "detection_type": "Port Scan Detected",
        "severity": "HIGH",
        "is_confirmed_attack": True,
        "description": f"Host {attacker_1} probed {len(scan_ports)} distinct ports on {target_server} within 12 seconds.",
        "recommendation": f"Add {attacker_1} to the border firewall drop table (e.g. iptables -A INPUT -s {attacker_1} -j DROP).",
        "status": "New",
        "notes": "Automated scan signature detected matching Nmap horizontal recon."
    })
    
    # 3. Attack Scenario: TCP SYN Flood / DoS (Attacker: 185.190.140.77)
    attacker_2 = "185.190.140.77"
    flood_start = now - timedelta(minutes=15)
    for j in range(30):
        t = (flood_start + timedelta(seconds=j * 0.1)).isoformat()
        events_to_insert.append({
            "timestamp": t,
            "src_ip": attacker_2,
            "dst_ip": target_server,
            "src_port": 30000 + j,
            "dst_port": 80,
            "protocol": "TCP",
            "packet_size": 60,
            "flags": "S",
            "info": "Rapid TCP SYN without ACK handshake",
            "is_suspicious": True
        })
    alerts_to_insert.append({
        "timestamp": (flood_start + timedelta(seconds=3)).isoformat(),
        "src_ip": attacker_2,
        "dst_ip": target_server,
        "detection_type": "SYN Flood / Connection Burst",
        "severity": "CRITICAL",
        "is_confirmed_attack": True,
        "description": f"High frequency SYN flood from {attacker_2}: 30 SYN packets within 3.0s targeting HTTP port 80.",
        "recommendation": "Enable SYN cookies on target kernel (sysctl -w net.ipv4.tcp_syncookies=1) and rate-limit source IP at edge router.",
        "status": "Investigating",
        "notes": "SOC Analyst initiated connection rate-limiting rule."
    })
    
    # 4. Attack Scenario: SMB EternalBlue Exploit Probe (Port 445)
    attacker_3 = "104.244.42.1"
    smb_time = (now - timedelta(minutes=8)).isoformat()
    events_to_insert.append({
        "timestamp": smb_time,
        "src_ip": attacker_3,
        "dst_ip": target_server,
        "src_port": 54112,
        "dst_port": 445,
        "protocol": "TCP",
        "packet_size": 178,
        "flags": "PA",
        "info": "SMBv1 negotiate protocol probe to port 445",
        "is_suspicious": True
    })
    alerts_to_insert.append({
        "timestamp": smb_time,
        "src_ip": attacker_3,
        "dst_ip": target_server,
        "detection_type": "Suspicious Port Probe (SMB)",
        "severity": "HIGH",
        "is_confirmed_attack": False,
        "description": f"External host {attacker_3} initiated unauthorized SMB connection to port 445 (EternalBlue/WannaCry vector).",
        "recommendation": "Block inbound port 445 from WAN interfaces immediately. Verify SMBv1 is disabled on internal hosts.",
        "status": "New",
        "notes": ""
    })
    
    # 5. Attack Scenario: Threat Blocklist Match (Attacker: 198.51.100.23)
    bl_ip = "198.51.100.23"
    bl_time = (now - timedelta(minutes=4)).isoformat()
    events_to_insert.append({
        "timestamp": bl_time,
        "src_ip": bl_ip,
        "dst_ip": "192.168.1.100",
        "src_port": 61299,
        "dst_port": 22,
        "protocol": "TCP",
        "packet_size": 74,
        "flags": "S",
        "info": "Inbound SSH connection attempt from threat feed IP",
        "is_suspicious": True
    })
    alerts_to_insert.append({
        "timestamp": bl_time,
        "src_ip": bl_ip,
        "dst_ip": "192.168.1.100",
        "detection_type": "Threat Intelligence Blocklist Match",
        "severity": "CRITICAL",
        "is_confirmed_attack": True,
        "description": f"IP {bl_ip} matches active threat blocklist: Known Tor Exit Node / Scanner.",
        "recommendation": "Drop all existing sessions and enforce automatic blacklisting on edge firewalls.",
        "status": "Resolved",
        "notes": "IP automatically dropped at perimeter gateway."
    })
    
    insert_events_batch(events_to_insert)
    for a in alerts_to_insert:
        insert_alert(a)

