import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

DB_PATH = os.environ.get("YNETMON_DB", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "ynetmon.db"))
_write_lock = threading.Lock()
_device_buffer_lock = threading.Lock()
_device_buffer: Dict[str, Dict[str, Any]] = {}
_last_device_flush: float = time.time()


def get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    return conn


def init_db() -> None:
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("PRAGMA auto_vacuum=INCREMENTAL;")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                csrf_token TEXT NOT NULL,
                client_ip TEXT,
                user_agent TEXT,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                iface TEXT,
                src_mac TEXT,
                dst_mac TEXT,
                eth_type TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                ip_version INTEGER,
                ttl INTEGER,
                protocol TEXT,
                l7_proto TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                tcp_flags TEXT,
                seq_num INTEGER,
                ack_num INTEGER,
                window_size INTEGER,
                length INTEGER,
                domain_sni TEXT,
                info TEXT,
                payload_hex TEXT,
                payload_ascii TEXT,
                osi_json TEXT,
                container_name TEXT,
                process_name TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(protocol)")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS device_stats (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                hostname TEXT,
                container_name TEXT,
                bytes_sent INTEGER DEFAULT 0,
                bytes_recv INTEGER DEFAULT 0,
                packets_sent INTEGER DEFAULT 0,
                packets_recv INTEGER DEFAULT 0,
                protocols TEXT DEFAULT '',
                first_seen REAL,
                last_seen REAL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                severity TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                message TEXT NOT NULL,
                notified INTEGER DEFAULT 0
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        defaults = {
            "webhook_url": "",
            "telegram_bot_token": "",
            "telegram_chat_id": "",
            "signal_mode": "callmebot",
            "signal_phone": "",
            "signal_target": "",
            "signal_api_url": "",
            "hub_url": "",
            "hub_api_key": "",
            "allowlist_ips": "155.133.250.4",
            "watched_ports": "21,22,23,3389,4444,5900",
            "bandwidth_threshold_mbps": "50.0",
            "port_scan_threshold": "15",
            "enable_notifications": "true",
            "max_stored_packets": "5000",
            "retention_hours": "24",
            "flow_dedup_seconds": "5",
        }
        for k, v in defaults.items():
            cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
        cur.execute("UPDATE settings SET value = '5000' WHERE key = 'max_stored_packets' AND value = '2000'")
        cur.execute("UPDATE settings SET value = '5' WHERE key = 'flow_dedup_seconds' AND value = '30'")

        # Remove historic false-positive alerts caused by Steam (155.133.x.x) or own outbound IP
        cur.execute("DELETE FROM alerts WHERE src_ip LIKE '155.133.%' OR src_ip LIKE '162.254.%'")

        # Clean expired sessions on startup
        cur.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
        conn.commit()
        conn.close()

    try:
        os.chmod(DB_PATH, 0o600)
    except Exception:
        pass


# User & Session DB operations
def get_user_count() -> int:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM users")
    row = cur.fetchone()
    conn.close()
    return int(row["cnt"]) if row else 0


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def create_user_db(username: str, password_hash: str, salt: str) -> None:
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, salt, time.time()),
        )
        conn.commit()
        conn.close()


def update_user_password_db(username: str, password_hash: str, salt: str) -> None:
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
            (password_hash, salt, username),
        )
        conn.commit()
        conn.close()


def create_session_db(
    token_hash: str,
    username: str,
    csrf_token: str,
    client_ip: str,
    user_agent: str,
    expires_at: float,
) -> None:
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        now = time.time()
        cur.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        cur.execute(
            """
            INSERT OR REPLACE INTO sessions (
                token_hash, username, csrf_token, client_ip, user_agent, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (token_hash, username, csrf_token, client_ip, user_agent, now, expires_at),
        )
        conn.commit()
        conn.close()


def get_session_db(token_hash: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM sessions WHERE token_hash = ?", (token_hash,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_session_db(token_hash: str) -> None:
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        conn.commit()
        conn.close()


def delete_user_sessions_db(username: str) -> None:
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE username = ?", (username,))
        conn.commit()
        conn.close()


def buffer_device_traffic(
    ip: str,
    mac: str,
    container: str,
    b_sent: int,
    b_recv: int,
    p_sent: int,
    p_recv: int,
    proto: str,
    now: float,
) -> None:
    if not ip or ip.startswith("127.") or ip == "::1":
        return
    with _device_buffer_lock:
        dev = _device_buffer.get(ip)
        if not dev:
            _device_buffer[ip] = {
                "mac": mac,
                "container": container,
                "b_sent": b_sent,
                "b_recv": b_recv,
                "p_sent": p_sent,
                "p_recv": p_recv,
                "protos": {proto} if proto else set(),
                "last_seen": now,
            }
        else:
            if mac and not dev["mac"]:
                dev["mac"] = mac
            if container and not dev["container"]:
                dev["container"] = container
            dev["b_sent"] += b_sent
            dev["b_recv"] += b_recv
            dev["p_sent"] += p_sent
            dev["p_recv"] += p_recv
            if proto:
                dev["protos"].add(proto)
            dev["last_seen"] = now


def flush_device_buffer() -> None:
    global _last_device_flush
    with _device_buffer_lock:
        if not _device_buffer:
            return
        to_flush = list(_device_buffer.items())
        _device_buffer.clear()
        _last_device_flush = time.time()

    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        for ip, dev in to_flush:
            proto_str = ",".join(sorted(dev["protos"]))
            _upsert_device(
                cur,
                ip,
                dev["mac"],
                dev["container"],
                dev["b_sent"],
                dev["b_recv"],
                dev["p_sent"],
                dev["p_recv"],
                proto_str,
                dev["last_seen"],
            )
        conn.commit()
        conn.close()


def insert_packet(pkt: Dict[str, Any]) -> int:
    now = pkt.get("timestamp", time.time())
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO packets (
                timestamp, iface, src_mac, dst_mac, eth_type,
                src_ip, dst_ip, ip_version, ttl, protocol, l7_proto,
                src_port, dst_port, tcp_flags, seq_num, ack_num, window_size,
                length, domain_sni, info, payload_hex, payload_ascii, osi_json,
                container_name, process_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                pkt.get("iface", "any"),
                pkt.get("src_mac", ""),
                pkt.get("dst_mac", ""),
                pkt.get("eth_type", "IPv4"),
                pkt.get("src_ip", ""),
                pkt.get("dst_ip", ""),
                pkt.get("ip_version", 4),
                pkt.get("ttl", 64),
                pkt.get("protocol", "TCP"),
                pkt.get("l7_proto", ""),
                pkt.get("src_port", 0),
                pkt.get("dst_port", 0),
                pkt.get("tcp_flags", ""),
                pkt.get("seq_num", 0),
                pkt.get("ack_num", 0),
                pkt.get("window_size", 0),
                pkt.get("length", 0),
                pkt.get("domain_sni", ""),
                pkt.get("info", ""),
                pkt.get("payload_hex", ""),
                pkt.get("payload_ascii", ""),
                json.dumps(pkt.get("osi", {}), ensure_ascii=False),
                pkt.get("container_name", ""),
                pkt.get("process_name", ""),
            ),
        )
        pkt_id = cur.lastrowid or 0

        if pkt_id % 200 == 0:
            cur.execute("SELECT value FROM settings WHERE key = 'max_stored_packets'")
            row_max = cur.fetchone()
            max_pkts = int(row_max["value"]) if row_max and str(row_max["value"]).isdigit() else 5000
            max_pkts = max(100, min(10000, max_pkts))
            cur.execute(
                "DELETE FROM packets WHERE id <= (SELECT MAX(id) - ? FROM packets)",
                (max_pkts,),
            )

        conn.commit()
        conn.close()

    length = int(pkt.get("length", 0))
    proto = pkt.get("l7_proto") or pkt.get("protocol") or "OTHER"
    src_ip = pkt.get("src_ip", "")
    dst_ip = pkt.get("dst_ip", "")
    container = pkt.get("container_name", "")

    if src_ip:
        buffer_device_traffic(src_ip, pkt.get("src_mac", ""), container, length, 0, 1, 0, proto, now)
    if dst_ip:
        buffer_device_traffic(dst_ip, pkt.get("dst_mac", ""), container, 0, length, 0, 1, proto, now)

    if now - _last_device_flush > 5.0 or len(_device_buffer) > 40:
        flush_device_buffer()

    return pkt_id


def record_device_traffic_only(pkt: Dict[str, Any]) -> None:
    """Update device bandwidth/packet counters in memory without SQL query."""
    now = pkt.get("timestamp", time.time())
    length = int(pkt.get("length", 0))
    proto = pkt.get("l7_proto") or pkt.get("protocol") or "OTHER"
    src_ip = pkt.get("src_ip", "")
    dst_ip = pkt.get("dst_ip", "")
    container = pkt.get("container_name", "")
    if src_ip:
        buffer_device_traffic(src_ip, pkt.get("src_mac", ""), container, length, 0, 1, 0, proto, now)
    if dst_ip:
        buffer_device_traffic(dst_ip, pkt.get("dst_mac", ""), container, 0, length, 0, 1, proto, now)
    if now - _last_device_flush > 5.0 or len(_device_buffer) > 40:
        flush_device_buffer()


def _upsert_device(
    cur: sqlite3.Cursor,
    ip: str,
    mac: str,
    container: str,
    b_sent: int,
    b_recv: int,
    p_sent: int,
    p_recv: int,
    proto: str,
    now: float,
) -> None:
    cur.execute("SELECT protocols, container_name, mac FROM device_stats WHERE ip = ?", (ip,))
    row = cur.fetchone()
    if row is None:
        cur.execute(
            """
            INSERT INTO device_stats (
                ip, mac, hostname, container_name,
                bytes_sent, bytes_recv, packets_sent, packets_recv,
                protocols, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (ip, mac, "", container, b_sent, b_recv, p_sent, p_recv, proto, now, now),
        )
    else:
        existing_protos = set(filter(None, (row["protocols"] or "").split(",")))
        if proto:
            existing_protos.add(proto)
        new_protos = ",".join(sorted(existing_protos))
        new_container = container if container else (row["container_name"] or "")
        new_mac = mac if mac else (row["mac"] or "")
        cur.execute(
            """
            UPDATE device_stats
            SET mac = ?,
                container_name = ?,
                bytes_sent = bytes_sent + ?,
                bytes_recv = bytes_recv + ?,
                packets_sent = packets_sent + ?,
                packets_recv = packets_recv + ?,
                protocols = ?,
                last_seen = ?
            WHERE ip = ?
            """,
            (new_mac, new_container, b_sent, b_recv, p_sent, p_recv, new_protos, now, ip),
        )


def query_packets(
    limit: int = 50,
    offset: int = 0,
    ip: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    search: Optional[str] = None,
    container: Optional[str] = None,
) -> Dict[str, Any]:
    conn = get_conn()
    cur = conn.cursor()
    clauses = []
    params: List[Any] = []
    if ip:
        clauses.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
        params.extend([f"%{ip[:64]}%", f"%{ip[:64]}%"])
    if port:
        clauses.append("(src_port = ? OR dst_port = ?)")
        params.extend([port, port])
    if protocol:
        clauses.append("(UPPER(protocol) = UPPER(?) OR UPPER(l7_proto) = UPPER(?))")
        params.extend([protocol[:16], protocol[:16]])
    if container:
        clauses.append("container_name LIKE ?")
        params.append(f"%{container[:64]}%")
    if search:
        clauses.append("(info LIKE ? OR domain_sni LIKE ? OR payload_ascii LIKE ? OR process_name LIKE ?)")
        s_val = f"%{search[:100]}%"
        params.extend([s_val, s_val, s_val, s_val])

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    cur.execute(f"SELECT COUNT(*) AS cnt FROM packets {where_sql}", params)
    cnt_row = cur.fetchone()
    total_count = int(cnt_row["cnt"]) if cnt_row else 0

    safe_limit = min(200, max(1, limit))
    safe_offset = max(0, offset)
    sql = f"SELECT * FROM packets {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    cur.execute(sql, [*params, safe_limit, safe_offset])
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        try:
            r["osi"] = json.loads(r.get("osi_json") or "{}")
        except Exception:
            r["osi"] = {}
    conn.close()
    return {"packets": rows, "total": total_count, "limit": safe_limit, "offset": safe_offset}


def get_packet_by_id(pkt_id: int) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM packets WHERE id = ?", (pkt_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["osi"] = json.loads(d.get("osi_json") or "{}")
    except Exception:
        d["osi"] = {}
    return d


def get_device_stats(limit: int = 100, search: Optional[str] = None) -> List[Dict[str, Any]]:
    flush_device_buffer()
    conn = get_conn()
    cur = conn.cursor()
    if search:
        s_val = f"%{search[:64]}%"
        cur.execute(
            """
            SELECT *, (bytes_sent + bytes_recv) AS total_bytes
            FROM device_stats
            WHERE ip LIKE ? OR container_name LIKE ? OR protocols LIKE ?
            ORDER BY total_bytes DESC LIMIT ?
            """,
            (s_val, s_val, s_val, limit),
        )
    else:
        cur.execute(
            """
            SELECT *, (bytes_sent + bytes_recv) AS total_bytes
            FROM device_stats
            ORDER BY total_bytes DESC LIMIT ?
            """,
            (limit,),
        )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def insert_alert(
    severity: str,
    rule_name: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    message: str,
    notified: bool = False,
) -> int:
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO alerts (timestamp, severity, rule_name, src_ip, dst_ip, dst_port, message, notified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (time.time(), severity, rule_name, src_ip, dst_ip, dst_port, message, 1 if notified else 0),
        )
        aid = cur.lastrowid or 0
        if aid % 50 == 0:
            cur.execute("DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 500)")
        conn.commit()
        conn.close()
        return aid


def get_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (min(200, max(1, limit)),))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def clear_alerts_db() -> None:
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM alerts")
        conn.commit()
        conn.close()


def clear_packets_db() -> None:
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM packets")
        conn.commit()
        cur.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        conn.close()


def run_db_maintenance() -> Dict[str, Any]:
    """Prune old packets by count & age, cap device_stats, and checkpoint WAL so disk usage stays bounded."""
    flush_device_buffer()
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM settings WHERE key IN ('max_stored_packets', 'retention_hours')")
        cfg = {r["key"]: r["value"] for r in cur.fetchall()}
        max_pkts = int(cfg.get("max_stored_packets", "5000") or 5000)
        max_pkts = max(100, min(10000, max_pkts))
        ret_hours = float(cfg.get("retention_hours", "24") or 24.0)
        cutoff = time.time() - (ret_hours * 3600.0)

        cur.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff,))
        cur.execute(
            "DELETE FROM packets WHERE id NOT IN (SELECT id FROM packets ORDER BY id DESC LIMIT ?)",
            (max_pkts,),
        )
        cur.execute(
            "DELETE FROM device_stats WHERE ip NOT IN (SELECT ip FROM device_stats ORDER BY last_seen DESC LIMIT 1000)"
        )
        cur.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
        conn.commit()
        try:
            cur.execute("PRAGMA incremental_vacuum(200);")
            cur.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except Exception:
            pass
        conn.close()
    return get_storage_stats()


def get_storage_stats() -> Dict[str, Any]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS p_cnt FROM packets")
    p_cnt = int(cur.fetchone()["p_cnt"])
    cur.execute("SELECT COUNT(*) AS d_cnt FROM device_stats")
    d_cnt = int(cur.fetchone()["d_cnt"])
    cur.execute("SELECT COUNT(*) AS a_cnt FROM alerts")
    a_cnt = int(cur.fetchone()["a_cnt"])
    conn.close()

    total_bytes = 0
    for suffix in ("", "-wal", "-shm"):
        p = DB_PATH + suffix
        if os.path.exists(p):
            try:
                total_bytes += os.path.getsize(p)
            except Exception:
                pass
    return {
        "db_size_bytes": total_bytes,
        "db_size_mb": round(total_bytes / (1024 * 1024), 2),
        "packets_count": p_cnt,
        "devices_count": d_cnt,
        "alerts_count": a_cnt,
    }


def get_settings() -> Dict[str, str]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM settings")
    res = {r["key"]: r["value"] for r in cur.fetchall()}
    conn.close()
    return res


def update_settings(new_settings: Dict[str, Any]) -> Dict[str, str]:
    allowed_keys = {
        "webhook_url",
        "telegram_bot_token",
        "telegram_chat_id",
        "signal_mode",
        "signal_phone",
        "signal_target",
        "signal_api_url",
        "hub_url",
        "hub_api_key",
        "allowlist_ips",
        "watched_ports",
        "bandwidth_threshold_mbps",
        "port_scan_threshold",
        "enable_notifications",
        "max_stored_packets",
        "retention_hours",
        "flow_dedup_seconds",
    }
    with _write_lock:
        conn = get_conn()
        cur = conn.cursor()
        for k, v in new_settings.items():
            if k in allowed_keys:
                cur.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, str(v)))
        conn.commit()
        conn.close()
    return get_settings()
