import ipaddress
import socket
import threading
import time
from typing import Any, Dict, Optional, Set, Tuple

# Known benign Cloud, CDN, Gaming (Steam/Valve), DNS, and VPN CIDR blocks
KNOWN_PROVIDER_CIDRS = [
    ("155.133.240.0/20", "Valve / Steam Gaming Network", "gaming"),
    ("162.254.192.0/21", "Valve / Steam SDR Network", "gaming"),
    ("208.64.200.0/22", "Valve / Steam Network", "gaming"),
    ("185.25.180.0/23", "Valve / Steam Europe", "gaming"),
    ("1.1.1.0/24", "Cloudflare DNS", "cdn_dns"),
    ("1.0.0.0/24", "Cloudflare DNS", "cdn_dns"),
    ("104.16.0.0/12", "Cloudflare CDN", "cdn_dns"),
    ("172.64.0.0/13", "Cloudflare CDN", "cdn_dns"),
    ("8.8.8.0/24", "Google Public DNS", "cdn_dns"),
    ("8.8.4.0/24", "Google Public DNS", "cdn_dns"),
    ("142.250.0.0/15", "Google Cloud / Services", "cdn_dns"),
    ("172.217.0.0/16", "Google Services", "cdn_dns"),
    ("140.82.112.0/20", "GitHub / Microsoft", "cloud"),
    ("185.199.108.0/22", "GitHub Pages / Fastly", "cloud"),
    ("100.64.0.0/10", "Tailscale / CGNAT Mesh VPN", "vpn"),
]

_COMPILED_CIDRS = [
    (ipaddress.ip_network(cidr), name, category)
    for cidr, name, category in KNOWN_PROVIDER_CIDRS
]

# Known local client applications whose outbound connections and return packets are normal user activity
TRUSTED_LOCAL_CLIENT_PROCESSES = {
    "steam",
    "steamwebhelper",
    "gamescope",
    "brave",
    "firefox",
    "chrome",
    "chromium",
    "vivaldi",
    "opera",
    "discord",
    "vesktop",
    "telegram-desktop",
    "signal-desktop",
    "spotify",
    "code",
    "codium",
    "cursor",
    "git",
    "curl",
    "wget",
    "apt",
    "pacman",
    "flatpak",
    "systemd-resolved",
    "avahi-daemon",
    "tailscaled",
    "NetworkManager",
    "wpa_supplicant",
}

_ptr_cache: Dict[str, Tuple[str, float]] = {}
_ptr_lock = threading.Lock()


def identify_ip_provider(ip_str: str) -> Dict[str, str]:
    """Identify if an IP belongs to a known gaming/CDN/DNS/VPN provider or private range."""
    if not ip_str:
        return {"provider": "Bilinmiyor", "category": "unknown", "ptr": ""}
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback:
            return {"provider": "Localhost (Loopback)", "category": "local", "ptr": "localhost"}
        if ip_obj.is_multicast or str(ip_obj) == "255.255.255.255":
            return {"provider": "Broadcast / Multicast (Yerel Ağ Keşfi)", "category": "local", "ptr": ""}
        for net, name, cat in _COMPILED_CIDRS:
            if ip_obj in net:
                return {"provider": name, "category": cat, "ptr": get_cached_ptr(ip_str)}
        if ip_obj.is_private:
            return {"provider": "Yerel Ağ Cihazı (LAN / Docker)", "category": "lan", "ptr": ""}
    except Exception:
        pass
    ptr = get_cached_ptr(ip_str)
    return {"provider": ptr or "Harici İnternet IP", "category": "external", "ptr": ptr}


def get_cached_ptr(ip_str: str) -> str:
    now = time.time()
    with _ptr_lock:
        cached = _ptr_cache.get(ip_str)
        if cached and now - cached[1] < 3600:
            return cached[0]
    return ""


def resolve_ptr_background(ip_str: str) -> None:
    """Non-blocking background reverse DNS lookup cached for 1 hour."""
    if not ip_str or ip_str.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.")):
        return
    with _ptr_lock:
        if ip_str in _ptr_cache:
            return
        if len(_ptr_cache) > 1000:
            _ptr_cache.clear()
        _ptr_cache[ip_str] = ("", time.time())

    def _worker() -> None:
        try:
            host, _, _ = socket.gethostbyaddr(ip_str)
            with _ptr_lock:
                _ptr_cache[ip_str] = (host, time.time())
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()


def is_steam_or_gaming_port(port: int) -> bool:
    return 27000 <= port <= 27200 or port in (3478, 4379, 4380)


def evaluate_traffic_decision(
    pkt: Dict[str, Any],
    local_ips: Set[str],
    listening_ports: Set[int],
    outbound_remote_ips: Set[str],
    watched_ports: Set[int],
    custom_allowlist: Set[str],
) -> Dict[str, Any]:
    """
    Multi-stage decision engine that determines:
    - direction: OUTBOUND, INBOUND_RETURN, INBOUND_SERVICE, LAN_INTERNAL
    - is_benign: True if normal user/client/gaming/CDN traffic
    - risk_score: 0..100
    - should_track_scan: True ONLY for genuine unsolicited inbound probes
    - should_alert_port: True ONLY for genuine external access to local watched ports
    - reason: Human-readable explanation of the decision
    """
    src_ip = pkt.get("src_ip", "")
    dst_ip = pkt.get("dst_ip", "")
    src_port = int(pkt.get("src_port") or 0)
    dst_port = int(pkt.get("dst_port") or 0)
    proto = pkt.get("protocol", "TCP")
    flags = pkt.get("tcp_flags", "")
    proc = (pkt.get("process_name") or "").lower()

    resolve_ptr_background(src_ip)
    resolve_ptr_background(dst_ip)

    # 1. Check explicit user allowlist
    if src_ip in custom_allowlist or dst_ip in custom_allowlist:
        return {
            "direction": "ALLOWLIST",
            "is_benign": True,
            "risk_score": 0,
            "should_track_scan": False,
            "should_alert_port": False,
            "provider": "Kullanıcı Beyaz Listesi",
            "reason": "IP adresi güvenilir listesinde (Allowlist).",
        }

    # 2. Outbound traffic initiated by our own machine
    if src_ip in local_ips or src_ip in ("127.0.0.1", "::1", "0.0.0.0"):
        dst_info = identify_ip_provider(dst_ip)
        return {
            "direction": "OUTBOUND",
            "is_benign": True,
            "risk_score": 0,
            "should_track_scan": False,
            "should_alert_port": False,
            "provider": dst_info["provider"],
            "reason": f"Giden trafik (Senin cihazından -> {dst_ip}:{dst_port} [{dst_info['provider']}]).",
        }

    src_info = identify_ip_provider(src_ip)
    provider_name = src_info["provider"]
    category = src_info["category"]

    # 3. Return traffic from known gaming/CDN/cloud providers or active outbound sessions
    if (
        category in ("gaming", "cdn_dns", "cloud", "vpn")
        or is_steam_or_gaming_port(src_port)
        or is_steam_or_gaming_port(dst_port)
        or proc in TRUSTED_LOCAL_CLIENT_PROCESSES
        or src_ip in outbound_remote_ips
    ):
        return {
            "direction": "INBOUND_RETURN",
            "is_benign": True,
            "risk_score": 5,
            "should_track_scan": False,
            "should_alert_port": False,
            "provider": provider_name,
            "reason": f"Güvenli İstemci/Oyun/CDN yanıt trafiği ({provider_name}, Süreç: {proc or 'sistem'}).",
        }

    # 4. Ephemeral destination port check:
    # If dst_port >= 32768 and NOT in our local listening_ports, and TCP flags contain ACK (e.g. SYN,ACK or PSH,ACK),
    # it is a response packet to an ephemeral client port, NOT an inbound service attack!
    if dst_port >= 32768 and dst_port not in listening_ports and ("ACK" in flags or proto == "UDP"):
        return {
            "direction": "INBOUND_RETURN",
            "is_benign": True,
            "risk_score": 10,
            "should_track_scan": False,
            "should_alert_port": False,
            "provider": provider_name,
            "reason": f"Yerel istemci portuna ({dst_port}) dönen yanıt paketi ({provider_name}).",
        }

    # 5. Unsolicited Inbound Traffic Analysis
    is_syn_only = proto == "TCP" and ("SYN" in flags and "ACK" not in flags)
    is_rst_or_fin_probe = proto == "TCP" and any(f in flags for f in ("FIN", "RST", "URG")) and "ACK" not in flags
    is_watched_target = dst_port in watched_ports and (dst_port in listening_ports or is_syn_only or not flags)

    risk_score = 40
    reasons = [f"Dış kaynak ({src_ip} - {provider_name}) -> Yerel Port {dst_port}"]

    if is_watched_target:
        risk_score += 35
        reasons.append(f"Kritik izlenen port ({dst_port}) hedeflendi")
    if is_syn_only:
        risk_score += 20
        reasons.append("Yeni bağlantı başlatma isteği (TCP SYN)")
    elif is_rst_or_fin_probe:
        risk_score += 25
        reasons.append(f"Anormal TCP bayrak taraması ({flags})")

    return {
        "direction": "INBOUND_EXTERNAL",
        "is_benign": False,
        "risk_score": min(100, risk_score),
        "should_track_scan": bool(is_syn_only or is_rst_or_fin_probe or dst_port < 10000),
        "should_alert_port": bool(is_watched_target),
        "provider": provider_name,
        "reason": " | ".join(reasons),
    }
