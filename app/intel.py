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


COMMON_MAC_VENDORS: Dict[str, str] = {
    # Network Equipment & Routers
    "e0:9d:1e": "Keenetic Limited (Modem/Router)",
    "00:1d:aa": "Keenetic / ZyXEL",
    "00:31:92": "Keenetic",
    "f0:79:59": "TP-Link Technologies",
    "50:c7:bf": "TP-Link",
    "c0:06:c3": "TP-Link",
    "98:48:27": "TP-Link",
    "50:eb:f6": "ASUSTek Computer",
    "04:d9:f5": "ASUSTek Computer",
    "00:11:32": "Synology Inc.",
    "bc:24:11": "Synology Inc.",
    "24:5a:4c": "Ubiquiti Networks",
    "dc:9f:db": "Ubiquiti Networks",
    "b4:fb:e4": "Ubiquiti Networks",
    "78:8a:20": "Ubiquiti Networks",
    "e4:38:83": "MikroTik",
    "cc:2d:e0": "MikroTik",
    "48:8f:5a": "MikroTik",

    # Apple Devices
    "b0:25:aa": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.",
    "a4:83:e7": "Apple, Inc.",
    "3c:22:fb": "Apple, Inc.",
    "a8:66:7f": "Apple, Inc.",
    "dc:a9:04": "Apple, Inc.",
    "38:f9:d3": "Apple, Inc.",
    "60:f4:45": "Apple, Inc.",
    "ac:bc:32": "Apple, Inc.",
    "f8:ff:c2": "Apple, Inc.",
    "7c:04:d0": "Apple, Inc.",

    # Intel & PC Motherboards
    "88:e9:fe": "Intel Corporate",
    "00:1b:21": "Intel Corporate",
    "34:17:eb": "Intel Corporate",
    "d8:50:e6": "Micro-Star / ECS (Homelab)",
    "00:e0:4c": "Realtek Semiconductor",
    "b8:85:84": "Realtek Semiconductor",
    "74:da:88": "Realtek Semiconductor",
    "70:85:c2": "ASRock Incorporation",
    "04:42:1a": "Gigabyte Technology",

    # Mobile, IoT & SBC
    "c4:07:2f": "Xiaomi Communications",
    "64:a2:00": "Xiaomi",
    "28:6c:07": "Xiaomi",
    "dc:a6:32": "Raspberry Pi Foundation",
    "b8:27:eb": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "28:cd:c1": "Raspberry Pi",
    "ec:fa:bc": "Espressif Inc (ESP32/ESP8266 IoT)",
    "84:f3:eb": "Espressif Inc (IoT)",
    "24:6f:28": "Espressif Inc (IoT)",
    "5c:cf:7f": "Espressif Inc (IoT)",
    "40:22:d8": "Espressif Inc (IoT)",
    "30:ae:a4": "Espressif Inc (IoT)",
    "24:0a:c4": "Espressif Inc (IoT)",
    "68:b6:b3": "Espressif Inc (IoT)",
    "08:3a:88": "Espressif Inc (IoT)",

    # Virtualization
    "00:50:56": "VMware Virtual NIC",
    "00:0c:29": "VMware Virtual NIC",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "00:15:5d": "Microsoft Hyper-V Virtual NIC",
}


def identify_mac_vendor(mac: str) -> str:
    """Identify device manufacturer or hardware type from MAC address."""
    if not mac or not isinstance(mac, str):
        return "-"
    mac_clean = mac.strip().lower()
    if mac_clean == "l3/tunnel":
        return "Tailscale / VPN Tüneli"
    if mac_clean.startswith("02:42:"):
        return "Docker Sanal Ağ Arayüzü"
    if mac_clean in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return "Yayın (Broadcast) / Tanımsız"

    # Match exact 3-byte OUI prefix
    if len(mac_clean) >= 8:
        prefix = mac_clean[:8]
        if prefix in COMMON_MAC_VENDORS:
            return COMMON_MAC_VENDORS[prefix]

    # Check IEEE 802 locally administered / randomized bit (used by mobile privacy MACs)
    try:
        first_byte = int(mac_clean[:2], 16)
        if first_byte & 0x02 != 0:
            return "Özel / Rastgele MAC (Mobil Cihaz)"
    except Exception:
        pass

    return "Ağ Arayüzü"

