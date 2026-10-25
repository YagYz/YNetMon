import struct
import time
from typing import Any, Dict, List, Optional

TCP_FLAG_GUIDE: Dict[str, Dict[str, str]] = {
    "SYN": {
        "name": "Synchronize (Senkronize Et)",
        "desc": "TCP 3'lü el sıkışmasının (3-Way Handshake) ilk adımıdır. İstemci yeni bir bağlantı başlatmak ve sıra numarasını (Sequence Number) senkronize etmek için gönderir.",
    },
    "ACK": {
        "name": "Acknowledgment (Onay)",
        "desc": "Karşı taraftan gelen verinin veya bayrağın başarıyla alındığını doğrular. 'Ack Num' alanı bir sonraki beklenen bayt sırasını gösterir.",
    },
    "PSH": {
        "name": "Push (Hemen İlet)",
        "desc": "Alıcı işletim sistemine, gelen veriyi tamponda (buffer) bekletmeden doğrudan uygulamaya (örn. web sunucusu veya tarayıcıya) aktarmasını söyler.",
    },
    "FIN": {
        "name": "Finish (Bağlantıyı Sonlandır)",
        "desc": "Göndericinin artık veri göndermeyeceğini ve TCP bağlantısını kibarca (graceful) kapatmak istediğini belirtir.",
    },
    "RST": {
        "name": "Reset (Sıfırla / Reddet)",
        "desc": "Bağlantıyı aniden keser veya kapalı bir porta gelen bağlantı isteğini (Port Closed) reddeder. Port taramalarında kapalı portlar RST+ACK döner.",
    },
    "URG": {
        "name": "Urgent (Acil Veri)",
        "desc": "Paket içindeki acil işaretçinin (Urgent Pointer) geçerli olduğunu ve öncelikli işlenmesi gerektiğini belirtir.",
    },
}

TCP_STATE_GUIDE: Dict[str, str] = {
    "LISTEN": "Sunucu bu portta gelecek yeni bağlantı (SYN) isteklerini dinliyor.",
    "SYN_SENT": "İstemci SYN paketi gönderdi ve karşıdan SYN+ACK yanıtı bekliyor (El sıkışma 1. adım).",
    "SYN_RECV": "Sunucu SYN aldı, SYN+ACK gönderdi ve son ACK onayını bekliyor (El sıkışma 2. adım).",
    "ESTABLISHED": "3'lü el sıkışma tamamlandı; iki taraf arasında aktif veri alışverişi yapılıyor.",
    "FIN_WAIT1": "Uygulama bağlantıyı kapatmak için FIN gönderdi, onay bekliyor.",
    "FIN_WAIT2": "Karşı taraf FIN'i onayladı (ACK), şimdi karşı tarafın da FIN göndermesi bekleniyor.",
    "CLOSE_WAIT": "Karşı taraf FIN gönderdi; yerel uygulamanın soketi kapatması bekleniyor.",
    "TIME_WAIT": "Bağlantı kapandı; ağda gecikmiş paketlerin karışmaması için soket kısa süre bekletiliyor.",
    "CLOSED": "Bağlantı tamamen kapalı.",
}

WELL_KNOWN_PORTS: Dict[int, Dict[str, str]] = {
    20: {"proto": "FTP-DATA", "desc": "Dosya Aktarım Protokolü (Veri Kanalı)"},
    21: {"proto": "FTP", "desc": "Dosya Aktarım Protokolü (Kontrol Kanalı - Şifresiz)"},
    22: {"proto": "SSH", "desc": "Secure Shell - Şifreli uzak sunucu yönetimi"},
    23: {"proto": "TELNET", "desc": "Şifresiz metin tabanlı uzak terminal (Güvensiz)"},
    25: {"proto": "SMTP", "desc": "E-posta gönderim protokolü"},
    53: {"proto": "DNS", "desc": "Alan Adı Sistemi - Domain isimlerini IP adresine çevirir"},
    67: {"proto": "DHCP", "desc": "Ağdaki cihazlara otomatik IP dağıtan sunucu portu"},
    68: {"proto": "DHCP", "desc": "DHCP istemci portu"},
    80: {"proto": "HTTP", "desc": "Şifresiz Web Trafiği (Plaintext HTML/JSON/API)"},
    123: {"proto": "NTP", "desc": "Ağ Zaman Protokolü - Saat senkronizasyonu"},
    443: {"proto": "TLS/HTTPS", "desc": "TLS ile şifrelenmiş güvenli web trafiği (SNI ile domain görülebilir)"},
    445: {"proto": "SMB", "desc": "Windows / Samba dosya ve yazıcı paylaşım protokolü"},
    3306: {"proto": "MySQL", "desc": "MySQL / MariaDB veritabanı bağlantısı"},
    3389: {"proto": "RDP", "desc": "Windows Uzak Masaüstü Protokolü"},
    5432: {"proto": "PostgreSQL", "desc": "PostgreSQL veritabanı bağlantısı"},
    6379: {"proto": "Redis", "desc": "Redis bellek içi veri yapısı sunucusu"},
    8080: {"proto": "HTTP-ALT", "desc": "Alternatif HTTP / Web uygulama ve proxy portu"},
    8443: {"proto": "HTTPS-ALT", "desc": "Alternatif HTTPS portu"},
    8765: {"proto": "YNetMon", "desc": "YNetMon Web Arayüzü ve WebSocket akışı"},
}


def format_hex_ascii(raw_bytes: bytes, max_len: int = 512) -> tuple[str, str]:
    clipped = raw_bytes[:max_len]
    hex_lines = []
    ascii_chars = []
    for offset in range(0, len(clipped), 16):
        chunk = clipped[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        hex_lines.append(f"{offset:04x}  {hex_part:<47}  |{ascii_part}|")
        ascii_chars.append(ascii_part)
    return "\n".join(hex_lines), "".join(ascii_chars)


def extract_tls_sni(payload: bytes) -> str:
    """Extract Server Name Indication (SNI) from TLS ClientHello payload if present."""
    try:
        if len(payload) < 43:
            return ""
        # Content Type 22 = Handshake, Version 0x0301..0x0303, Handshake Type 1 = ClientHello
        if payload[0] != 0x16 or payload[5] != 0x01:
            return ""
        pos = 43
        if pos >= len(payload):
            return ""
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return ""
        cipher_suites_len = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2 + cipher_suites_len
        if pos + 1 > len(payload):
            return ""
        comp_methods_len = payload[pos]
        pos += 1 + comp_methods_len
        if pos + 2 > len(payload):
            return ""
        extensions_len = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2
        end_ext = min(len(payload), pos + extensions_len)
        while pos + 4 <= end_ext:
            ext_type, ext_len = struct.unpack("!HH", payload[pos : pos + 4])
            pos += 4
            if ext_type == 0x0000 and pos + 5 <= end_ext:  # server_name extension
                name_Type = payload[pos + 2]
                name_len = struct.unpack("!H", payload[pos + 3 : pos + 5])[0]
                if name_Type == 0 and pos + 5 + name_len <= end_ext:
                    return payload[pos + 5 : pos + 5 + name_len].decode("utf-8", errors="ignore")
            pos += ext_len
    except Exception:
        pass
    return ""


def extract_http_info(payload: bytes) -> tuple[str, str]:
    """Return (domain_host, request_or_response_line) if HTTP payload."""
    try:
        text = payload[:512].decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        if not lines:
            return "", ""
        first = lines[0].strip()
        methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/1.")
        if not any(first.startswith(m) for m in methods):
            return "", ""
        host = ""
        for line in lines[1:12]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return host, first[:100]
    except Exception:
        return "", ""


_IFACE_STATS_CACHE: Dict[str, Any] = {}
_IFACE_STATS_CACHE_TIME: float = 0.0


def get_cached_iface_stats() -> Dict[str, Any]:
    global _IFACE_STATS_CACHE, _IFACE_STATS_CACHE_TIME
    now = time.time()
    if not _IFACE_STATS_CACHE or (now - _IFACE_STATS_CACHE_TIME > 10.0):
        try:
            import psutil  # type: ignore

            _IFACE_STATS_CACHE = psutil.net_if_stats()
            _IFACE_STATS_CACHE_TIME = now
        except Exception:
            pass
    return _IFACE_STATS_CACHE


def build_osi_explanation(pkt: Dict[str, Any]) -> Dict[str, Any]:
    """Generate educational 7-layer OSI breakdown for a packet dictionary."""
    src_port = pkt.get("src_port", 0)
    dst_port = pkt.get("dst_port", 0)
    proto = pkt.get("protocol", "TCP")
    l7 = pkt.get("l7_proto") or proto
    flags_str = pkt.get("tcp_flags", "")
    flags_list = [f for f in flags_str.split(",") if f]

    flag_explanations = [
        {"flag": f, **TCP_FLAG_GUIDE.get(f, {"name": f, "desc": "TCP kontrol bayrağı"})}
        for f in flags_list
    ]

    port_info = WELL_KNOWN_PORTS.get(dst_port) or WELL_KNOWN_PORTS.get(src_port) or {
        "proto": l7,
        "desc": "Dinamik / Ephemeral veya özel uygulama portu",
    }

    ttl = pkt.get("ttl", 64)
    os_guess = (
        "Linux / Android / Container (~64)"
        if ttl <= 64
        else ("Windows (~128)" if ttl <= 128 else "Network Router / Solaris (~255)")
    )

    # 1. Katman 1 - Fiziksel (Physical)
    iface_name = pkt.get("iface") or "eth0"
    stats_dict = get_cached_iface_stats()
    st = stats_dict.get(iface_name) or stats_dict.get(iface_name.split(":")[0])
    mtu = getattr(st, "mtu", 1500) if st else (65536 if iface_name == "lo" else 1500)
    speed = getattr(st, "speed", 0) if st else 0
    speed_str = (
        f"{speed} Mbps"
        if speed > 0
        else (
            "Sanal / Köprü Arabirimi"
            if ("docker" in iface_name or "br-" in iface_name or "veth" in iface_name or iface_name == "lo")
            else "1000 Mbps (Otomatik)"
        )
    )
    medium_type = (
        "Loopback (Yerel Bellek İçi Soket İletişimi)"
        if iface_name == "lo"
        else (
            "Sanal Köprü (Docker Bridge / veth pair)"
            if ("docker" in iface_name or "br-" in iface_name or "veth" in iface_name)
            else (
                "VPN Tüneli (WireGuard / Tailscale TUN)"
                if ("tailscale" in iface_name or "wg" in iface_name or "tun" in iface_name)
                else (
                    "Kablosuz Ağ (Wi-Fi 802.11)"
                    if ("wl" in iface_name)
                    else "Bakır / Fiber Ethernet (IEEE 802.3 RJ45 / SFP+)"
                )
            )
        )
    )

    # 5. Katman 5 - Oturum (Session)
    session_tuple = f"{pkt.get('src_ip', '')}:{src_port} ↔ {pkt.get('dst_ip', '')}:{dst_port}"
    if proto == "TCP":
        if "SYN" in flags_list and "ACK" not in flags_list:
            session_phase = "SYN_SENT (Oturum Başlatma Talebi)"
        elif "SYN" in flags_list and "ACK" in flags_list:
            session_phase = "SYN_RCVD (Oturum Onayı - 2. Adım)"
        elif "FIN" in flags_list or "RST" in flags_list:
            session_phase = "TERMINATING (Oturum Kapatılıyor)"
        elif "PSH" in flags_list:
            session_phase = "DATA_TRANSFER (Aktif Veri İletimi)"
        else:
            session_phase = "ESTABLISHED (Aktif Çift Yönlü Oturum)"
        dialogue = "Full-Duplex (Eşzamanlı Çift Yönlü Oturum)"
    elif proto == "UDP":
        session_phase = "STATELESS_DATAGRAM (Bağlantısız İstek-Yanıt)"
        dialogue = "Simplex / Datagram (Bağlantısız İletim)"
    else:
        session_phase = "CONTROL_MESSAGE (Ağ Denetim İletisi)"
        dialogue = "Unidirectional (Tek Yönlü Bildirim)"

    # 6. Katman 6 - Sunum (Presentation)
    payload_hex = pkt.get("payload_hex", "")
    is_tls = (
        l7 in ("TLS", "HTTPS")
        or dst_port == 443
        or src_port == 443
        or (payload_hex and payload_hex.startswith("0000  16 03"))
    )
    is_http = l7 == "HTTP" or dst_port == 80 or src_port == 80
    is_dns = l7 == "DNS" or dst_port == 53 or src_port == 53
    is_ssh = l7 == "SSH" or dst_port == 22 or src_port == 22

    if is_tls:
        encoding_str = "Kriptolu İkili Veri (TLS Record / Ciphertext)"
        enc_str = "TLS 1.2 / TLS 1.3 (AES-GCM / ChaCha20 - Uçtan Uca Şifreli)"
        mime_str = "application/tls-record (Kriptolu Uygulama Yükü)"
        comp_str = "TLS Compression Devre Dışı (CRIME/BREACH Güvenlik Koruması)"
        l6_learn = (
            "Katman 6 verinin gizliliğini TLS şifrelemesiyle sağlar. Ağdaki üçüncü şahıslar verinin içeriğini "
            "(HTTP başlıkları, JSON, parolalar) göremez, yalnızca şifreli baytları izler."
        )
    elif is_http:
        encoding_str = "UTF-8 / ASCII Metin (Plaintext HTTP Frame)"
        enc_str = "Şifresiz (Plaintext - Ağ Dinlemeye ve MitM Saldırılarına Açık)"
        mime_str = "application/json / text/html (REST / Web API)"
        comp_str = "Gzip / Brotli / Deflate HTTP Aktarımı Desteklenir"
        l6_learn = (
            "Şifrelenmemiş metin protokolü; tüm istek ve yanıt gövdeleri Katman 6'da açık metin (plaintext) "
            "olarak iletilir. Güvenlik için HTTPS zorunlu kılınmalıdır."
        )
    elif is_dns:
        encoding_str = "RFC 1035 İkili DNS Wire Formatı"
        enc_str = "Şifresiz UDP/53 (DoH/DoT Değil)"
        mime_str = "application/dns-message"
        comp_str = "DNS İsim Sıkıştırması (Pointer Offset 0xc0)"
        l6_learn = "DNS sorgu ve yanıtları RFC 1035 standartlarına göre ikili (binary) formatta paketlenir. Alan adları etiket uzunluklarıyla dizilir."
    elif is_ssh:
        encoding_str = "SSH-2.0 Binary Packet Protocol (RFC 4253)"
        enc_str = "Kriptolu (ChaCha20-Poly1305 / AES-256-CTR)"
        mime_str = "application/x-ssh-payload"
        comp_str = "none veya zlib@openssh.com"
        l6_learn = "SSH protokolü ilk sürüm dizisinden sonra tüm komut ve terminal oturum yükünü güçlü simetrik şifrelemeyle Katman 6'da gizler."
    else:
        encoding_str = "ASCII / Binary Veri" if payload_hex else "Yüksüz Kontrol Paketi (Sadece Başlıklar)"
        enc_str = "Ham Veri (Şifresiz)"
        mime_str = "application/octet-stream"
        comp_str = "Uygulanmamış (Ham Baytlar)"
        l6_learn = "Katman 6 verinin formatlanması, karakter seti kodlaması (Encoding) ve serileştirilmesinden sorumludur."

    return {
        "layer1": {
            "title": "Katman 1 - Fiziksel (Physical / Bit & Sinyal)",
            "iface": iface_name,
            "mtu": mtu,
            "speed": speed_str,
            "medium": medium_type,
            "status": "Aktif (Link UP)" if getattr(st, "isup", True) else "Bağlantı Yok (DOWN)",
            "learn": (
                f"Fiziksel katman veriyi kablo veya radyo dalgaları üzerinden bit (0 ve 1) dizisi olarak iletir. "
                f"Ağ arabirimi ({iface_name}), MTU ({mtu} bayt) boyutuyla tek seferde fiziksel hatta basılabilecek azami çerçeve boyutunu belirler."
            ),
        },
        "layer2": {
            "title": "Katman 2 - Veri Bağı (Data Link / Ethernet Frame)",
            "src_mac": pkt.get("src_mac") or "00:00:00:00:00:00",
            "dst_mac": pkt.get("dst_mac") or "00:00:00:00:00:00",
            "eth_type": pkt.get("eth_type", "IPv4 (0x0800)"),
            "frame_size": f"{pkt.get('length', 64) + 14} Bayt (Ethernet Başlığı Dahil)",
            "learn": "Yerel ağda (LAN / VLAN / Docker Bridge) paketlerin hangi fiziksel/sanal ağ kartından hangisine gideceğini MAC adresleriyle belirler.",
        },
        "layer3": {
            "title": "Katman 3 - Ağ (Network / IP & Yönlendirme)",
            "src_ip": pkt.get("src_ip", ""),
            "dst_ip": pkt.get("dst_ip", ""),
            "ip_version": f"IPv{pkt.get('ip_version', 4)}",
            "ttl": ttl,
            "os_hint": os_guess,
            "learn": f"TTL (Time-To-Live: {ttl}) paketin sonsuz döngüye girmemesi için geçtiği her router'da 1 azalır. Başlangıç TTL değerinden gönderici işletim sistemi tahmin edilebilir ({os_guess}).",
        },
        "layer4": {
            "title": f"Katman 4 - Taşıma (Transport / {proto})",
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": flags_list,
            "flag_details": flag_explanations,
            "seq_num": pkt.get("seq_num", 0),
            "ack_num": pkt.get("ack_num", 0),
            "window_size": pkt.get("window_size", 0),
            "learn": (
                "TCP bağlantılı ve güvenilirdir (sıra numarası, ACK onayı ve pencere akış kontrolü kullanır)."
                if proto == "TCP"
                else (
                    "UDP bağlantısızdır; el sıkışma yapmaz, düşük gecikme isteyen DNS, oyun ve ses/video akışlarında tercih edilir."
                    if proto == "UDP"
                    else "ICMP ağ teşhis ve kontrol mesajları (Ping Echo Request/Reply, Destination Unreachable) taşır."
                )
            ),
        },
        "layer5": {
            "title": "Katman 5 - Oturum (Session / Bağlantı & Durum)",
            "session_id": session_tuple,
            "session_phase": session_phase,
            "dialogue_mode": dialogue,
            "process": pkt.get("process_name") or pkt.get("container_name") or "İşletim Sistemi Çekirdeği",
            "learn": (
                "Katman 5, iki uç nokta arasındaki iletişim oturumunun kurulmasını, senkronize edilmesini ve "
                "düzgün sonlandırılmasını (Graceful Close) yönetir. Soketlerin açık kalması (Keep-Alive) ve el sıkışma oturum durumu burada koordine edilir."
            ),
        },
        "layer6": {
            "title": "Katman 6 - Sunum (Presentation / Şifreleme & Kodlama)",
            "encoding": encoding_str,
            "encryption": enc_str,
            "mime_type": mime_str,
            "compression": comp_str,
            "learn": l6_learn,
        },
        "layer7": {
            "title": f"Katman 7 - Uygulama (Application / {l7})",
            "l7_proto": l7,
            "service_desc": port_info["desc"],
            "domain_sni": pkt.get("domain_sni", ""),
            "info": pkt.get("info", ""),
            "learn": (
                f"HTTPS/TLS trafiğinde içerik şifrelidir ancak el sıkışma (ClientHello) sırasındaki SNI alanından '{pkt.get('domain_sni')}' domainine gidildiği görülebilir."
                if pkt.get("domain_sni") and l7 in ("TLS", "HTTPS")
                else f"{port_info['desc']}"
            ),
        },
    }


def generate_educational_packets(local_ip: str = "192.168.1.100") -> List[Dict[str, Any]]:
    """Generate realistic multi-layer networking packets (TCP Handshake, DNS, TLS SNI, HTTP, ICMP) for interactive learning."""
    now = time.time()
    samples: List[Dict[str, Any]] = []

    # 1. DNS Query
    dns_payload = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06github\x03com\x00\x00\x01\x00\x01"
    p_hex, p_asc = format_hex_ascii(dns_payload)
    pkt1 = {
        "timestamp": now - 0.4,
        "iface": "eth0",
        "src_mac": "02:42:ac:11:00:02",
        "dst_mac": "bc:24:11:a0:00:01",
        "eth_type": "IPv4 (0x0800)",
        "src_ip": local_ip,
        "dst_ip": "1.1.1.1",
        "ip_version": 4,
        "ttl": 64,
        "protocol": "UDP",
        "l7_proto": "DNS",
        "src_port": 54321,
        "dst_port": 53,
        "tcp_flags": "",
        "seq_num": 0,
        "ack_num": 0,
        "window_size": 0,
        "length": 60,
        "domain_sni": "github.com",
        "info": "DNS Standard Query A github.com -> Cloudflare (1.1.1.1)",
        "payload_hex": p_hex,
        "payload_ascii": p_asc,
        "container_name": "host-system",
        "process_name": "systemd-resolved",
    }
    pkt1["osi"] = build_osi_explanation(pkt1)
    samples.append(pkt1)

    # 2. TCP 3-Way Handshake Step 1: SYN
    pkt2 = {
        "timestamp": now - 0.3,
        "iface": "eth0",
        "src_mac": "02:42:ac:11:00:02",
        "dst_mac": "bc:24:11:a0:00:01",
        "eth_type": "IPv4 (0x0800)",
        "src_ip": local_ip,
        "dst_ip": "140.82.121.4",
        "ip_version": 4,
        "ttl": 64,
        "protocol": "TCP",
        "l7_proto": "HTTPS",
        "src_port": 49152,
        "dst_port": 443,
        "tcp_flags": "SYN",
        "seq_num": 1000,
        "ack_num": 0,
        "window_size": 64240,
        "length": 74,
        "domain_sni": "github.com",
        "info": "[TCP Handshake 1/3] 49152 -> 443 [SYN] Seq=1000 Win=64240",
        "payload_hex": "0000  c0 00 01 bb 00 00 03 e8 00 00 00 00 a0 02 fa f0  |................|",
        "payload_ascii": "................",
        "container_name": "host-system",
        "process_name": "curl",
    }
    pkt2["osi"] = build_osi_explanation(pkt2)
    samples.append(pkt2)

    # 3. TCP 3-Way Handshake Step 2: SYN,ACK
    pkt3 = {
        "timestamp": now - 0.2,
        "iface": "eth0",
        "src_mac": "bc:24:11:a0:00:01",
        "dst_mac": "02:42:ac:11:00:02",
        "eth_type": "IPv4 (0x0800)",
        "src_ip": "140.82.121.4",
        "dst_ip": local_ip,
        "ip_version": 4,
        "ttl": 56,
        "protocol": "TCP",
        "l7_proto": "HTTPS",
        "src_port": 443,
        "dst_port": 49152,
        "tcp_flags": "SYN,ACK",
        "seq_num": 5000,
        "ack_num": 1001,
        "window_size": 65535,
        "length": 74,
        "domain_sni": "github.com",
        "info": "[TCP Handshake 2/3] 443 -> 49152 [SYN, ACK] Seq=5000 Ack=1001",
        "payload_hex": "0000  01 bb c0 00 00 00 13 88 00 00 03 e9 a0 12 ff ff  |................|",
        "payload_ascii": "................",
        "container_name": "host-system",
        "process_name": "curl",
    }
    pkt3["osi"] = build_osi_explanation(pkt3)
    samples.append(pkt3)

    # 4. TLS ClientHello with SNI
    tls_mock = b"\x16\x03\x01\x00\xc8\x01\x00\x00\xc4\x03\x03TLS_CLIENT_HELLO_SNI:github.com"
    t_hex, t_asc = format_hex_ascii(tls_mock)
    pkt4 = {
        "timestamp": now - 0.1,
        "iface": "eth0",
        "src_mac": "02:42:ac:11:00:02",
        "dst_mac": "bc:24:11:a0:00:01",
        "eth_type": "IPv4 (0x0800)",
        "src_ip": local_ip,
        "dst_ip": "140.82.121.4",
        "ip_version": 4,
        "ttl": 64,
        "protocol": "TCP",
        "l7_proto": "TLS",
        "src_port": 49152,
        "dst_port": 443,
        "tcp_flags": "PSH,ACK",
        "seq_num": 1001,
        "ack_num": 5001,
        "window_size": 64240,
        "length": 266,
        "domain_sni": "github.com",
        "info": "TLSv1.3 Client Hello (SNI=github.com)",
        "payload_hex": t_hex,
        "payload_ascii": t_asc,
        "container_name": "host-system",
        "process_name": "curl",
    }
    pkt4["osi"] = build_osi_explanation(pkt4)
    samples.append(pkt4)

    # 5. Plaintext HTTP GET Request
    http_bytes = (
        b"GET /api/v1/health HTTP/1.1\r\n"
        b"Host: homelab.local:8080\r\n"
        b"User-Agent: YNetMon-Lab/1.0\r\n"
        b"Accept: application/json\r\n\r\n"
    )
    h_hex, h_asc = format_hex_ascii(http_bytes)
    pkt5 = {
        "timestamp": now,
        "iface": "docker0",
        "src_mac": "02:42:ac:11:00:01",
        "dst_mac": "02:42:ac:11:00:05",
        "eth_type": "IPv4 (0x0800)",
        "src_ip": "172.17.0.1",
        "dst_ip": "172.17.0.5",
        "ip_version": 4,
        "ttl": 64,
        "protocol": "TCP",
        "l7_proto": "HTTP",
        "src_port": 38910,
        "dst_port": 80,
        "tcp_flags": "PSH,ACK",
        "seq_num": 2048,
        "ack_num": 4096,
        "window_size": 502,
        "length": len(http_bytes) + 54,
        "domain_sni": "homelab.local:8080",
        "info": "HTTP GET /api/v1/health (Host: homelab.local:8080)",
        "payload_hex": h_hex,
        "payload_ascii": h_asc,
        "container_name": "homelab-nginx",
        "process_name": "nginx",
    }
    pkt5["osi"] = build_osi_explanation(pkt5)
    samples.append(pkt5)

    return samples
