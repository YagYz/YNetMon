import asyncio
import json
import os
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import psutil

from .database import get_settings, insert_packet, record_device_traffic_only
from .inspector import (
    TCP_STATE_GUIDE,
    WELL_KNOWN_PORTS,
    build_osi_explanation,
    extract_http_info,
    extract_tls_sni,
    format_hex_ascii,
)
from .intel import evaluate_traffic_decision, identify_ip_provider
from .notifier import trigger_alert


class NetworkMonitor:
    def __init__(self) -> None:
        self.raw_capture_active: bool = False
        self.raw_capture_error: str = ""
        self.selected_iface: str = "all"
        self.sniffer: Any = None

        self.prev_io: Dict[str, Any] = {}
        self.prev_io_time: float = time.time()
        self.bandwidth_history: Deque[Dict[str, Any]] = deque(maxlen=60)
        self.recent_packets: Deque[Dict[str, Any]] = deque(maxlen=100)
        self.active_connections: List[Dict[str, Any]] = []
        self.docker_containers: List[Dict[str, Any]] = []
        self.ip_to_container: Dict[str, str] = {}
        self.port_to_container: Dict[int, str] = {}

        self.local_ips: Set[str] = {"127.0.0.1", "::1"}
        self.listening_ports: Set[int] = set()
        self.outbound_remote_ips: Set[str] = set()

        self._seen_flows: Dict[Tuple[str, int, str, int, str], float] = {}
        self._port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
        self._port_scan_reset: float = time.time()
        self._alert_cooldown: Dict[str, float] = {}
        self._last_docker_refresh: float = 0.0
        self._last_local_ips_time: float = 0.0
        self._pid_cache: Dict[int, Tuple[float, str]] = {}
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def get_local_ip(self) -> str:
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                if iface == "lo":
                    continue
                for a in addrs:
                    if a.family == socket.AF_INET and not a.address.startswith("127."):
                        return a.address
        except Exception:
            pass
        return "127.0.0.1"

    def get_interfaces(self) -> List[Dict[str, Any]]:
        res = []
        addrs_map = psutil.net_if_addrs()
        stats_map = psutil.net_if_stats()
        for iface, addrs in addrs_map.items():
            ipv4 = next((a.address for a in addrs if a.family == socket.AF_INET), "")
            mac = next((a.address for a in addrs if getattr(socket, "AF_PACKET", 17) == a.family), "")
            st = stats_map.get(iface)
            res.append(
                {
                    "name": iface,
                    "ip": ipv4,
                    "mac": mac,
                    "is_up": st.isup if st else True,
                    "speed_mbps": st.speed if st else 0,
                }
            )
        return res

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self.prev_io = psutil.net_io_counters(pernic=True)
        self.prev_io_time = time.time()
        self._try_start_raw_sniffer()

    def _try_start_raw_sniffer(self) -> None:
        try:
            test_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            test_sock.close()
        except PermissionError:
            self.raw_capture_active = False
            self.raw_capture_error = "Raw paket yakalama için root veya CAP_NET_RAW yetkisi gerekir (Socket Flow Modu aktif)."
            return
        except Exception as exc:
            self.raw_capture_active = False
            self.raw_capture_error = f"Ham soket açılamadı ({exc}). Socket Flow Modu aktif."
            return

        try:
            from scapy.all import AsyncSniffer  # type: ignore

            if self.sniffer:
                try:
                    self.sniffer.stop()
                except Exception:
                    pass

            if self.selected_iface in ("all", "any", ""):
                all_stats = psutil.net_if_stats()
                active_ifaces = [
                    name
                    for name, st in all_stats.items()
                    if st.isup and name != "lo" and not name.startswith("veth")
                ]
                iface_arg = active_ifaces if active_ifaces else None
            else:
                iface_arg = self.selected_iface

            self.sniffer = AsyncSniffer(
                iface=iface_arg,
                prn=self._on_raw_packet,
                store=False,
            )
            self.sniffer.start()
            time.sleep(0.15)
            if getattr(self.sniffer, "running", False):
                self.raw_capture_active = True
                self.raw_capture_error = ""
            else:
                self.raw_capture_active = False
                self.raw_capture_error = "Raw paket yakalama için root veya CAP_NET_RAW yetkisi gerekir (Socket Flow Modu aktif)."
        except Exception as exc:
            self.raw_capture_active = False
            self.raw_capture_error = f"Scapy Raw Sniffer başlatılamadı ({exc}). Socket Flow Modu aktif."

    def _on_raw_packet(self, scapy_pkt: Any) -> None:
        try:
            from scapy.layers.dns import DNS, DNSQR  # type: ignore
            from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
            from scapy.layers.inet6 import IPv6  # type: ignore
            from scapy.layers.l2 import Ether  # type: ignore

            pkt_dict: Dict[str, Any] = {
                "timestamp": time.time(),
                "iface": getattr(scapy_pkt, "sniffed_on", self.selected_iface or "any") or "any",
                "src_mac": "",
                "dst_mac": "",
                "eth_type": "IPv4 (0x0800)",
                "src_ip": "",
                "dst_ip": "",
                "ip_version": 4,
                "ttl": 64,
                "protocol": "OTHER",
                "l7_proto": "",
                "src_port": 0,
                "dst_port": 0,
                "tcp_flags": "",
                "seq_num": 0,
                "ack_num": 0,
                "window_size": 0,
                "length": len(scapy_pkt),
                "domain_sni": "",
                "info": "",
                "payload_hex": "",
                "payload_ascii": "",
                "container_name": "",
                "process_name": "",
            }

            if scapy_pkt.haslayer(Ether):
                eth = scapy_pkt[Ether]
                pkt_dict["src_mac"] = eth.src
                pkt_dict["dst_mac"] = eth.dst
                pkt_dict["eth_type"] = f"0x{eth.type:04x}"
            else:
                pkt_dict["src_mac"] = "L3/TUNNEL"
                pkt_dict["dst_mac"] = "L3/TUNNEL"
                pkt_dict["eth_type"] = "IPv4 (0x0800)" if scapy_pkt.haslayer(IP) else "IPv6 (0x86dd)"

            if scapy_pkt.haslayer(IP):
                ip = scapy_pkt[IP]
                pkt_dict["src_ip"] = ip.src
                pkt_dict["dst_ip"] = ip.dst
                pkt_dict["ip_version"] = 4
                pkt_dict["ttl"] = int(ip.ttl)
            elif scapy_pkt.haslayer(IPv6):
                ip6 = scapy_pkt[IPv6]
                pkt_dict["src_ip"] = ip6.src
                pkt_dict["dst_ip"] = ip6.dst
                pkt_dict["ip_version"] = 6
                pkt_dict["ttl"] = int(ip6.hlim)
                pkt_dict["eth_type"] = "IPv6 (0x86dd)"
            else:
                return

            # Filter out noisy self WebSocket frames on port 8765
            raw_payload = b""
            if scapy_pkt.haslayer(TCP):
                tcp = scapy_pkt[TCP]
                pkt_dict["protocol"] = "TCP"
                pkt_dict["src_port"] = int(tcp.sport)
                pkt_dict["dst_port"] = int(tcp.dport)
                fl_str = str(tcp.flags)
                # Ignore noisy continuous WebSocket frames on port 8765, allow SYN/FIN for visibility
                if pkt_dict["src_port"] == 8765 or pkt_dict["dst_port"] == 8765:
                    if "S" not in fl_str and "F" not in fl_str and "R" not in fl_str:
                        return
                flag_map = [("S", "SYN"), ("A", "ACK"), ("P", "PSH"), ("F", "FIN"), ("R", "RST"), ("U", "URG")]
                fl_str = str(tcp.flags)
                pkt_dict["tcp_flags"] = ",".join(name for ch, name in flag_map if ch in fl_str)
                pkt_dict["seq_num"] = int(tcp.seq)
                pkt_dict["ack_num"] = int(tcp.ack)
                pkt_dict["window_size"] = int(tcp.window)
                raw_payload = bytes(tcp.payload)
            elif scapy_pkt.haslayer(UDP):
                udp = scapy_pkt[UDP]
                pkt_dict["protocol"] = "UDP"
                pkt_dict["src_port"] = int(udp.sport)
                pkt_dict["dst_port"] = int(udp.dport)
                raw_payload = bytes(udp.payload)
            elif scapy_pkt.haslayer(ICMP):
                icmp = scapy_pkt[ICMP]
                pkt_dict["protocol"] = "ICMP"
                pkt_dict["l7_proto"] = "ICMP"
                pkt_dict["info"] = f"ICMP Type={icmp.type} Code={icmp.code}"
                raw_payload = bytes(icmp.payload)

            # L7 Detection
            sport, dport = pkt_dict["src_port"], pkt_dict["dst_port"]
            if scapy_pkt.haslayer(DNS) and scapy_pkt.haslayer(DNSQR):
                pkt_dict["l7_proto"] = "DNS"
                qname = scapy_pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="ignore").rstrip(".")
                pkt_dict["domain_sni"] = str(qname)
                pkt_dict["info"] = f"DNS Sorgusu: {qname}"
            else:
                sni = extract_tls_sni(raw_payload) if (dport == 443 or sport == 443) else ""
                http_host, http_line = extract_http_info(raw_payload)
                if sni:
                    pkt_dict["l7_proto"] = "TLS"
                    pkt_dict["domain_sni"] = sni
                    pkt_dict["info"] = f"TLS ClientHello SNI={sni}"
                elif http_line:
                    pkt_dict["l7_proto"] = "HTTP"
                    pkt_dict["domain_sni"] = http_host
                    pkt_dict["info"] = f"{http_line} (Host: {http_host})" if http_host else http_line
                else:
                    wk = WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport)
                    pkt_dict["l7_proto"] = wk["proto"] if wk else pkt_dict["protocol"]
                    flags_disp = f" [{pkt_dict['tcp_flags']}]" if pkt_dict["tcp_flags"] else ""
                    pkt_dict["info"] = f"{pkt_dict['src_ip']}:{sport} -> {pkt_dict['dst_ip']}:{dport}{flags_disp} Len={pkt_dict['length']}"

            if raw_payload:
                p_hex, p_asc = format_hex_ascii(raw_payload)
                pkt_dict["payload_hex"] = p_hex
                pkt_dict["payload_ascii"] = p_asc

            src_c = self.ip_to_container.get(pkt_dict["src_ip"], "")
            dst_c = self.ip_to_container.get(pkt_dict["dst_ip"], "")
            if not src_c and sport in self.port_to_container:
                src_c = self.port_to_container[sport]
            if not dst_c and dport in self.port_to_container:
                dst_c = self.port_to_container[dport]

            pkt_dict["src_container"] = src_c
            pkt_dict["dst_container"] = dst_c
            pkt_dict["container_name"] = src_c or dst_c or ""
            pkt_dict["osi"] = build_osi_explanation(pkt_dict)
            self.record_packet(pkt_dict)
        except Exception:
            pass

    def record_packet(self, pkt_dict: Dict[str, Any], force_store: bool = False) -> Dict[str, Any]:
        decision = self._evaluate_packet(pkt_dict)
        if isinstance(pkt_dict.get("osi"), dict):
            pkt_dict["osi"]["decision"] = decision

        self._check_packet_rules(pkt_dict, decision)

        now = time.time()
        flags = pkt_dict.get("tcp_flags", "")
        is_interesting = (
            force_store
            or bool(pkt_dict.get("domain_sni"))
            or any(f in flags for f in ("SYN", "FIN", "RST"))
            or pkt_dict.get("l7_proto") in ("DNS", "HTTP", "ICMP")
            or not decision.get("is_benign", True)
        )

        if not is_interesting:
            flow_key = (
                pkt_dict.get("src_ip", ""),
                int(pkt_dict.get("src_port") or 0),
                pkt_dict.get("dst_ip", ""),
                int(pkt_dict.get("dst_port") or 0),
                pkt_dict.get("protocol", ""),
            )
            settings = get_settings()
            dedup_sec = float(settings.get("flow_dedup_seconds", "30") or 30.0)
            last_ts = self._seen_flows.get(flow_key, 0.0)
            if now - last_ts < dedup_sec:
                record_device_traffic_only(pkt_dict)
                return pkt_dict
            if len(self._seen_flows) > 1500:
                self._seen_flows = {k: v for k, v in self._seen_flows.items() if now - v < 120.0}
            self._seen_flows[flow_key] = now

        pkt_id = insert_packet(pkt_dict)
        pkt_dict["id"] = pkt_id
        with self._lock:
            self.recent_packets.appendleft(pkt_dict)
        return pkt_dict

    def _evaluate_packet(self, pkt: Dict[str, Any]) -> Dict[str, Any]:
        settings = get_settings()
        watched_raw = settings.get("watched_ports", "21,22,23,3389,4444,5900")
        watched_ports = {int(p.strip()) for p in watched_raw.split(",") if p.strip().isdigit()}
        allow_raw = settings.get("allowlist_ips", "")
        custom_allow = {ip.strip() for ip in allow_raw.split(",") if ip.strip()}
        return evaluate_traffic_decision(
            pkt=pkt,
            local_ips=self.local_ips,
            listening_ports=self.listening_ports,
            outbound_remote_ips=self.outbound_remote_ips,
            watched_ports=watched_ports,
            custom_allowlist=custom_allow,
        )

    def _check_packet_rules(self, pkt: Dict[str, Any], decision: Dict[str, Any]) -> None:
        if decision.get("is_benign", False):
            return

        now = time.time()
        if now - self._port_scan_reset > 30:
            self._port_scan_tracker.clear()
            self._port_scan_reset = now
        if len(self._alert_cooldown) > 1000:
            self._alert_cooldown = {k: v for k, v in self._alert_cooldown.items() if now - v < 300}

        settings = get_settings()
        scan_thresh = int(settings.get("port_scan_threshold", "15") or 15)

        src_ip = pkt.get("src_ip", "")
        dst_ip = pkt.get("dst_ip", "")
        dst_port = int(pkt.get("dst_port", 0))
        risk = decision.get("risk_score", 50)
        provider = decision.get("provider", "Bilinmiyor")
        reason = decision.get("reason", "")

        # 1. Watched sensitive port check (only when decision engine confirms external inbound probe)
        if decision.get("should_alert_port") and dst_port > 0:
            key = f"port:{src_ip}:{dst_port}"
            if now - self._alert_cooldown.get(key, 0) > 60:
                self._alert_cooldown[key] = now
                self._schedule_alert(
                    "high" if risk >= 75 else "medium",
                    "Kritik Port Erişim Denemesi",
                    src_ip,
                    dst_ip,
                    dst_port,
                    f"[Risk: {risk}/100 | {provider}] {reason}",
                )

        # 2. Inbound Port Scan Detection (only tracks external unsolicited inbound probes to distinct local ports)
        if decision.get("should_track_scan") and src_ip and dst_port > 0:
            self._port_scan_tracker[src_ip].add(dst_port)
            if len(self._port_scan_tracker[src_ip]) >= scan_thresh:
                key = f"scan:{src_ip}"
                if now - self._alert_cooldown.get(key, 0) > 120:
                    self._alert_cooldown[key] = now
                    ports_list = sorted(list(self._port_scan_tracker[src_ip]))[:8]
                    ports_count = len(self._port_scan_tracker[src_ip])
                    self._schedule_alert(
                        "high",
                        "Doğrulanmış Port Taraması (Inbound Scan)",
                        src_ip,
                        dst_ip,
                        dst_port,
                        f"[Risk: 90/100 | {provider}] Dış kaynak son 30 sn içinde {ports_count} farklı yerel porta ({', '.join(map(str, ports_list))}...) tarama yaptı.",
                    )

    def _schedule_alert(
        self, severity: str, rule_name: str, src_ip: str, dst_ip: str, dst_port: int, message: str
    ) -> None:
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(
                trigger_alert(severity, rule_name, src_ip, dst_ip, dst_port, message),
                self._loop,
            )

    def sample_metrics(self) -> Dict[str, Any]:
        now = time.time()
        dt = max(0.2, now - self.prev_io_time)
        curr_io = psutil.net_io_counters(pernic=True)

        total_rx_bps = 0.0
        total_tx_bps = 0.0
        total_rx_pps = 0.0
        total_tx_pps = 0.0
        per_iface: Dict[str, Dict[str, float]] = {}

        for iface, counters in curr_io.items():
            if iface == "lo":
                continue
            prev = self.prev_io.get(iface)
            if prev:
                rx_bps = max(0.0, (counters.bytes_recv - prev.bytes_recv) / dt)
                tx_bps = max(0.0, (counters.bytes_sent - prev.bytes_sent) / dt)
                rx_pps = max(0.0, (counters.packets_recv - prev.packets_recv) / dt)
                tx_pps = max(0.0, (counters.packets_sent - prev.packets_sent) / dt)
                per_iface[iface] = {
                    "rx_bps": round(rx_bps, 1),
                    "tx_bps": round(tx_bps, 1),
                    "rx_pps": round(rx_pps, 1),
                    "tx_pps": round(tx_pps, 1),
                    "total_rx": counters.bytes_recv,
                    "total_tx": counters.bytes_sent,
                }
                if self.selected_iface in ("all", "any", "") or self.selected_iface == iface:
                    total_rx_bps += rx_bps
                    total_tx_bps += tx_bps
                    total_rx_pps += rx_pps
                    total_tx_pps += tx_pps

        self.prev_io = curr_io
        self.prev_io_time = now

        point = {
            "timestamp": now,
            "rx_bps": round(total_rx_bps, 1),
            "tx_bps": round(total_tx_bps, 1),
            "rx_pps": round(total_rx_pps, 1),
            "tx_pps": round(total_tx_pps, 1),
            "interfaces": per_iface,
        }
        self.bandwidth_history.append(point)

        # Bandwidth threshold check
        settings = get_settings()
        bw_limit_mbps = float(settings.get("bandwidth_threshold_mbps", "50.0") or 50.0)
        current_mbps = ((total_rx_bps + total_tx_bps) * 8.0) / 1_000_000.0
        if current_mbps > bw_limit_mbps:
            key = "bw_limit"
            if now - self._alert_cooldown.get(key, 0) > 60:
                self._alert_cooldown[key] = now
                self._schedule_alert(
                    "high",
                    "Yüksek Bant Genişliği Aşımı",
                    self.get_local_ip(),
                    "all",
                    0,
                    f"Anlık toplam trafik {current_mbps:.2f} Mbps ile eşik değerini ({bw_limit_mbps} Mbps) aştı.",
                )

        self._refresh_connections_and_flows()
        return point

    def _refresh_connections_and_flows(self) -> None:
        conns_out: List[Dict[str, Any]] = []
        now = time.time()

        # Refresh local IPs every 30s instead of every 1s
        if now - self._last_local_ips_time > 30.0 or not self.local_ips:
            new_local_ips: Set[str] = {"127.0.0.1", "::1"}
            try:
                for _, addrs in psutil.net_if_addrs().items():
                    for a in addrs:
                        if a.family in (socket.AF_INET, socket.AF_INET6) and a.address:
                            new_local_ips.add(a.address.split("%")[0])
            except Exception:
                pass
            self.local_ips = new_local_ips
            self._last_local_ips_time = now

        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            conns = []

        new_listening: Set[int] = set()
        new_outbound_remotes: Set[str] = set()
        for c in conns:
            if c.status == "LISTEN" and c.laddr:
                new_listening.add(c.laddr.port)
            elif c.raddr and c.raddr.ip and c.laddr and c.laddr.port not in new_listening:
                new_outbound_remotes.add(c.raddr.ip)
        self.listening_ports = new_listening
        self.outbound_remote_ips = new_outbound_remotes

        for c in conns:
            laddr_ip = c.laddr.ip if c.laddr else ""
            laddr_port = c.laddr.port if c.laddr else 0
            raddr_ip = c.raddr.ip if c.raddr else ""
            raddr_port = c.raddr.port if c.raddr else 0

            if laddr_port == 8765 or raddr_port == 8765:
                continue

            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            status = c.status if proto == "TCP" else "STATELESS"
            proc_name = ""
            if c.pid:
                cached = self._pid_cache.get(c.pid)
                if cached and (now - cached[0] < 15.0):
                    proc_name = cached[1]
                else:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except Exception:
                        proc_name = f"pid:{c.pid}"
                    self._pid_cache[c.pid] = (now, proc_name)

            container = (
                self.ip_to_container.get(laddr_ip)
                or self.ip_to_container.get(raddr_ip)
                or self.port_to_container.get(laddr_port)
                or self.port_to_container.get(raddr_port)
                or ""
            )

            remote_provider = identify_ip_provider(raddr_ip)["provider"] if raddr_ip else "-"

            conns_out.append(
                {
                    "proto": proto,
                    "local_ip": laddr_ip,
                    "local_port": laddr_port,
                    "remote_ip": raddr_ip,
                    "remote_port": raddr_port,
                    "remote_provider": remote_provider,
                    "status": status,
                    "status_explain": TCP_STATE_GUIDE.get(status, "UDP bağlantısız soket akışı."),
                    "pid": c.pid or 0,
                    "process": proc_name or "kernel/system",
                    "container": container,
                }
            )

            # In Socket Flow mode (when raw capture is off), synthesize educational flow packets for active remote connections
            if not self.raw_capture_active and raddr_ip and not raddr_ip.startswith("127."):
                if len(self._seen_flows) > 1500:
                    self._seen_flows = {k: v for k, v in self._seen_flows.items() if now - v < 60.0}
                flow_key = (laddr_ip, laddr_port, raddr_ip, raddr_port, status)
                last_logged = self._seen_flows.get(flow_key, 0)
                if now - last_logged > 15.0:
                    self._seen_flows[flow_key] = now
                    wk = WELL_KNOWN_PORTS.get(raddr_port) or WELL_KNOWN_PORTS.get(laddr_port)
                    l7 = wk["proto"] if wk else proto
                    flags = (
                        "SYN"
                        if status == "SYN_SENT"
                        else ("FIN,ACK" if "FIN" in status or "CLOSE" in status else ("ACK,PSH" if status == "ESTABLISHED" else ""))
                    )
                    payload_summary = f"FLOW {proto} {laddr_ip}:{laddr_port} -> {raddr_ip}:{raddr_port} [{status}] proc={proc_name}".encode()
                    p_hex, p_asc = format_hex_ascii(payload_summary)
                    pkt_dict = {
                        "timestamp": now,
                        "iface": self.selected_iface or "socket",
                        "src_mac": "00:00:00:00:00:00",
                        "dst_mac": "00:00:00:00:00:00",
                        "eth_type": "IPv6 (0x86dd)" if ":" in laddr_ip else "IPv4 (0x0800)",
                        "src_ip": laddr_ip,
                        "dst_ip": raddr_ip,
                        "ip_version": 6 if ":" in laddr_ip else 4,
                        "ttl": 64,
                        "protocol": proto,
                        "l7_proto": l7,
                        "src_port": laddr_port,
                        "dst_port": raddr_port,
                        "tcp_flags": flags,
                        "seq_num": 1,
                        "ack_num": 1 if "ACK" in flags else 0,
                        "window_size": 64240,
                        "length": 128,
                        "domain_sni": "",
                        "info": f"[Aktif Soket Akışı] {proc_name or 'uygulama'}: {laddr_ip}:{laddr_port} -> {raddr_ip}:{raddr_port} ({status})",
                        "payload_hex": p_hex,
                        "payload_ascii": p_asc,
                        "src_container": self.ip_to_container.get(laddr_ip, ""),
                        "dst_container": self.ip_to_container.get(raddr_ip, ""),
                        "container_name": container,
                        "process_name": proc_name,
                    }
                    pkt_dict["osi"] = build_osi_explanation(pkt_dict)
                    self.record_packet(pkt_dict)

        self.active_connections = conns_out[:150]

    def _query_docker_engine(self) -> Optional[List[Dict[str, Any]]]:
        sock_path = "/var/run/docker.sock"
        if not os.path.exists(sock_path):
            return None
        try:
            import http.client

            class UnixConn(http.client.HTTPConnection):
                def __init__(conn_self):
                    super().__init__("localhost")

                def connect(conn_self):
                    conn_self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    conn_self.sock.settimeout(2.0)
                    conn_self.sock.connect(sock_path)

            conn = UnixConn()
            try:
                conn.request("GET", "/containers/json")
                resp = conn.getresponse()
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
            finally:
                conn.close()
        except Exception:
            pass
        return None

    def refresh_docker_containers(self, force: bool = False) -> List[Dict[str, Any]]:
        now = time.time()
        if not force and (now - self._last_docker_refresh < 4.0) and self.docker_containers:
            return self.docker_containers

        containers: List[Dict[str, Any]] = []
        ip_map: Dict[str, str] = {}
        port_map: Dict[int, str] = {}

        raw_list = self._query_docker_engine()
        if raw_list is not None:
            for c in raw_list:
                cid = (c.get("Id") or "")[:12]
                name = (c.get("Names") or [""])[0].lstrip("/")
                image = c.get("Image", "")
                status = c.get("Status", "")
                net_settings = c.get("NetworkSettings", {}) or {}
                networks = net_settings.get("Networks", {}) or {}
                ips = [ninfo.get("IPAddress") for ninfo in networks.values() if ninfo.get("IPAddress")]
                net_mode = list(networks.keys())[0] if networks else "bridge"
                for ip_addr in ips:
                    ip_map[ip_addr] = name
                ports = c.get("Ports") or []
                port_parts = []
                for p in ports:
                    pub = p.get("PublicPort")
                    priv = p.get("PrivatePort")
                    ptype = p.get("Type", "tcp")
                    if pub:
                        port_map[pub] = name
                        port_parts.append(f"{pub}->{priv}/{ptype}")
                    elif priv:
                        port_map[priv] = name
                        port_parts.append(f"{priv}/{ptype}")
                ports_str = ", ".join(port_parts) or "dahili"
                containers.append(
                    {
                        "id": cid,
                        "name": name,
                        "image": image,
                        "status": status,
                        "network_mode": net_mode,
                        "ips": ips,
                        "ports": ports_str,
                        "stats": f"Ağ: {net_mode} | Durum: {status}",
                    }
                )
            self.docker_containers = containers
            self.ip_to_container = ip_map
            self.port_to_container = port_map
            self._last_docker_refresh = now
            return containers

        # Fallback if docker.sock not available but docker cli exists
        try:
            ps_out = subprocess.check_output(
                ["docker", "ps", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"],
                stderr=subprocess.DEVNULL,
                timeout=2.0,
                text=True,
            ).strip()
            if ps_out:
                for line in ps_out.splitlines():
                    cid, name, image, status, ports_str = (line.split("|") + ["", "", "", "", ""])[:5]
                    if not cid:
                        continue
                    containers.append(
                        {
                            "id": cid[:12],
                            "name": name,
                            "image": image,
                            "status": status,
                            "network_mode": "bridge",
                            "ips": [],
                            "ports": ports_str,
                            "stats": f"Durum: {status}",
                        }
                    )
        except Exception:
            pass

        self.docker_containers = containers
        self.ip_to_container = ip_map
        self.port_to_container = port_map
        self._last_docker_refresh = now
        return containers

    def export_pcap(self, packets_list: List[Dict[str, Any]], filepath: str) -> str:
        from scapy.layers.inet import IP, TCP, UDP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore
        from scapy.packet import Raw  # type: ignore
        from scapy.utils import wrpcap  # type: ignore

        scapy_pkts = []
        for p in packets_list:
            src_ip = p.get("src_ip") or "127.0.0.1"
            dst_ip = p.get("dst_ip") or "127.0.0.1"
            if ":" in src_ip or ":" in dst_ip:
                continue
            eth = Ether(
                src=p.get("src_mac") if p.get("src_mac") and p.get("src_mac") != "00:00:00:00:00:00" else "02:42:ac:11:00:01",
                dst=p.get("dst_mac") if p.get("dst_mac") and p.get("dst_mac") != "00:00:00:00:00:00" else "02:42:ac:11:00:02",
            )
            ip_layer = IP(src=src_ip, dst=dst_ip, ttl=int(p.get("ttl") or 64))
            proto = p.get("protocol", "TCP")
            sport = int(p.get("src_port") or 12345)
            dport = int(p.get("dst_port") or 80)
            payload_bytes = (p.get("info") or "YNetMon").encode("utf-8", errors="ignore")
            if proto == "UDP":
                pkt = eth / ip_layer / UDP(sport=sport, dport=dport) / Raw(load=payload_bytes)
            else:
                pkt = eth / ip_layer / TCP(sport=sport, dport=dport) / Raw(load=payload_bytes)
            pkt.time = float(p.get("timestamp") or time.time())
            scapy_pkts.append(pkt)

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        # Keep at most 3 recent .pcap files to prevent disk exhaustion
        try:
            parent = os.path.dirname(filepath)
            pcap_files = sorted(
                [
                    os.path.join(parent, f)
                    for f in os.listdir(parent)
                    if f.startswith("ynetmon_capture_") and f.endswith(".pcap")
                ],
                key=lambda x: os.path.getmtime(x),
            )
            for old_file in pcap_files[:-2]:
                try:
                    os.remove(old_file)
                except Exception:
                    pass
        except Exception:
            pass
        wrpcap(filepath, scapy_pkts)
        return filepath


monitor = NetworkMonitor()
