import html
import ipaddress
import socket
import time
from typing import Any, Dict, Tuple
from urllib.parse import quote_plus, urlparse

import httpx
from .database import get_settings, insert_alert


def validate_safe_webhook_url(url: str, allow_private: bool = False) -> Tuple[bool, str]:
    """Validate URL against SSRF (blocks loopback, RFC1918 private, link-local, metadata, credentials)."""
    if not url:
        return True, ""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http"):
            return False, "URL yalnızca https:// veya http:// ile başlayabilir."
        if parsed.username or parsed.password:
            return False, "Güvenlik: URL içinde kullanıcı adı/şifre kullanılamaz."
        hostname = parsed.hostname
        if not hostname:
            return False, "Geçersiz alan adı."
        if parsed.port == 8765 and hostname.lower() in ("localhost", "127.0.0.1", "::1"):
            return False, "Güvenlik: YNetMon kendi portuna (8765) bildirim gönderemez."
        if hostname.lower() == "metadata.google.internal":
            return False, "Güvenlik (SSRF koruması): Bulut metadata adresleri kullanılamaz."
        if not allow_private and hostname.lower() == "localhost":
            return False, "Güvenlik (SSRF koruması): Yerel (localhost) adreslere genel webhook gönderilemez."

        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_multicast:
                return False, f"Güvenlik (SSRF koruması): Geçersiz IP ({ip_str}) kullanılamaz."
            if not allow_private and (ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_reserved):
                return False, f"Güvenlik (SSRF koruması): Dahili/özel ağ IP adresi ({ip_str}) genel webhook olarak kullanılamaz."
        return True, ""
    except Exception as exc:
        return False, f"URL doğrulanamadı: {exc}"


async def detect_telegram_chat_id(bot_token: str) -> Tuple[bool, str, str]:
    """Fetch latest chat_id from Telegram getUpdates after user sends /start to their bot."""
    clean_token = bot_token.strip()
    if not clean_token:
        return False, "", "Önce Telegram Bot Token girin."
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(f"https://api.telegram.org/bot{clean_token}/getUpdates")
            if resp.status_code != 200:
                return False, "", f"Telegram API hatası (HTTP {resp.status_code}). Token'ı kontrol edin."
            data = resp.json()
            results = data.get("result") or []
            for item in reversed(results):
                msg = item.get("message") or item.get("channel_post") or {}
                chat = msg.get("chat") or {}
                cid = chat.get("id")
                if cid is not None:
                    title = chat.get("username") or chat.get("first_name") or chat.get("title") or str(cid)
                    return True, str(cid), f"Bulundu: {title} (Chat ID: {cid})"
            return False, "", "Henüz mesaj bulunamadı. Telegram'da botunuza '/start' yazıp tekrar tıklayın."
    except Exception as exc:
        return False, "", f"Telegram bağlantı hatası: {exc}"


async def trigger_alert(
    severity: str,
    rule_name: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    message: str,
) -> Dict[str, Any]:
    settings = get_settings()
    notified = False
    if settings.get("enable_notifications", "true").lower() == "true":
        ok, _ = await send_webhook_notification(severity, rule_name, src_ip, dst_ip, dst_port, message, settings)
        notified = ok

    alert_id = insert_alert(severity, rule_name, src_ip, dst_ip, dst_port, message, notified)
    return {
        "id": alert_id,
        "timestamp": time.time(),
        "severity": severity,
        "rule_name": rule_name,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "message": message,
        "notified": notified,
    }


async def send_webhook_notification(
    severity: str,
    rule_name: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    message: str,
    settings: Dict[str, str],
) -> Tuple[bool, str]:
    webhook_url = (settings.get("webhook_url") or "").strip()
    tg_token = (settings.get("telegram_bot_token") or "").strip()
    tg_chat = (settings.get("telegram_chat_id") or "").strip()
    signal_mode = (settings.get("signal_mode") or "callmebot").strip()
    signal_phone = (settings.get("signal_phone") or "").strip()
    signal_target = (settings.get("signal_target") or "").strip()
    signal_api_url = (settings.get("signal_api_url") or "").strip()
    hub_url = (settings.get("hub_url") or "").strip()
    hub_api_key = (settings.get("hub_api_key") or "").strip()

    results = []
    sent_any = False

    plain_summary = (
        f"🚨 YNetMon Alarm [{severity.upper()}]\n"
        f"Kural: {rule_name}\n"
        f"Kaynak: {src_ip} -> {dst_ip}:{dst_port}\n"
        f"Detay: {message}"
    )

    async with httpx.AsyncClient(timeout=6.0, follow_redirects=False) as client:
        # 0. Central Homelab Bot Gateway (hub_url)
        if hub_url:
            ok_hub, reason = validate_safe_webhook_url(hub_url, allow_private=True)
            if not ok_hub:
                results.append(f"Bot Hub URL Hatası ({reason})")
            else:
                try:
                    headers = {"Content-Type": "application/json"}
                    if hub_api_key:
                        headers["X-API-Key"] = hub_api_key
                    hub_payload = {
                        "source": "ynetmon",
                        "service": "YNetMon Homelab Guard",
                        "severity": severity,
                        "title": rule_name,
                        "message": message,
                        "metadata": {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                        },
                        "timestamp": time.time(),
                    }
                    resp = await client.post(hub_url, json=hub_payload, headers=headers)
                    if resp.status_code < 400:
                        sent_any = True
                        results.append(f"Bot Hub: Gönderildi (HTTP {resp.status_code})")
                    else:
                        results.append(f"Bot Hub Hatası (HTTP {resp.status_code})")
                except Exception as exc:
                    results.append(f"Bot Hub Bağlantı Hatası ({exc})")

        # 1. Telegram (HTML escaped to prevent formatting errors / injection)
        if tg_token and tg_chat:
            try:
                tg_url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
                html_text = (
                    f"🚨 <b>YNetMon Alarm [{html.escape(severity.upper())}]</b>\n"
                    f"<b>Kural:</b> <code>{html.escape(str(rule_name))}</code>\n"
                    f"<b>Kaynak:</b> <code>{html.escape(str(src_ip))}</code> -&gt; <code>{html.escape(str(dst_ip))}:{int(dst_port)}</code>\n"
                    f"<b>Detay:</b> {html.escape(str(message))}"
                )
                resp = await client.post(
                    tg_url,
                    json={"chat_id": tg_chat, "text": html_text, "parse_mode": "HTML"},
                )
                if resp.status_code < 400:
                    sent_any = True
                    results.append("Telegram: Gönderildi")
                else:
                    results.append(f"Telegram Hatası (HTTP {resp.status_code})")
            except Exception as exc:
                results.append(f"Telegram Bağlantı Hatası ({exc})")

        # 2. Signal (CallMeBot or self-hosted signal-cli-rest-api)
        if signal_phone and signal_target:
            try:
                if signal_mode == "rest_api" and signal_api_url:
                    ok_url, reason = validate_safe_webhook_url(signal_api_url, allow_private=True)
                    if not ok_url:
                        results.append(f"Signal URL Hatası ({reason})")
                    else:
                        endpoint = signal_api_url.rstrip("/") + "/v2/send"
                        resp = await client.post(
                            endpoint,
                            json={
                                "message": plain_summary,
                                "number": signal_phone,
                                "recipients": [r.strip() for r in signal_target.split(",") if r.strip()],
                            },
                        )
                        if resp.status_code < 400:
                            sent_any = True
                            results.append("Signal (REST API): Gönderildi")
                        else:
                            results.append(f"Signal REST Hatası (HTTP {resp.status_code})")
                else:
                    cb_url = (
                        f"https://signal.callmebot.com/signal/send.php"
                        f"?phone={quote_plus(signal_phone)}&apikey={quote_plus(signal_target)}"
                        f"&text={quote_plus(plain_summary)}"
                    )
                    resp = await client.get(cb_url)
                    if resp.status_code < 400:
                        sent_any = True
                        results.append("Signal (CallMeBot): Gönderildi")
                    else:
                        results.append(f"Signal CallMeBot Hatası (HTTP {resp.status_code})")
            except Exception as exc:
                results.append(f"Signal Hatası ({exc})")

        # 3. Discord / Generic Webhook
        if webhook_url:
            is_safe, err_reason = validate_safe_webhook_url(webhook_url, allow_private=False)
            if not is_safe:
                results.append(err_reason)
            else:
                try:
                    if "discord.com/api/webhooks" in webhook_url:
                        payload = {
                            "username": "YNetMon Homelab Guard",
                            "embeds": [
                                {
                                    "title": f"[{severity.upper()}] {rule_name[:120]}",
                                    "description": message[:500],
                                    "color": 15158332 if severity == "high" else 16753920,
                                    "fields": [
                                        {"name": "Kaynak IP", "value": (src_ip or "-")[:64], "inline": True},
                                        {"name": "Hedef", "value": f"{dst_ip}:{dst_port}"[:80], "inline": True},
                                    ],
                                }
                            ],
                        }
                    else:
                        payload = {
                            "app": "YNetMon",
                            "severity": severity,
                            "rule": rule_name,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "message": message,
                            "timestamp": time.time(),
                        }
                    resp = await client.post(webhook_url, json=payload)
                    if resp.status_code < 400:
                        sent_any = True
                        results.append(f"Webhook: Gönderildi (HTTP {resp.status_code})")
                    else:
                        results.append(f"Webhook Hatası (HTTP {resp.status_code})")
                except Exception as exc:
                    results.append(f"Webhook Bağlantı Hatası ({exc})")

    if not results:
        return False, "Bildirim kanalı tanımlı değil (Telegram, Signal veya Webhook ayarlayın)."
    return sent_any, " | ".join(results)
