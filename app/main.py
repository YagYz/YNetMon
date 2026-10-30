import asyncio
import hmac
import os
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .auth import (
    COOKIE_NAME,
    CSRF_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    change_password,
    check_rate_limit,
    clear_failed_attempts,
    create_initial_admin,
    create_session,
    dummy_verify_password,
    is_setup_required,
    record_failed_attempt,
    require_auth,
    revoke_session,
    verify_password,
    verify_session_token,
    verify_websocket_auth,
)
from .database import (
    clear_alerts_db,
    clear_packets_db,
    delete_device_db,
    get_alerts,
    get_device_stats,
    get_packet_by_id,
    get_settings,
    get_storage_stats,
    get_user_by_username,
    init_db,
    query_packets,
    run_db_maintenance,
    update_device_name_db,
    update_settings,
)
from .inspector import (
    TCP_FLAG_GUIDE,
    TCP_STATE_GUIDE,
    WELL_KNOWN_PORTS,
    generate_educational_packets,
)
from .monitor import monitor
from .notifier import (
    detect_telegram_chat_id,
    send_webhook_notification,
    trigger_alert,
    validate_safe_webhook_url,
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
MASK_SENTINEL = "••••••••"


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class TelegramTokenRequest(BaseModel):
    bot_token: Optional[str] = None


class SettingsUpdate(BaseModel):
    webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    signal_mode: Optional[str] = None
    signal_phone: Optional[str] = None
    signal_target: Optional[str] = None
    signal_api_url: Optional[str] = None
    hub_url: Optional[str] = None
    hub_api_key: Optional[str] = None
    allowlist_ips: Optional[str] = None
    watched_ports: Optional[str] = None
    bandwidth_threshold_mbps: Optional[str] = None
    port_scan_threshold: Optional[str] = None
    max_stored_packets: Optional[str] = None
    retention_hours: Optional[str] = None
    flow_dedup_seconds: Optional[str] = None
    enable_notifications: Optional[str] = None


class InterfaceSelect(BaseModel):
    iface: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await asyncio.to_thread(run_db_maintenance)
    env_user = os.environ.get("YNETMON_ADMIN_USER", "").strip()
    env_pass = os.environ.get("YNETMON_ADMIN_PASS", "").strip()
    if is_setup_required() and env_user and env_pass:
        try:
            create_initial_admin(env_user, env_pass)
        except Exception:
            pass

    loop = asyncio.get_running_loop()
    monitor.start(loop)
    monitor.refresh_docker_containers()

    existing = query_packets(limit=5)
    if not existing.get("packets"):
        for sample in generate_educational_packets(monitor.get_local_ip()):
            monitor.record_packet(sample, force_store=True)

    bg_task = asyncio.create_task(_background_sampler())
    yield
    bg_task.cancel()


async def _background_sampler() -> None:
    tick = 0
    while True:
        try:
            await asyncio.to_thread(monitor.sample_metrics)
            if tick % 5 == 0:
                await asyncio.to_thread(monitor.refresh_docker_containers)
            if tick % 60 == 0 and tick > 0:
                await asyncio.to_thread(run_db_maintenance)
            tick += 1
        except Exception:
            pass
        await asyncio.sleep(1.0)


app = FastAPI(
    title="YNetMon - Homelab Network Monitor & OSI Packet Inspector",
    version="1.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _set_auth_cookies(response: Response, token: str, csrf_token: str, request: Request) -> None:
    is_https = request.url.scheme == "https"
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite="strict",
        secure=is_https,
        path="/",
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=SESSION_TTL_SECONDS,
        httponly=False,
        samesite="strict",
        secure=is_https,
        path="/",
    )


@app.get("/login", response_model=None)
async def login_page(request: Request) -> Response:
    token = request.cookies.get(COOKIE_NAME)
    if verify_session_token(token):
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return FileResponse(os.path.join(STATIC_DIR, "login.html"))


@app.get("/", response_model=None)
async def index(request: Request) -> Response:
    token = request.cookies.get(COOKIE_NAME)
    if not verify_session_token(token):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/auth/status")
async def api_auth_status(request: Request) -> Dict[str, Any]:
    setup_needed = await asyncio.to_thread(is_setup_required)
    sess = verify_session_token(request.cookies.get(COOKIE_NAME))
    return {
        "setup_required": setup_needed,
        "authenticated": bool(sess),
        "username": sess["username"] if sess else None,
        "csrf_token": sess["csrf_token"] if sess else None,
    }


@app.post("/api/auth/setup")
async def api_auth_setup(body: LoginRequest, request: Request, response: Response) -> Dict[str, Any]:
    if not await asyncio.to_thread(is_setup_required):
        raise HTTPException(status_code=400, detail="Kurulum zaten tamamlanmış. Lütfen giriş yapın.")
    try:
        await asyncio.to_thread(create_initial_admin, body.username, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    client_ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    token, csrf_token = await asyncio.to_thread(create_session, body.username.strip(), client_ip, ua)
    _set_auth_cookies(response, token, csrf_token, request)
    return {"ok": True, "username": body.username.strip(), "csrf_token": csrf_token}


@app.post("/api/auth/login")
async def api_auth_login(body: LoginRequest, request: Request, response: Response) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = check_rate_limit(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Çok fazla başarısız giriş denemesi. {retry_after} saniye sonra tekrar deneyin.",
        )

    user = await asyncio.to_thread(get_user_by_username, body.username.strip())
    if not user:
        await asyncio.to_thread(dummy_verify_password, body.password)
        pw_ok = False
    else:
        pw_ok = await asyncio.to_thread(verify_password, body.password, user["password_hash"], user["salt"])

    if not user or not pw_ok:
        fails = record_failed_attempt(client_ip)
        if fails >= 5:
            await trigger_alert(
                severity="high",
                rule_name="Brute-Force Giriş Engellendi",
                src_ip=client_ip,
                dst_ip=monitor.get_local_ip(),
                dst_port=8765,
                message=f"{client_ip} adresinden '{body.username}' hesabına ardışık {fails} başarısız şifre denemesi yapıldı.",
            )
        raise HTTPException(status_code=401, detail="Kullanıcı adı veya şifre hatalı.")

    clear_failed_attempts(client_ip)
    ua = request.headers.get("user-agent", "")
    token, csrf_token = await asyncio.to_thread(create_session, user["username"], client_ip, ua)
    _set_auth_cookies(response, token, csrf_token, request)
    return {"ok": True, "username": user["username"], "csrf_token": csrf_token}


@app.post("/api/auth/logout")
async def api_auth_logout(request: Request, response: Response, sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    await asyncio.to_thread(revoke_session, request.cookies.get(COOKIE_NAME))
    response.delete_cookie(COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")
    return {"ok": True}


@app.post("/api/auth/change-password")
async def api_change_password(
    body: PasswordChangeRequest,
    request: Request,
    response: Response,
    sess: Dict[str, str] = Depends(require_auth),
) -> Dict[str, Any]:
    ok, msg = await asyncio.to_thread(
        change_password, sess["username"], body.current_password, body.new_password
    )
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    client_ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    token, csrf_token = await asyncio.to_thread(create_session, sess["username"], client_ip, ua)
    _set_auth_cookies(response, token, csrf_token, request)
    return {"ok": True, "message": msg, "csrf_token": csrf_token}


@app.get("/api/status")
async def api_status(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    storage = await asyncio.to_thread(get_storage_stats)
    return {
        "raw_capture_active": monitor.raw_capture_active,
        "raw_capture_error": monitor.raw_capture_error,
        "selected_iface": monitor.selected_iface,
        "local_ip": monitor.get_local_ip(),
        "interfaces": monitor.get_interfaces(),
        "bandwidth_history": list(monitor.bandwidth_history),
        "username": sess["username"],
        "storage": storage,
    }


@app.post("/api/interface")
async def set_interface(body: InterfaceSelect, sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    valid_ifaces = {i["name"] for i in monitor.get_interfaces()} | {"all", "any"}
    if body.iface not in valid_ifaces:
        raise HTTPException(status_code=400, detail="Geçersiz ağ arayüzü seçildi.")
    monitor.selected_iface = body.iface
    await asyncio.to_thread(monitor._try_start_raw_sniffer)
    return {
        "selected_iface": monitor.selected_iface,
        "raw_capture_active": monitor.raw_capture_active,
        "raw_capture_error": monitor.raw_capture_error,
    }


@app.get("/api/packets")
async def api_packets(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=50000),
    ip: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    search: Optional[str] = None,
    container: Optional[str] = None,
    sess: Dict[str, str] = Depends(require_auth),
) -> Dict[str, Any]:
    res = await asyncio.to_thread(query_packets, limit, offset, ip, port, protocol, search, container)
    return res


@app.post("/api/packets/clear")
async def api_clear_packets(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    await asyncio.to_thread(clear_packets_db)
    with monitor._lock:
        monitor.recent_packets.clear()
    storage = await asyncio.to_thread(get_storage_stats)
    return {"ok": True, "storage": storage}


@app.get("/api/storage")
async def api_storage(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    return await asyncio.to_thread(get_storage_stats)


@app.post("/api/storage/vacuum")
async def api_storage_vacuum(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    stats = await asyncio.to_thread(run_db_maintenance)
    return {"ok": True, "storage": stats}


@app.get("/api/packets/{pkt_id}")
async def api_packet_detail(pkt_id: int, sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    pkt = await asyncio.to_thread(get_packet_by_id, pkt_id)
    if not pkt:
        raise HTTPException(status_code=404, detail="Paket bulunamadı")
    return pkt


@app.post("/api/lab/generate")
async def api_generate_lab_traffic(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    samples = generate_educational_packets(monitor.get_local_ip())
    recorded = []
    for s in samples:
        rec = await asyncio.to_thread(monitor.record_packet, s, True)
        recorded.append(rec)
    return {"status": "ok", "generated": len(recorded), "packets": recorded}


@app.get("/api/export/pcap")
async def api_export_pcap(
    limit: int = Query(200, ge=1, le=2000),
    sess: Dict[str, str] = Depends(require_auth),
) -> FileResponse:
    res = await asyncio.to_thread(query_packets, limit, 0)
    pkts = res.get("packets", [])
    filename = f"ynetmon_capture_{int(time.time())}.pcap"
    filepath = os.path.join(DATA_DIR, filename)
    await asyncio.to_thread(monitor.export_pcap, pkts, filepath)
    return FileResponse(filepath, media_type="application/vnd.tcpdump.pcap", filename=filename)


@app.get("/api/connections")
async def api_connections(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    return {"connections": monitor.active_connections, "count": len(monitor.active_connections)}


class DeviceNameUpdate(BaseModel):
    name: str = Field(..., max_length=64)


@app.get("/api/devices")
async def api_devices(
    search: Optional[str] = None,
    filter: Optional[str] = None,
    sess: Dict[str, str] = Depends(require_auth),
) -> Dict[str, Any]:
    devices = await asyncio.to_thread(get_device_stats, 200, search, filter)
    active_count = sum(1 for d in devices if d.get("is_online"))
    return {"devices": devices, "count": len(devices), "active_count": active_count}


@app.post("/api/devices/{ip}/name")
async def api_update_device_name(
    ip: str,
    body: DeviceNameUpdate,
    sess: Dict[str, str] = Depends(require_auth),
) -> Dict[str, Any]:
    ok = await asyncio.to_thread(update_device_name_db, ip, body.name)
    if not ok:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadı.")
    return {"ok": True, "ip": ip, "name": body.name}


@app.delete("/api/devices/{ip}")
async def api_delete_device(
    ip: str,
    sess: Dict[str, str] = Depends(require_auth),
) -> Dict[str, Any]:
    ok = await asyncio.to_thread(delete_device_db, ip)
    if not ok:
        raise HTTPException(status_code=404, detail="Cihaz bulunamadı.")
    return {"ok": True, "ip": ip}


@app.get("/api/docker")
async def api_docker(
    refresh: bool = False,
    sess: Dict[str, str] = Depends(require_auth),
) -> Dict[str, Any]:
    if refresh:
        await asyncio.to_thread(monitor.refresh_docker_containers)
    return {"containers": monitor.docker_containers}


@app.get("/api/alerts")
async def api_alerts(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    alerts = await asyncio.to_thread(get_alerts, 100)
    return {"alerts": alerts}


@app.post("/api/alerts/clear")
async def api_clear_alerts(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    await asyncio.to_thread(clear_alerts_db)
    return {"ok": True}


@app.get("/api/settings")
async def api_get_settings(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, str]:
    raw = await asyncio.to_thread(get_settings)
    masked = dict(raw)
    if masked.get("webhook_url"):
        masked["webhook_url"] = MASK_SENTINEL
    if masked.get("telegram_bot_token"):
        masked["telegram_bot_token"] = MASK_SENTINEL
    if masked.get("hub_api_key"):
        masked["hub_api_key"] = MASK_SENTINEL
    if masked.get("signal_target") and masked.get("signal_mode", "callmebot") == "callmebot":
        masked["signal_target"] = MASK_SENTINEL
    return masked


@app.post("/api/settings")
async def api_update_settings(
    body: SettingsUpdate,
    sess: Dict[str, str] = Depends(require_auth),
) -> Dict[str, str]:
    existing = await asyncio.to_thread(get_settings)
    clean: Dict[str, str] = {}
    for k, v in body.model_dump().items():
        if v is None:
            continue
        val_str = str(v).strip()
        if k in ("webhook_url", "telegram_bot_token", "signal_target", "hub_api_key") and val_str == MASK_SENTINEL:
            clean[k] = existing.get(k, "")
            continue
        if k == "webhook_url" and val_str:
            ok, reason = await asyncio.to_thread(validate_safe_webhook_url, val_str, False)
            if not ok:
                raise HTTPException(status_code=400, detail=reason)
        if k in ("signal_api_url", "hub_url") and val_str:
            ok, reason = await asyncio.to_thread(validate_safe_webhook_url, val_str, True)
            if not ok:
                raise HTTPException(status_code=400, detail=reason)
        if k == "bandwidth_threshold_mbps" and val_str:
            try:
                bw_val = float(val_str)
                if not (0.1 <= bw_val <= 100000.0):
                    raise ValueError()
                val_str = str(round(bw_val, 2))
            except ValueError:
                raise HTTPException(status_code=400, detail="Bant genişliği eşiği 0.1 ile 100000 Mbps arasında olmalıdır.")
        if k == "port_scan_threshold" and val_str:
            try:
                ps_val = int(val_str)
                if not (2 <= ps_val <= 10000):
                    raise ValueError()
                val_str = str(ps_val)
            except ValueError:
                raise HTTPException(status_code=400, detail="Port tarama eşiği 2 ile 10000 arasında bir tam sayı olmalıdır.")
        if k == "max_stored_packets" and val_str:
            try:
                mp_val = int(val_str)
                if not (100 <= mp_val <= 10000):
                    raise ValueError()
                val_str = str(mp_val)
            except ValueError:
                raise HTTPException(status_code=400, detail="Maksimum paket kaydı 100 ile 10000 arasında olmalıdır.")
        if k == "retention_hours" and val_str:
            try:
                rh_val = float(val_str)
                if not (1.0 <= rh_val <= 720.0):
                    raise ValueError()
                val_str = str(round(rh_val, 1))
            except ValueError:
                raise HTTPException(status_code=400, detail="Kayıt saklama süresi 1 ile 720 saat arasında olmalıdır.")
        if k == "flow_dedup_seconds" and val_str:
            try:
                fd_val = int(val_str)
                if not (0 <= fd_val <= 600):
                    raise ValueError()
                val_str = str(fd_val)
            except ValueError:
                raise HTTPException(status_code=400, detail="Akış tekilleştirme süresi 0 ile 600 saniye arasında olmalıdır.")
        if k == "watched_ports" and val_str:
            ports_list = [p.strip() for p in val_str.split(",") if p.strip()]
            if len(ports_list) > 50 or not all(p.isdigit() and 1 <= int(p) <= 65535 for p in ports_list):
                raise HTTPException(status_code=400, detail="İzlenen portlar 1-65535 arasında virgülle ayrılmış sayılar olmalıdır.")
            val_str = ",".join(ports_list)
        clean[k] = val_str

    await asyncio.to_thread(update_settings, clean)
    await asyncio.to_thread(run_db_maintenance)
    return await api_get_settings(sess)


# External Bot Hub & Homelab Integration API (Authenticated via X-API-Key header)
async def require_integration_key(request: Request) -> None:
    provided = request.headers.get("X-API-Key", "").strip()
    settings = await asyncio.to_thread(get_settings)
    expected = (settings.get("hub_api_key") or "").strip()
    if not expected or len(expected) < 8:
        raise HTTPException(
            status_code=403,
            detail="Entegrasyon API'si için Ayarlar'dan en az 8 karakterli bir 'Bot Hub API Key' tanımlayın.",
        )
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Geçersiz X-API-Key.")


@app.get("/api/v1/integration/summary", dependencies=[Depends(require_integration_key)])
async def integration_summary() -> Dict[str, Any]:
    """External integration endpoint for Telegram Bot Hub / Homepage / Uptime monitors."""
    latest_bw = monitor.bandwidth_history[-1] if monitor.bandwidth_history else {
        "rx_bps": 0,
        "tx_bps": 0,
        "rx_pps": 0,
        "tx_pps": 0,
    }
    storage = await asyncio.to_thread(get_storage_stats)
    recent_alerts = await asyncio.to_thread(get_alerts, 5)
    return {
        "service": "YNetMon",
        "local_ip": monitor.get_local_ip(),
        "capture_mode": "raw_l2_l7" if monitor.raw_capture_active else "socket_flow",
        "rx_bps": latest_bw.get("rx_bps", 0),
        "tx_bps": latest_bw.get("tx_bps", 0),
        "active_connections": len(monitor.active_connections),
        "docker_containers": len(monitor.docker_containers),
        "storage": storage,
        "recent_alerts": recent_alerts,
    }


@app.get("/api/v1/integration/alerts", dependencies=[Depends(require_integration_key)])
async def integration_alerts(limit: int = Query(20, ge=1, le=100)) -> Dict[str, Any]:
    alerts = await asyncio.to_thread(get_alerts, limit)
    return {"service": "YNetMon", "alerts": alerts}


@app.get("/api/v1/integration/docker", dependencies=[Depends(require_integration_key)])
async def integration_docker() -> Dict[str, Any]:
    return {"service": "YNetMon", "containers": monitor.docker_containers}


@app.post("/api/telegram/detect-chat-id")
async def api_detect_telegram_chat_id(
    body: TelegramTokenRequest,
    sess: Dict[str, str] = Depends(require_auth),
) -> Dict[str, Any]:
    existing = await asyncio.to_thread(get_settings)
    token = (body.bot_token or "").strip()
    if not token or token == MASK_SENTINEL:
        token = existing.get("telegram_bot_token", "")
    ok, chat_id, detail = await detect_telegram_chat_id(token)
    if ok and chat_id:
        await asyncio.to_thread(update_settings, {"telegram_bot_token": token, "telegram_chat_id": chat_id})
    return {"ok": ok, "chat_id": chat_id, "detail": detail}


@app.post("/api/alerts/test")
async def api_test_alert(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    settings = await asyncio.to_thread(get_settings)
    ok, detail = await send_webhook_notification(
        severity="high",
        rule_name="Test Bildirimi",
        src_ip=monitor.get_local_ip(),
        dst_ip="192.168.1.1",
        dst_port=22,
        message="YNetMon Homelab ağ izleme aracından gönderilen test alarmıdır.",
        settings=settings,
    )
    alert = await trigger_alert(
        severity="high",
        rule_name="Test Bildirimi",
        src_ip=monitor.get_local_ip(),
        dst_ip="192.168.1.1",
        dst_port=22,
        message=f"Test alarmı tetiklendi ({detail}).",
    )
    return {"ok": ok, "detail": detail, "alert": alert}


@app.get("/api/guide")
async def api_networking_guide(sess: Dict[str, str] = Depends(require_auth)) -> Dict[str, Any]:
    return {
        "tcp_flags": TCP_FLAG_GUIDE,
        "tcp_states": TCP_STATE_GUIDE,
        "well_known_ports": WELL_KNOWN_PORTS,
    }


_active_ws_connections = 0
MAX_WS_CONNECTIONS = 10


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket) -> None:
    global _active_ws_connections
    sess = verify_websocket_auth(websocket)
    if not sess or _active_ws_connections >= MAX_WS_CONNECTIONS:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    _active_ws_connections += 1
    await websocket.accept()
    try:
        while True:
            latest_bw = monitor.bandwidth_history[-1] if monitor.bandwidth_history else {
                "timestamp": time.time(),
                "rx_bps": 0,
                "tx_bps": 0,
                "rx_pps": 0,
                "tx_pps": 0,
            }
            payload = {
                "timestamp": time.time(),
                "raw_capture_active": monitor.raw_capture_active,
                "raw_capture_error": monitor.raw_capture_error,
                "bandwidth": latest_bw,
                "recent_packets": list(monitor.recent_packets)[:25],
                "active_connections_count": len(monitor.active_connections),
                "docker_count": len(monitor.docker_containers),
            }
            await websocket.send_json(payload)
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _active_ws_connections = max(0, _active_ws_connections - 1)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("YNETMON_PORT", "8765"))
    host = os.environ.get("YNETMON_HOST", "0.0.0.0")
    uvicorn.run("app.main:app", host=host, port=port)
