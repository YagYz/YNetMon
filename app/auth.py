import hashlib
import hmac
import secrets
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple
from fastapi import HTTPException, Request, WebSocket, status

from .database import (
    create_session_db,
    create_user_db,
    delete_session_db,
    delete_user_sessions_db,
    get_session_db,
    get_user_by_username,
    get_user_count,
    update_user_password_db,
)

PBKDF2_ITERATIONS = 600_000
SESSION_TTL_SECONDS = 12 * 3600  # 12 saat
COOKIE_NAME = "ynetmon_session"
CSRF_COOKIE_NAME = "ynetmon_csrf"

# Constant-time dummy values to prevent username enumeration via timing attacks
DUMMY_SALT_HEX = "00112233445566778899aabbccddeeff"
DUMMY_HASH_HEX = "a" * 64

# Bounded brute-force rate limiter: ip -> list of failed timestamps
_failed_attempts: "OrderedDict[str, List[float]]" = OrderedDict()
MAX_TRACKED_IPS = 2000
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 300  # 5 dakika


def hash_password(password: str, salt_hex: Optional[str] = None) -> Tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return derived.hex(), salt.hex()


def verify_password(password: str, expected_hash_hex: str, salt_hex: str) -> bool:
    derived_hex, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(derived_hex, expected_hash_hex)


def dummy_verify_password(password: str) -> None:
    """Run PBKDF2 even when user is not found to prevent timing-based user enumeration."""
    verify_password(password, DUMMY_HASH_HEX, DUMMY_SALT_HEX)


def validate_password_strength(password: str) -> Optional[str]:
    if len(password) < 8:
        return "Şifre en az 8 karakter olmalıdır."
    if len(password) > 128:
        return "Şifre 128 karakterden uzun olamaz."
    return None


def check_rate_limit(client_ip: str) -> Tuple[bool, int]:
    now = time.time()
    attempts = [ts for ts in _failed_attempts.get(client_ip, []) if now - ts < LOCKOUT_WINDOW_SECONDS]
    if attempts:
        _failed_attempts[client_ip] = attempts
    else:
        _failed_attempts.pop(client_ip, None)
    if len(attempts) >= MAX_FAILED_ATTEMPTS:
        retry_after = int(LOCKOUT_WINDOW_SECONDS - (now - attempts[0]))
        return False, max(1, retry_after)
    return True, 0


def record_failed_attempt(client_ip: str) -> int:
    now = time.time()
    while len(_failed_attempts) >= MAX_TRACKED_IPS:
        _failed_attempts.popitem(last=False)
    attempts = [ts for ts in _failed_attempts.get(client_ip, []) if now - ts < LOCKOUT_WINDOW_SECONDS]
    attempts.append(now)
    _failed_attempts[client_ip] = attempts
    return len(attempts)


def clear_failed_attempts(client_ip: str) -> None:
    _failed_attempts.pop(client_ip, None)


def is_setup_required() -> bool:
    return get_user_count() == 0


def create_initial_admin(username: str, password: str) -> bool:
    if get_user_count() > 0:
        return False
    clean_user = username.strip()
    if not clean_user or len(clean_user) < 3 or len(clean_user) > 32:
        raise ValueError("Kullanıcı adı 3-32 karakter arasında olmalıdır.")
    if not all(ch.isalnum() or ch in ("_", "-", ".") for ch in clean_user):
        raise ValueError("Kullanıcı adı yalnızca harf, rakam ve . _ - içerebilir.")
    err = validate_password_strength(password)
    if err:
        raise ValueError(err)
    pw_hash, salt = hash_password(password)
    create_user_db(clean_user, pw_hash, salt)
    return True


def create_session(username: str, client_ip: str, user_agent: str) -> Tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_hex(16)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = time.time() + SESSION_TTL_SECONDS
    create_session_db(token_hash, username, csrf_token, client_ip, user_agent[:200], expires_at)
    return token, csrf_token


def verify_session_token(token: Optional[str]) -> Optional[Dict[str, str]]:
    if not token or len(token) > 128:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    sess = get_session_db(token_hash)
    if not sess:
        return None
    if time.time() > float(sess["expires_at"]):
        delete_session_db(token_hash)
        return None
    return {
        "username": sess["username"],
        "csrf_token": sess["csrf_token"],
        "token_hash": token_hash,
    }


def revoke_session(token: Optional[str]) -> None:
    if not token:
        return
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    delete_session_db(token_hash)


def change_password(username: str, current_password: str, new_password: str) -> Tuple[bool, str]:
    user = get_user_by_username(username)
    if not user:
        return False, "Kullanıcı bulunamadı."
    if not verify_password(current_password, user["password_hash"], user["salt"]):
        return False, "Mevcut şifre hatalı."
    err = validate_password_strength(new_password)
    if err:
        return False, err
    pw_hash, salt = hash_password(new_password)
    update_user_password_db(username, pw_hash, salt)
    delete_user_sessions_db(username)
    return True, "Şifre başarıyla güncellendi."


def require_auth(request: Request) -> Dict[str, str]:
    token = request.cookies.get(COOKIE_NAME)
    sess = verify_session_token(token)
    if not sess:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Oturum açmanız gerekiyor.")
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        header_csrf = request.headers.get("X-CSRF-Token", "")
        if not header_csrf or not hmac.compare_digest(header_csrf, sess["csrf_token"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Geçersiz CSRF anahtarı.")
    return sess


def verify_websocket_auth(websocket: WebSocket) -> Optional[Dict[str, str]]:
    # CSWSH protection: verify Origin matches Host if Origin header is present
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    if origin and host:
        origin_host = origin.split("://")[-1].split("/")[0]
        if origin_host.lower() != host.lower():
            return None
    token = websocket.cookies.get(COOKIE_NAME)
    return verify_session_token(token)
