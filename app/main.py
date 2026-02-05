from fastapi import FastAPI, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import redis
import uuid
import time
import os
import json
import secrets
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from fastapi import HTTPException
from redis.exceptions import RedisError

load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0").strip() == "1"
COOKIE_SAMESITE = "lax"
COOKIE_PATH = "/"

ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = ROOT / "logs" / "app.jsonl"
DEBUG_ADMIN_TOKEN = os.environ.get("DEBUG_ADMIN_TOKEN", "").strip()
DEBUG_MODE = os.getenv("DEBUG_MODE", "0").strip() == "1"
CSRF_COOKIE = "csrf_token"

def redis_unavailable(request: Request, where: str):
    # 503を返しつつ、ログにも残す
    log_event(request, "system.redis_unavailable", severity="ERROR", meta={"where": where})
    raise HTTPException(status_code=503, detail="system_unavailable")

def safe_redis(request: Request, where: str, fn):
    try:
        return fn()
    except RedisError:
        redis_unavailable(request, where)

def require_admin(request: Request):
    token = request.headers.get("x-admin-token", "").strip()
    if not DEBUG_ADMIN_TOKEN or token != DEBUG_ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="admin_required")

def now_iso():
    # ISO8601（JSTにしたいなら後で変えられる。まずはUTC）
    return datetime.now(timezone.utc).isoformat()

def hash_str(s: str) -> str:
    # 生IPやUAをそのままログに残さない（提出物として好印象）
    # 強い暗号が要るわけじゃないので、まずはsha256でOK
    import hashlib
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]

def get_ip_hash(request: Request) -> str:
    # ローカルなら 127.0.0.1 になる
    ip = request.client.host if request.client else "unknown"
    return hash_str(ip)

def get_ua_hash(request: Request) -> str:
    ua = request.headers.get("user-agent", "unknown")
    return hash_str(ua)

def log_event(request: Request,event: str,severity: str = "INFO",user: str | None = None,meta: dict | None = None):
    rec = {
        "ts": now_iso(),
        "event": event,
        "severity": severity,
        "user": user,
        "ip_hash": get_ip_hash(request),
        "ua_hash": get_ua_hash(request),
        "path": request.url.path,
        "meta": meta or {},
        "anon_id": get_anon_id(request),
    }
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        # ログ書き込み失敗でアプリ本体を落とさない
        print("[LOG_ERROR] failed to write log_event")

def set_anon_cookie(resp, value: str):
    # ローカル開発では secure=False。本番HTTPS運用なら True にする
    resp.set_cookie(
        ANON_COOKIE,
        value,
        httponly=True,
        samesite=COOKIE_SAMESITE,
        secure=COOKIE_SECURE,
        path=COOKIE_PATH,
    )

def set_csrf_cookie(resp, value: str):
    # CSRFトークンはJSから読む設計なので httponly=False が必要
    resp.set_cookie(
        CSRF_COOKIE,
        value,
        httponly=False,
        samesite=COOKIE_SAMESITE,
        secure=COOKIE_SECURE,
        path=COOKIE_PATH,
    )

RATE_LIMIT_WINDOW = 10      # 秒
RATE_LIMIT_COUNT = 5        # 回数
BLOCK_TIME = 30             # 秒（一時ブロック）


app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)

        # 基本ヘッダ
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # CSP: まずは最小構成（このアプリの実装に合わせて調整済み）
        # - script は 'self' のみ（インラインscriptを使っているので 'unsafe-inline' を付ける）
        # - style はインラインがあるので 'unsafe-inline'
        # - connect は poll のfetchがあるので 'self'
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self';"
        )

        return resp

app.add_middleware(SecurityHeadersMiddleware)

r = redis.Redis(
    host="127.0.0.1",
    port=6379,
    decode_responses=True,
    socket_connect_timeout=1.0,
    socket_timeout=1.0,
    retry_on_timeout=True,
)

def get_risk_score(ip_hash: str, ua_hash: str) -> int:
    fp = f"{ip_hash}:{ua_hash}"
    key = f"risk:fp:{fp}"
    v = r.get(key)
    try:
        return int(v) if v else 0
    except ValueError:
        return 0

ANON_COOKIE = "anon_id"
NAME_COOKIE = "anon_name"

def get_anon_id(request: Request) -> Optional[str]:
    return request.cookies.get(ANON_COOKIE)

def get_anon_name(request: Request) -> Optional[str]:
    return request.cookies.get(NAME_COOKIE)

def ensure_anon(request: Request):
    """
    匿名ID（anon_id）が無ければ発行する。
    """
    anon_id = get_anon_id(request)
    if anon_id:
        return anon_id, None  # 既にあるのでSet-Cookie不要

    anon_id = str(uuid.uuid4())
    return anon_id, anon_id  # 新規発行したのでSet-Cookieする値も返す

def display_actor(request: Request) -> str:
    """
    表示名（任意） > anon_id短縮
    """
    name = get_anon_name(request)
    if name and name.strip():
        return name.strip()[:20]
    anon_id = get_anon_id(request) or "unknown"
    return "anon-" + anon_id.replace("-", "")[:8]

def check_csrf(request: Request) -> bool:
    cookie_tok = request.cookies.get(CSRF_COOKIE, "")
    header_tok = request.headers.get("x-csrf-token", "")
    if not cookie_tok or not header_tok:
        return False
    return secrets.compare_digest(cookie_tok, header_tok)


# --- Chat storage (Redis) ---
# list key: chat:messages (LPUSH/ LRANGE)
# message is "id|ts|user|text" (最小でOK。あとでJSONにする)
def next_message_id() -> int:
    return int(r.incr("chat:next_id"))

def add_message(user: str, text: str) -> dict:
    mid = next_message_id()
    ts = int(time.time())
    # 区切り文字に | を使うので、テキスト内の | は置換しておく（雑でOK）
    safe_text = text.replace("|", " ")
    raw = f"{mid}|{ts}|{user}|{safe_text}"
    r.lpush("chat:messages", raw)
    r.ltrim("chat:messages", 0, 199)  # 最大200件保持
    return {"id": mid, "ts": ts, "user": user, "text": safe_text}

def get_messages_latest(limit: int = 100) -> list[dict]:
    raws = r.lrange("chat:messages", 0, limit - 1)
    msgs = []
    for raw in reversed(raws):  # 古い→新しい順に表示
        try:
            mid_s, ts_s, user, text = raw.split("|", 3)
            msgs.append({"id": int(mid_s), "ts": int(ts_s), "user": user, "text": text})
        except Exception:
            continue
    return msgs

def get_messages_after(after_id: int) -> list[dict]:
    # Redis listなので効率は良くないが、最初はこれでOK（最大200件に絞ってる）
    raws = r.lrange("chat:messages", 0, 199)
    msgs = []
    for raw in reversed(raws):
        try:
            mid_s, ts_s, user, text = raw.split("|", 3)
            mid = int(mid_s)
            if mid > after_id:
                msgs.append({"id": mid, "ts": int(ts_s), "user": user, "text": text})
        except Exception:
            continue
    return msgs

#連投チェック関数
def is_rate_limited(user: str) -> bool:
    key = f"rate:{user}"
    count = r.incr(key)
    if count == 1:
        r.expire(key, RATE_LIMIT_WINDOW)
    return count > RATE_LIMIT_COUNT

def block_user(user: str):
    key = f"block:{str(user)}"
    r.setex(key, BLOCK_TIME, "1")
    # 念のため即確認（デバッグ中だけ）
    ttl = r.ttl(key)
    if ttl is None or ttl <= 0:
        # ここに来たら「書けてない」＝重大
        # まずはprintでOK（後でログにする）
        print(f"[BLOCK_ERROR] failed to set {key}, ttl={ttl}")

def is_blocked(user: str) -> bool:
    key = f"block:{str(user)}"
    ttl = r.ttl(key)
    return ttl is not None and ttl > 0

def get_block_ttl_sec(user: str) -> int:
    key = f"block:{str(user)}"
    ttl = r.ttl(key)
    # ttlは None, -1, -2 などがあり得るので安全に丸める
    if ttl is None or ttl <= 0:
        return 0
    return int(ttl)


# --- Routes ---
@app.get("/", response_class=HTMLResponse)
def root():
    return HTMLResponse("<a href='/login'>login</a>")

@app.get("/health/redis")
def redis_health(request: Request):
    try:
        r.set("healthcheck", "ok", ex=10)
        return {"redis": r.get("healthcheck")}
    except redis.exceptions.RedisError:
        return JSONResponse({"redis": "unavailable"}, status_code=503)

@app.get("/chat", response_class=HTMLResponse)
def chat_page(request: Request):
    anon_id, newly_issued = ensure_anon(request)
    csrf_tok, csrf_new = ensure_csrf(request)

    messages = safe_redis(request, "get_messages_latest", lambda: get_messages_latest(100))
    last_id = messages[-1]["id"] if messages else 0
    error = request.query_params.get("error")

    response = templates.TemplateResponse("chat.html", {
        "request": request,
        "user": display_actor(request),  # テンプレ側の表示用
        "messages": messages,
        "last_id": last_id,
        "error": error
    })

    # anon_id が新規発行されたとき
    if newly_issued:
        set_anon_cookie(response, newly_issued)

    # csrf_token が新規発行されたとき
    if csrf_new:
        set_csrf_cookie(response, csrf_new)

    return response

def ensure_csrf(request: Request):
    tok = request.cookies.get(CSRF_COOKIE)
    if tok and len(tok) >= 16:
        return tok, None
    new_tok = secrets.token_urlsafe(32)
    return new_tok, new_tok


@app.post("/chat/post")
def chat_post(request: Request, text: str = Form(...)):
    is_ajax = request.headers.get("x-requested-with", "").lower() == "fetch"
    anon_id, newly_issued = ensure_anon(request)

    if not check_csrf(request):
        log_event(request, "security.csrf_failed", severity="WARN", user=None,
                meta={"reason": "csrf_missing_or_mismatch"})
        if is_ajax:
            return JSONResponse({"ok": False, "error": "csrf_missing"}, status_code=403)
        return RedirectResponse("/chat?error=csrf_missing", status_code=303)

    # ブロック/レート制限の判定は anon_id で行う
    actor_key = anon_id
  
    # SOC runner が付与した risk スコア取得
    ip_hash = get_ip_hash(request)
    ua_hash = get_ua_hash(request)
  
    risk = safe_redis(request, "get_risk_score", lambda: get_risk_score(ip_hash, ua_hash))

    # 高リスクfingerprintは即ブロック（SOC判断）
    if risk >= 8:
        log_event(
            request,
            "security.high_risk_block",
            severity="WARN",
            user=None,
            meta={"actor": actor_key, "risk_score": risk, "reason": "risk>=8"},
        )

        if is_ajax:
            resp = JSONResponse({"ok": False, "error": "high_risk_block", "risk": risk}, status_code=403)
        else:
            resp = RedirectResponse("/chat?error=high_risk_block", status_code=303)

        if newly_issued:
            set_anon_cookie(resp, newly_issued)

        return resp

    if safe_redis(request, "is_blocked", lambda: is_blocked(actor_key)):
        ttl = safe_redis(request, "get_block_ttl_sec", lambda: get_block_ttl_sec(actor_key))

        log_event(request, "security.blocked_action_attempt", severity="WARN", user=None,
                  meta={"actor": actor_key, "action": "chat_post", "block_sec": ttl})
        if is_ajax:
            resp = JSONResponse({"ok": False, "error": "blocked", "block_sec": ttl}, status_code=429)
        else:
            resp = RedirectResponse("/chat?error=blocked", status_code=303)
        if newly_issued:
            set_anon_cookie(resp, newly_issued)

        return resp
    
    
    if safe_redis(request, "is_rate_limited", lambda: is_rate_limited(actor_key)):
        safe_redis(request, "block_user", lambda: block_user(actor_key))
        ttl = safe_redis(request, "get_block_ttl_sec", lambda: get_block_ttl_sec(actor_key))

        log_event(
            request,
            "security.rate_limited_and_blocked",
            severity="WARN",
            user=None,
            meta={
                "actor": actor_key,
                "scope": "chat_post",
                "window_sec": RATE_LIMIT_WINDOW,
                "limit": RATE_LIMIT_COUNT,
                "block_sec": ttl,
            },
        )

        if is_ajax:
            resp = JSONResponse({"ok": False, "error": "rate_limited", "block_sec": ttl}, status_code=429)
        else:
            resp = RedirectResponse("/chat?error=rate_limited", status_code=303)

        if newly_issued:
            set_anon_cookie(resp, newly_issued)
        return resp

    text = text.strip()
    #メッセージの長さ制限
    MAX_MSG_LEN = 300
    if len(text) > MAX_MSG_LEN:
        log_event(
            request,
            "security.message_too_long",
            severity="WARN",
            user=None,
            meta={"actor": actor_key, "length": len(text), "max": MAX_MSG_LEN},
        )
        if is_ajax:
            return JSONResponse({"ok": False, "error": "too_long", "max": MAX_MSG_LEN}, status_code=400)
        return RedirectResponse("/chat?error=too_long", status_code=303)

    if text:
        m = safe_redis(request, "add_message", lambda: add_message(display_actor(request), text))  #投稿者表示用の匿名名（anon-xxxx）で保存
        log_event(request, "chat.message_posted", severity="INFO", user=None,
                  meta={"actor": actor_key, "message_id": m["id"], "length": len(m["text"])})

    if is_ajax:
        resp = JSONResponse({"ok": True})
    else:
        resp = RedirectResponse("/chat", status_code=303)

    if newly_issued:
        set_anon_cookie(resp, newly_issued)
    return resp

@app.get("/chat/poll")
def chat_poll(request: Request, after: int = 0):
    anon_id, newly_issued = ensure_anon(request)

    msgs = safe_redis(request, "get_messages_after", lambda: get_messages_after(after))

    resp = JSONResponse({"messages": msgs})
    if newly_issued:
        set_anon_cookie(resp, newly_issued)

    return resp

if DEBUG_MODE:

    @app.get("/debug/unblock-me")
    def debug_unblock_me(request: Request, token: str):
        # tokenはクエリから受け取る（ローカル検証用）
        expected = os.environ.get("DEBUG_ADMIN_TOKEN", "").strip()
        if not expected or token.strip() != expected:
            raise HTTPException(status_code=403, detail="admin_required")

        anon_id = get_anon_id(request)
        fp = f"{get_ip_hash(request)}:{get_ua_hash(request)}"

        # block解除
        if anon_id:
            r.delete(f"block:{anon_id}")

        # risk解除（キー名が違う可能性があるので両方消す）
        r.delete(f"risk:fp:{fp}")
        r.delete(f"risk:{fp}")

        log_event(request, "debug.unblock_me", severity="INFO", user=None,
                meta={"anon_id": anon_id, "fingerprint": fp})

        return RedirectResponse("/chat", status_code=303)

    @app.get("/debug/block")
    def debug_block(request: Request):
        anon_id = get_anon_id(request)  # Cookieから
        if not anon_id:
            return JSONResponse({"ok": False, "error": "no_anon_id"}, status_code=400)

        key = f"block:{anon_id}"
        ttl = r.ttl(key)
        exists = 1 if r.exists(key) else 0
        return {"ok": True, "anon_id": anon_id, "key": key, "exists": str(exists), "ttl": ttl}

    @app.get("/debug/whoami")
    def debug_whoami(request: Request):
        require_admin(request)
        return {
            "anon_id": get_anon_id(request),
            "ip_hash": get_ip_hash(request),
            "ua_hash": get_ua_hash(request),
        }

    @app.post("/debug/unblock")
    def debug_unblock(request: Request):
        require_admin(request)
        anon_id = get_anon_id(request)
        if not anon_id:
            return {"ok": False, "error": "no_anon_id"}

        key = f"block:{anon_id}"
        deleted = r.delete(key)

        log_event(request, "debug.unblock", severity="INFO", user=None,
                meta={"actor": anon_id, "redis_key": key, "deleted": int(deleted)})

        return {"ok": True, "actor": anon_id, "deleted": int(deleted)}

    @app.post("/debug/reset-risk")
    def debug_reset_risk(request: Request):
        require_admin(request)
        fp = f"{get_ip_hash(request)}:{get_ua_hash(request)}"
        key = f"risk:fp:{fp}"
        deleted = r.delete(key)

        log_event(request, "debug.reset_risk", severity="INFO", user=None,
                meta={"fingerprint": fp, "redis_key": key, "deleted": int(deleted)})

        return {"ok": True, "fingerprint": fp, "deleted": int(deleted)}

