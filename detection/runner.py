import os
import time
import json
import requests
import redis
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(dotenv_path=ROOT / ".env")

r = redis.Redis(host="localhost", port=6379, decode_responses=True)

LOG_PATH = Path("logs/app.jsonl")

# Discord webhook URL を環境変数から読む（コードに直書きしない）
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()

# 通知対象イベント（まずは分かりやすく security.* を中心）
DEFAULT_NOTIFY_PREFIXES = ("security.",)
DEFAULT_NOTIFY_EVENTS = {
    "auth.login_fail",  # オプション（入れておくとそれっぽい）
}

def should_notify(event: str) -> bool:
    if event in DEFAULT_NOTIFY_EVENTS:
        return True
    return any(event.startswith(p) for p in DEFAULT_NOTIFY_PREFIXES)

def format_message(rec: dict) -> str:
    # Discordに読みやすい要約を作る
    ts = rec.get("ts")
    event = rec.get("event")
    sev = rec.get("severity")
    user = rec.get("user")
    path = rec.get("path")
    ip_hash = rec.get("ip_hash")
    ua_hash = rec.get("ua_hash")
    anon_id = rec.get("anon_id")
    meta = rec.get("meta", {})

    lines = []
    lines.append(f"**[{sev}] {event}**")
    lines.append(f"- time: `{ts}`")
    lines.append(f"- user: `{user}`")
    lines.append(f"- path: `{path}`")
    lines.append(f"- ip_hash: `{ip_hash}`")
    lines.append(f"- ua_hash: `{ua_hash}`")
    lines.append(f"- anon_id: `{anon_id}`")

    # metaは長くなりすぎないように軽く整形
    if meta:
        meta_str = json.dumps(meta, ensure_ascii=False)
        if len(meta_str) > 400:
            meta_str = meta_str[:400] + "..."
        lines.append(f"- meta: `{meta_str}`")

    return "\n".join(lines)


def send_discord(text: str) -> None:
    if not DISCORD_WEBHOOK_URL:
        print("[WARN] DISCORD_WEBHOOK_URL is not set. Print only:\n" + text + "\n")
        return

    resp = requests.post(DISCORD_WEBHOOK_URL, json={"content": text,"allowed_mentions": {"parse": []},}, timeout=10)
    if resp.status_code >= 300:
        print(f"[ERROR] Discord webhook failed: {resp.status_code} {resp.text}")

def emit_event(event: str, rec: dict, meta: dict | None = None, severity: str = "WARN"):
    """
    runner側で検知したイベントをDiscordに通知する（アプリのログには書かない）。
    """
    ts = rec.get("ts")
    path = rec.get("path")
    ip_hash = rec.get("ip_hash")
    ua_hash = rec.get("ua_hash")
    anon_id = rec.get("anon_id")
    user = rec.get("user")

    payload = {
        "ts": ts,
        "event": event,
        "severity": severity,
        "user": user,
        "anon_id": anon_id,
        "path": path,
        "ip_hash": ip_hash,
        "ua_hash": ua_hash,
        "meta": meta or {},
    }

    msg = format_message(payload)
    print("[ALERT]\n" + msg + "\n")
    send_discord(msg)


def check_evasion(rec: dict):
    """
    同一fingerprint(ip_hash+ua_hash)から短時間でanon_idが変わる = Cookie削除/シークレット等の回避疑い
    """
    anon_id = rec.get("anon_id")
    ip_hash = rec.get("ip_hash")
    ua_hash = rec.get("ua_hash")
    event = rec.get("event", "")

    if not (anon_id and ip_hash and ua_hash):
        return

    fp = f"{ip_hash}:{ua_hash}"
    last_key = f"fp:last_anon:{fp}"
    changes_key = f"fp:changes:{fp}"
    cooldown_key = f"fp:evasion_cd:{fp}"

    last = r.get(last_key)

    # 初回は記録して終わり
    if not last:
        r.setex(last_key, 1800, anon_id)  # 30分
        return

    # 同じanonなら更新だけ
    if last == anon_id:
        r.expire(last_key, 1800)
        return

    # anonが変わった = 変化回数カウント
    n = r.incr(changes_key)
    r.expire(changes_key, 600)   # 10分
    r.setex(last_key, 1800, anon_id)

    # 通知スパム防止：同じfingerprintで一定時間に1回だけ通知
    if r.get(cooldown_key):
        return

    # 10分で2回以上変わったら「強めの疑い」
    if n >= 2:
        r.setex(cooldown_key, 120, "1")  # 2分クールダウン
        emit_event(
            "security.evasion_suspected",
            rec,
            meta={
                "fingerprint": fp,
                "prev_anon": last,
                "new_anon": anon_id,
                "changes_10min": n,
                "trigger_event": event,
                "hint": "Cookie削除/シークレット/ブラウザ変更等の可能性",
            },
            severity="WARN",
        )
    
    # risk加点(evasionは重めに+5)
    risk_key = f"risk:fp:{fp}"
    score = r.incrby(risk_key, 5)
    r.expire(risk_key, 3600)  # 1時間で自然減衰

    # 一定以上ならエスカレーション通知
    if score >= 8:
        emit_event(
            "security.risk_escalated",
            rec,
            meta={"fingerprint": fp, "risk_score": score, "reason": "evasion_suspected"},
            severity="ERROR",
        )


def follow_file(path: Path):
    """
    app.jsonl の追記を追う（tail -f 的なやつ）
    """
    # ファイルが出来るまで待つ
    while not path.exists():
        print("[INFO] waiting for log file...", path)
        time.sleep(1)

    with path.open("r", encoding="utf-8") as f:
        # 末尾から開始（最初は過去ログを流さない）
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            check_evasion(rec)

            event = rec.get("event", "")
            if should_notify(event):
                msg = format_message(rec)
                print("[ALERT]\n" + msg + "\n")
                send_discord(msg)

def main():
    print("[INFO] runner started. watching:", LOG_PATH)
    follow_file(LOG_PATH)

if __name__ == "__main__":
    main()
