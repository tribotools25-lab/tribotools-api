#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import io
import csv
import json
import hmac
import uuid
import time
import hashlib
import sqlite3
import threading
import typing as t
import requests

from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Body, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, Response

API_VERSION = "PYRATAS-1.0.0"

# =========================
# ENV
# =========================
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR / "licenses.db").resolve()

DB_PATH = os.getenv("LICENSE_DB", str(DEFAULT_DB))
ADMIN_TOKEN = (os.getenv("ADMIN_TOKEN") or "").strip()

TELEGRAM_BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
TELEGRAM_WEBHOOK_SECRET = (os.getenv("TELEGRAM_WEBHOOK_SECRET") or "").strip()

MP_ACCESS_TOKEN = (os.getenv("MP_ACCESS_TOKEN") or "").strip()
BASE_PUBLIC_URL = (os.getenv("BASE_PUBLIC_URL") or "").strip()

# =========================
# APP
# =========================
app = FastAPI(title="Pyratas API", version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

core = APIRouter()
admin = APIRouter(prefix="/admin", tags=["admin"])

# =========================
# DB (SQLite)
# =========================
_conn: sqlite3.Connection | None = None
_conn_lock = threading.Lock()

def connect_once() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        with _conn_lock:
            if _conn is None:
                conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                _conn = conn
    return _conn

def now_utc_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def init_db():
    conn = connect_once()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS license (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT UNIQUE,
            status TEXT DEFAULT 'active',
            max_devices INTEGER DEFAULT 1,
            notes TEXT,
            created_at TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS activation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT,
            device_id TEXT,
            token TEXT,
            fingerprint TEXT,
            activated_at TEXT,
            expires_at TEXT,
            UNIQUE(license_key_hash, device_id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            license_key_hash TEXT,
            device_id TEXT,
            event TEXT,
            meta TEXT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_license ON usage(license_key_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_device ON usage(device_id)")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS credit_wallet (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT UNIQUE,
            balance INTEGER NOT NULL DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS credit_tx (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT,
            change INTEGER,
            reason TEXT,
            meta TEXT,
            created_at TEXT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_credit_tx_lic ON credit_tx(license_key_hash)")

    # Tabela simples pra mapear pagamentos -> licença/telegram
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS mp_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id INTEGER UNIQUE,
            telegram_chat_id TEXT,
            service TEXT,
            license_key TEXT,
            status TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    conn.commit()

def ensure_wallet_for_license(lic_hash: str) -> None:
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT id FROM credit_wallet WHERE license_key_hash=?", (lic_hash,))
    row = cur.fetchone()
    if row:
        return
    now = now_utc_str()
    cur.execute(
        "INSERT INTO credit_wallet (license_key_hash, balance, created_at, updated_at) VALUES (?,?,?,?)",
        (lic_hash, 0, now, now),
    )
    conn.commit()

# =========================
# ADMIN AUTH
# =========================
admin_scheme = HTTPBearer(auto_error=False)

def require_admin(credentials: HTTPAuthorizationCredentials = Depends(admin_scheme)):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=500, detail="ADMIN_TOKEN não configurado no servidor.")
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Bearer token ausente.")
    token = credentials.credentials.strip()
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Token inválido.")
    return True

# =========================
# STARTUP
# =========================
@app.on_event("startup")
def _startup():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    init_db()

# =========================
# HOME / HEALTH
# =========================
@core.get("/")
def home():
    return {"status": "ok", "msg": "Pyratas API rodando", "version": API_VERSION}

@core.get("/healthz")
def healthz():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r["name"] for r in cur.fetchall()]
    return {"ok": True, "tables": tables, "db_path": str(DB_PATH)}

# =========================
# TELEGRAM BOT (PYRATAS)
# =========================

def tg_api(method: str, payload: dict):
    if not TELEGRAM_BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN não configurado.")
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}"
    return requests.post(url, json=payload, timeout=20).json()

def tg_send(chat_id: int, text: str, reply_markup: dict | None = None):
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return tg_api("sendMessage", payload)

def tg_answer_callback(callback_query_id: str, text: str = "", show_alert: bool = False):
    return tg_api("answerCallbackQuery", {
        "callback_query_id": callback_query_id,
        "text": text,
        "show_alert": show_alert
    })

# ====== COPY / MENU (EDITE AQUI) ======
PYRATAS_WELCOME = """🚀 <b>PYRATAS</b>

Bem-vindo. Aqui você compra e ativa as ferramentas oficiais da nossa stack.
✅ Infra estável • ✅ Automação real • ✅ Histórico de entrega

Escolha um produto:"""

PYRATAS_SUPPORT = """👤 Suporte: @suportebrisola
📌 Dúvidas? Me chama que a gente resolve em minutos."""

SERVICES = {
    "robo_meet": {
        "title": "Robô Audiência Google Meet",
        "price": 97.00,
        "credits": 1000,
        "days": 30,
        "max_devices": 1,
        "desc": "Abre várias janelas e entra na reunião automaticamente.",
    },
    # Você pode adicionar mais produtos aqui:
    # "robo_tiktok": {...}
}

def build_main_menu():
    buttons = []
    for k, v in SERVICES.items():
        buttons.append([{"text": f"✅ {v['title']} — R$ {v['price']:.2f}", "callback_data": f"buy:{k}"}])
    buttons.append([{"text": "📞 Falar com suporte", "callback_data": "support"}])
    return {"inline_keyboard": buttons}

def build_service_menu(service_key: str):
    s = SERVICES[service_key]
    buttons = [
        [{"text": "💠 Gerar PIX agora", "callback_data": f"pix:{service_key}"}],
        [{"text": "⬅️ Voltar", "callback_data": "back"}],
    ]
    return {"inline_keyboard": buttons}

def validate_tg_secret(request: Request):
    if not TELEGRAM_WEBHOOK_SECRET:
        return
    received = (request.headers.get("x-telegram-bot-api-secret-token") or "").strip()
    if not received or not hmac.compare_digest(received, TELEGRAM_WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Webhook secret inválido.")

@core.post("/webhooks/telegram")
async def telegram_webhook(update: dict = Body(...), request: Request = None):
    validate_tg_secret(request)

    # log simples
    try:
        conn = connect_once()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
            (now_utc_str(), "TELEGRAM", "WEBHOOK", "telegram_update", json.dumps({"update_id": update.get("update_id")}, ensure_ascii=False)),
        )
        conn.commit()
    except Exception:
        pass

    # mensagem normal
    msg = update.get("message") or update.get("edited_message")
    if msg and "text" in msg:
        chat_id = int((msg.get("chat") or {}).get("id"))
        text = (msg.get("text") or "").strip()

        if text.startswith("/start"):
            tg_send(chat_id, PYRATAS_WELCOME, build_main_menu())
            return {"ok": True}

        if text.startswith("/menu"):
            tg_send(chat_id, PYRATAS_WELCOME, build_main_menu())
            return {"ok": True}

        # fallback
        tg_send(chat_id, "Digite /start para ver o menu de produtos.")
        return {"ok": True}

    # callback (botões)
    cb = update.get("callback_query")
    if cb:
        cb_id = cb.get("id")
        data = (cb.get("data") or "").strip()
        chat_id = int((((cb.get("message") or {}).get("chat")) or {}).get("id"))

        if data == "support":
            tg_answer_callback(cb_id)
            tg_send(chat_id, PYRATAS_SUPPORT)
            return {"ok": True}

        if data == "back":
            tg_answer_callback(cb_id)
            tg_send(chat_id, PYRATAS_WELCOME, build_main_menu())
            return {"ok": True}

        if data.startswith("buy:"):
            service_key = data.split("buy:", 1)[1]
            if service_key not in SERVICES:
                tg_answer_callback(cb_id, "Produto inválido.", True)
                return {"ok": True}
            s = SERVICES[service_key]
            tg_answer_callback(cb_id)
            text = (
                f"🧩 <b>{s['title']}</b>\n\n"
                f"{s['desc']}\n\n"
                f"💰 <b>R$ {s['price']:.2f}</b> • ⏳ {s['days']} dias • 🎫 {s['credits']} créditos\n\n"
                f"Clique abaixo para gerar o PIX:"
            )
            tg_send(chat_id, text, build_service_menu(service_key))
            return {"ok": True}

        if data.startswith("pix:"):
            service_key = data.split("pix:", 1)[1]
            if service_key not in SERVICES:
                tg_answer_callback(cb_id, "Produto inválido.", True)
                return {"ok": True

                }
            tg_answer_callback(cb_id, "Gerando PIX…")

            # cria pedido MP e envia pro usuário
            try:
                order = create_mp_pix_for_chat(chat_id=chat_id, service_key=service_key)
            except Exception as e:
                tg_send(chat_id, f"⚠️ Não consegui gerar o PIX agora.\n\nErro: {str(e)}\n\nTente novamente em 1 minuto.")
                return {"ok": True}

            # manda instruções + link (ticket_url) e o “copia e cola”
            ticket_url = (((order.get("point_of_interaction") or {}).get("transaction_data") or {}).get("ticket_url")) or ""
            qr_code = (((order.get("point_of_interaction") or {}).get("transaction_data") or {}).get("qr_code")) or ""

            msg_txt = (
                "✅ <b>PIX gerado!</b>\n\n"
                "1) Abra seu banco e pague via QR / copia e cola.\n"
                "2) Assim que aprovar, eu libero automaticamente.\n\n"
                f"🔗 Link do QR (Mercado Pago): {ticket_url}\n\n"
                f"📋 <b>Copia e cola (PIX)</b>:\n<code>{qr_code}</code>\n\n"
                "Se der problema no seu banco, tente pagar pelo próprio Mercado Pago."
            )
            tg_send(chat_id, msg_txt)
            return {"ok": True}

        tg_answer_callback(cb_id)
        return {"ok": True}

    return {"ok": True}

# =========================
# MERCADO PAGO PIX
# =========================

def mp_headers(idem_key: str | None = None):
    if not MP_ACCESS_TOKEN:
        raise RuntimeError("MP_ACCESS_TOKEN não configurado.")
    h = {
        "Authorization": f"Bearer {MP_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }
    if idem_key:
        h["X-Idempotency-Key"] = idem_key
    return h

def create_mp_pix_for_chat(chat_id: int, service_key: str) -> dict:
    if not BASE_PUBLIC_URL:
        raise RuntimeError("BASE_PUBLIC_URL não configurado.")
    s = SERVICES[service_key]

    payload = {
        "transaction_amount": float(s["price"]),
        "description": f"[PYRATAS] {s['title']} - Licença",
        "payment_method_id": "pix",
        "payer": {"email": "cliente@pyratas.app"},  # você pode trocar depois pra coletar email
        "notification_url": f"{BASE_PUBLIC_URL}/webhooks/mercadopago",
        "external_reference": f"tg:{chat_id}|svc:{service_key}",
    }

    idem = str(uuid.uuid4())
    r = requests.post(
        "https://api.mercadopago.com/v1/payments",
        headers=mp_headers(idem),
        json=payload,
        timeout=30,
    )
    resp = r.json()
    resp["_http_status"] = r.status_code

    if r.status_code >= 400:
        raise RuntimeError(json.dumps(resp, ensure_ascii=False))

    # salva mapeamento (payment_id -> chat/service)
    payment_id = resp.get("id")
    if payment_id:
        conn = connect_once()
        cur = conn.cursor()
        now = now_utc_str()
        cur.execute(
            """
            INSERT OR IGNORE INTO mp_orders (payment_id, telegram_chat_id, service, license_key, status, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?)
            """,
            (int(payment_id), str(chat_id), service_key, "", "pending", now, now),
        )
        conn.commit()

    return resp

@core.post("/webhooks/mercadopago")
async def mercadopago_webhook(request: Request):
    if not MP_ACCESS_TOKEN:
        return {"status": "missing_mp_token"}

    body = await request.json()
    payment_id = (body.get("data") or {}).get("id") or body.get("id")
    if not payment_id:
        return {"status": "ignored"}

    # consulta pagamento real
    r = requests.get(
        f"https://api.mercadopago.com/v1/payments/{payment_id}",
        headers=mp_headers(),
        timeout=30,
    )
    pay = r.json()
    status = (pay.get("status") or "").lower()

    conn = connect_once()
    cur = conn.cursor()

    # busca chat_id e service
    cur.execute("SELECT telegram_chat_id, service FROM mp_orders WHERE payment_id=?", (int(payment_id),))
    row = cur.fetchone()
    chat_id = int(row["telegram_chat_id"]) if row else None
    service_key = row["service"] if row else None

    # atualiza status no DB
    cur.execute(
        "UPDATE mp_orders SET status=?, updated_at=? WHERE payment_id=?",
        (status, now_utc_str(), int(payment_id)),
    )
    conn.commit()

    if status != "approved":
        return {"status": status, "payment_id": payment_id}

    # aprovado: gera licença + créditos e manda mensagem
    if chat_id and service_key in SERVICES:
        s = SERVICES[service_key]

        # gera chave “human-readable”
        new_license_key = f"PYR-{service_key.upper()}-{uuid.uuid4().hex[:8].upper()}"

        # cria licença no DB
        lic_hash = sha256(new_license_key)
        now = now_utc_str()

        try:
            cur.execute(
                "INSERT INTO license (license_key_hash, status, max_devices, notes, created_at) VALUES (?,?,?,?,?)",
                (lic_hash, "active", int(s["max_devices"]), f"tg:{chat_id} svc:{service_key} pay:{payment_id}", now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass

        ensure_wallet_for_license(lic_hash)

        # adiciona créditos
        cur.execute(
            "UPDATE credit_wallet SET balance = balance + ?, updated_at=? WHERE license_key_hash=?",
            (int(s["credits"]), now, lic_hash),
        )
        cur.execute(
            "INSERT INTO credit_tx (license_key_hash, change, reason, meta, created_at) VALUES (?,?,?,?,?)",
            (lic_hash, int(s["credits"]), "purchase", json.dumps({"payment_id": payment_id, "service": service_key}, ensure_ascii=False), now),
        )
        conn.commit()

        # salva licença na ordem
        cur.execute(
            "UPDATE mp_orders SET license_key=?, updated_at=? WHERE payment_id=?",
            (new_license_key, now, int(payment_id)),
        )
        conn.commit()

        msg = (
            "✅ <b>Pagamento aprovado!</b>\n\n"
            f"🧾 Produto: <b>{s['title']}</b>\n"
            f"🎫 Créditos liberados: <b>{s['credits']}</b>\n\n"
            "🔑 <b>Sua licença:</b>\n"
            f"<code>{new_license_key}</code>\n\n"
            "📌 Próximo passo:\n"
            "Abra o robô no seu PC, cole a licença e ative.\n\n"
            f"{PYRATAS_SUPPORT}"
        )
        tg_send(chat_id, msg)

    return {"status": "paid_confirmed", "payment_id": payment_id}

# =========================
# LICENÇA (CLIENTE)
# =========================

@core.post("/activate")
def activate(data: dict = Body(...)):
    license_key = (data.get("license_key") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    fingerprint = data.get("fingerprint", {})

    if not license_key or not device_id:
        raise HTTPException(400, "Campos obrigatórios: license_key, device_id")

    lic_hash = sha256(license_key)
    conn = connect_once()
    cur = conn.cursor()

    cur.execute("SELECT status, max_devices FROM license WHERE license_key_hash=?", (lic_hash,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Licença inválida.")
    if (row["status"] or "") != "active":
        raise HTTPException(403, "Licença inativa.")
    max_devices = row["max_devices"] or 1

    cur.execute("SELECT COUNT(*) AS c FROM activation WHERE license_key_hash=?", (lic_hash,))
    qtd = cur.fetchone()["c"]

    if qtd >= max_devices:
        cur.execute("SELECT 1 FROM activation WHERE license_key_hash=? AND device_id=?", (lic_hash, device_id))
        if cur.fetchone() is None:
            raise HTTPException(403, "Licença já está em uso em outro computador.")

    token = str(uuid.uuid4())
    now = now_utc_str()
    expires_at = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

    cur.execute(
        """
        INSERT OR REPLACE INTO activation
            (license_key_hash, device_id, token, fingerprint, activated_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (lic_hash, device_id, token, json.dumps(fingerprint, ensure_ascii=False), now, expires_at),
    )
    conn.commit()

    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
        (now, lic_hash, device_id, "activate", json.dumps({"fingerprint": fingerprint}, ensure_ascii=False)),
    )
    conn.commit()

    return {"status": "ok", "token": token, "expires_at": expires_at, "max_devices": max_devices}

@core.post("/validate")
def validate(data: dict = Body(...)):
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(400, "Token e device_id são obrigatórios.")

    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT a.license_key_hash, a.expires_at, l.status AS lic_status
        FROM activation a
        LEFT JOIN license l ON l.license_key_hash = a.license_key_hash
        WHERE a.token = ? AND a.device_id = ?
        """,
        (token, device_id),
    )
    row = cur.fetchone()
    if not row:
        return {"valid": False, "reason": "Token não encontrado."}

    lic_hash = row["license_key_hash"]
    lic_status = (row["lic_status"] or "active").lower()
    exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")

    if lic_status != "active":
        valid = False
        reason = "Licença desativada pelo administrador."
        event_name = "validate_license_inactive"
    elif datetime.utcnow() > exp:
        valid = False
        reason = "Token expirado."
        event_name = "validate_expired"
    else:
        valid = True
        reason = "Token válido."
        event_name = "validate_ok"

    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
        (now_utc_str(), lic_hash, device_id, event_name, json.dumps({"reason": reason}, ensure_ascii=False)),
    )
    conn.commit()

    return {"valid": valid, "reason": reason}

@core.get("/credits/balance")
def credits_balance(token: str = Query(...), device_id: str = Query(...)):
    conn = connect_once()
    cur = conn.cursor()

    token = token.strip()
    device_id = device_id.strip()

    cur.execute("SELECT license_key_hash, expires_at FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Ativação não encontrada para este token/device_id.")

    exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > exp:
        raise HTTPException(403, "Token expirado.")

    lic_hash = row["license_key_hash"]
    ensure_wallet_for_license(lic_hash)

    cur.execute("SELECT balance FROM credit_wallet WHERE license_key_hash=?", (lic_hash,))
    row2 = cur.fetchone()
    balance = row2["balance"] if row2 else 0
    return {"license_key_hash": lic_hash, "balance": balance}

@core.post("/credits/consume")
def credits_consume(data: dict = Body(...)):
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    amount = int(data.get("amount", 0))
    if not token or not device_id:
        raise HTTPException(400, "token e device_id são obrigatórios.")
    if amount <= 0:
        raise HTTPException(400, "amount deve ser > 0")

    reason = (data.get("reason") or "").strip() or "consume"
    meta = json.dumps(data.get("meta", {}), ensure_ascii=False)

    conn = connect_once()
    cur = conn.cursor()

    cur.execute("SELECT license_key_hash, expires_at FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Ativação não encontrada para este token/device_id.")

    exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > exp:
        raise HTTPException(403, "Token expirado.")

    lic_hash = row["license_key_hash"]
    ensure_wallet_for_license(lic_hash)

    cur.execute("SELECT balance FROM credit_wallet WHERE license_key_hash=?", (lic_hash,))
    row2 = cur.fetchone()
    balance = row2["balance"] if row2 else 0

    if balance < amount:
        raise HTTPException(402, f"Créditos insuficientes. Saldo atual: {balance}, necessário: {amount}")

    now = now_utc_str()
    cur.execute("UPDATE credit_wallet SET balance = balance - ?, updated_at=? WHERE license_key_hash=?", (amount, now, lic_hash))
    cur.execute("INSERT INTO credit_tx (license_key_hash, change, reason, meta, created_at) VALUES (?,?,?,?,?)", (lic_hash, -amount, reason, meta, now))
    conn.commit()

    cur.execute("SELECT balance FROM credit_wallet WHERE license_key_hash=?", (lic_hash,))
    new_balance = cur.fetchone()["balance"]
    return {"status": "ok", "license_key_hash": lic_hash, "debited": amount, "balance": new_balance}

@core.get("/stats")
def stats():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM license")
    total_licenses = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM activation WHERE datetime(expires_at) > datetime('now')")
    active_activations = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(DISTINCT device_id) AS c FROM activation WHERE datetime(expires_at) > datetime('now')")
    unique_devices = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM usage WHERE datetime(ts) > datetime('now','-1 day')")
    usage_24h = cur.fetchone()["c"]
    return {
        "total_licenses": total_licenses,
        "active_activations": active_activations,
        "unique_devices": unique_devices,
        "usage_24h": usage_24h,
    }

# =========================
# ADMIN (Painel / APIs)
# =========================

@admin.post("/licenses", dependencies=[Depends(require_admin)])
def create_license(body: dict = Body(...)):
    lk = (body.get("license_key") or "").strip()
    if not lk:
        raise HTTPException(400, "license_key obrigatório")
    max_dev = int(body.get("max_devices", 1) or 1)
    notes = body.get("notes", "")
    lic_hash = sha256(lk)

    conn = connect_once()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO license (license_key_hash, status, max_devices, notes, created_at) VALUES (?,?,?,?,?)",
            (lic_hash, "active", max_dev, notes, now_utc_str()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Licença já existe")

    ensure_wallet_for_license(lic_hash)
    return {"status": "ok", "license_key_hash": lic_hash, "max_devices": max_dev}

@admin.get("/usage-summary", dependencies=[Depends(require_admin)])
def usage_summary():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            l.license_key_hash,
            l.status,
            l.max_devices,
            COALESCE(l.notes, '') AS notes,
            COALESCE(cw.balance, 0) AS credits_balance,
            COUNT(u.id) AS total_events,
            SUM(CASE WHEN u.event='run_start' THEN 1 ELSE 0 END) AS runs,
            SUM(CASE WHEN u.event='activate' THEN 1 ELSE 0 END)  AS activations,
            SUM(CASE WHEN u.event='validate_ok' THEN 1 ELSE 0 END) AS validations,
            COUNT(DISTINCT CASE WHEN u.device_id IS NOT NULL THEN u.device_id END) AS devices
        FROM license l
        LEFT JOIN usage u ON u.license_key_hash = l.license_key_hash
        LEFT JOIN credit_wallet cw ON cw.license_key_hash = l.license_key_hash
        GROUP BY l.license_key_hash, l.status, l.max_devices, l.notes, cw.balance
        ORDER BY runs DESC, activations DESC, l.license_key_hash ASC
        """
    )
    rows = [dict(r) for r in cur.fetchall()]
    return {"rows": rows, "count": len(rows)}

@admin.get("/usage-csv", dependencies=[Depends(require_admin)])
def usage_csv():
    summary = usage_summary()
    rows: list[dict] = summary["rows"]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["license_key_hash","status","max_devices","devices","runs","activations","validations","total_events","credits_balance","notes"]
    )
    for r in rows:
        writer.writerow([
            r["license_key_hash"],
            r["status"],
            r["max_devices"],
            r.get("devices", 0),
            r.get("runs", 0),
            r.get("activations", 0),
            r.get("validations", 0),
            r.get("total_events", 0),
            r.get("credits_balance", 0),
            (r.get("notes","") or "").replace("\n"," ").replace("\r"," "),
        ])

    csv_bytes = output.getvalue().encode("utf-8-sig")
    headers = {"Content-Disposition": 'attachment; filename="pyratas_usage_summary.csv"'}
    return Response(content=csv_bytes, media_type="text/csv", headers=headers)

# =========================
# /panel (HTML)
# =========================
@core.get("/panel", response_class=HTMLResponse)
def panel():
    # (Seu painel — mantido)
    html = """
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
      <meta charset="UTF-8" />
      <title>Pyratas - Painel</title>
      <style>
        body { margin:0; font-family:system-ui; background:#050816; color:#f9fafb; }
        header { padding:16px 24px; background:#020617; border-bottom:1px solid #1f2933; display:flex; justify-content:space-between; align-items:center; }
        header h1 { font-size:20px; margin:0; }
        .badge { font-size:11px; padding:4px 8px; border-radius:999px; background:#111827; border:1px solid #4b5563; }
        main { padding:20px 24px 40px 24px; max-width:1200px; margin:0 auto; }
        .token-box { display:flex; gap:8px; align-items:center; margin-bottom:20px; flex-wrap:wrap; }
        .token-box label { font-size:13px; color:#9ca3af; }
        .token-box input { background:#020617; border-radius:999px; border:1px solid #4b5563; padding:6px 12px; color:#e5e7eb; min-width:260px; outline:none; }
        .token-box button { border-radius:999px; border:none; padding:6px 14px; font-size:13px; cursor:pointer; background:#22c55e; color:#022c22; font-weight:600; }
        .token-box button.secondary { background:#111827; color:#e5e7eb; border:1px solid #374151; }
        .token-status { font-size:12px; color:#9ca3af; }
        .cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-bottom:24px; }
        .card { padding:14px 16px; border-radius:16px; background:radial-gradient(circle at top left, #1f2933, #020617); border:1px solid #1f2937; }
        .card h3 { margin:0 0 4px 0; font-size:13px; color:#9ca3af; }
        .card .value { font-size:22px; font-weight:600; }
        .section { margin-top:20px; margin-bottom:4px; display:flex; justify-content:space-between; align-items:center; gap:8px; }
        .section-title { font-size:14px; color:#e5e7eb; }
        .section-sub { font-size:12px; color:#6b7280; }
        .pill { display:inline-flex; align-items:center; gap:4px; padding:2px 8px; border-radius:999px; background:#111827; font-size:11px; color:#9ca3af; }
        .dot { width:6px; height:6px; border-radius:999px; background:#22c55e; }
        .table-wrapper { border-radius:16px; border:1px solid #1f2937; overflow:hidden; background:#020617; max-height:480px; overflow-y:auto; }
        table { width:100%; border-collapse:collapse; margin-top:8px; font-size:13px; }
        th, td { padding:8px 10px; border-bottom:1px solid #111827; }
        th { text-align:left; background:#020617; position:sticky; top:0; z-index:1; }
      </style>
    </head>
    <body>
      <header>
        <h1>Pyratas — Painel</h1>
        <span class="badge">API v<span id="apiVersion">-</span></span>
      </header>
      <main>
        <div class="token-box">
          <label for="tokenInput">Admin Token:</label>
          <input id="tokenInput" type="password" placeholder="cole o ADMIN_TOKEN" />
          <button id="saveTokenBtn">Salvar</button>
          <button id="loadBtn" class="secondary">Carregar</button>
          <div class="token-status" id="tokenStatus"></div>
        </div>

        <div class="cards">
          <div class="card"><h3>Total de licenças</h3><div class="value" id="cardTotalLic">-</div></div>
          <div class="card"><h3>Ativações ativas</h3><div class="value" id="cardActiveAct">-</div></div>
          <div class="card"><h3>Dispositivos únicos</h3><div class="value" id="cardDevices">-</div></div>
          <div class="card"><h3>Eventos últimas 24h</h3><div class="value" id="cardUsage24h">-</div></div>
        </div>

        <div class="section">
          <div><div class="section-title">Uso por licença</div><div class="section-sub">Requer ADMIN_TOKEN</div></div>
          <span class="pill"><span class="dot"></span> atualizado</span>
        </div>

        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>license_key_hash</th><th>status</th><th>max_devices</th><th>devices</th>
                <th>runs</th><th>activations</th><th>validations</th><th>total_events</th><th>credits</th><th>notes</th>
              </tr>
            </thead>
            <tbody id="usageBody"><tr><td colspan="10">Clique em Carregar</td></tr></tbody>
          </table>
        </div>
      </main>

      <script>
        const tokenInput = document.getElementById("tokenInput");
        const saveTokenBtn = document.getElementById("saveTokenBtn");
        const loadBtn = document.getElementById("loadBtn");
        const tokenStatus = document.getElementById("tokenStatus");
        const usageBody = document.getElementById("usageBody");
        const apiVersionSpan = document.getElementById("apiVersion");

        const cardTotalLic = document.getElementById("cardTotalLic");
        const cardActiveAct = document.getElementById("cardActiveAct");
        const cardDevices   = document.getElementById("cardDevices");
        const cardUsage24h  = document.getElementById("cardUsage24h");

        function getToken(){ return window.localStorage.getItem("pyr_admin_token") || ""; }
        function setToken(tok){ if(tok) window.localStorage.setItem("pyr_admin_token", tok); else window.localStorage.removeItem("pyr_admin_token"); }
        function updateTokenStatus(){
          const t = getToken();
          tokenStatus.textContent = t ? "Token salvo no navegador." : "Nenhum token salvo.";
        }

        tokenInput.value = getToken();
        updateTokenStatus();

        saveTokenBtn.addEventListener("click", () => {
          setToken(tokenInput.value.trim());
          updateTokenStatus();
        });

        async function fetchJSON(url, opts={}){
          const token = getToken();
          const headers = Object.assign({ "Accept":"application/json" }, opts.headers || {});
          if(token) headers["Authorization"] = "Bearer " + token;
          const resp = await fetch(url, { method: opts.method || "GET", headers, body: opts.body });
          if(!resp.ok) throw new Error(resp.status + " " + await resp.text());
          return resp.json();
        }

        async function carregar(){
          const v = await fetchJSON("/");
          apiVersionSpan.textContent = v.version || "-";

          const s = await fetchJSON("/stats");
          cardTotalLic.textContent = s.total_licenses ?? "-";
          cardActiveAct.textContent = s.active_activations ?? "-";
          cardDevices.textContent = s.unique_devices ?? "-";
          cardUsage24h.textContent = s.usage_24h ?? "-";

          const u = await fetchJSON("/api/admin/usage-summary");
          const rows = u.rows || [];
          usageBody.innerHTML = "";
          if(!rows.length){
            usageBody.innerHTML = "<tr><td colspan='10'>Sem dados</td></tr>";
            return;
          }
          for(const r of rows){
            const tr = document.createElement("tr");
            tr.innerHTML = `
              <td>${r.license_key_hash}</td>
              <td>${r.status}</td>
              <td>${r.max_devices}</td>
              <td>${r.devices}</td>
              <td>${r.runs}</td>
              <td>${r.activations}</td>
              <td>${r.validations}</td>
              <td>${r.total_events}</td>
              <td>${r.credits_balance}</td>
              <td>${(r.notes||"").replace(/</g,"&lt;")}</td>
            `;
            usageBody.appendChild(tr);
          }
        }

        loadBtn.addEventListener("click", carregar);
      </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

# =========================
# ROUTERS
# =========================
app.include_router(core)
app.include_router(admin, prefix="/api")
