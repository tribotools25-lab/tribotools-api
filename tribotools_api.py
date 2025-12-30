#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TriboTools API (Licenças + Créditos) + Bot Telegram + Mercado Pago PIX

ENV VARS (Render):
- LICENSE_DB
- ADMIN_TOKEN
- BASE_PUBLIC_URL              (ex: https://tribotools-api.onrender.com)
- MP_ACCESS_TOKEN
- TELEGRAM_BOT_TOKEN
- TELEGRAM_WEBHOOK_SECRET

Fluxo Telegram:
- /start -> mostra menu
- seleciona produto -> pede e-mail
- envia e-mail -> cria PIX (MercadoPago) -> manda QR + copia/cola + link
- webhook MercadoPago aprovado -> gera licença + créditos -> entrega no Telegram
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import threading
import uuid
import io
import csv
import re
import requests

from fastapi import FastAPI, HTTPException, Depends, Body, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, Response

import hmac

API_VERSION = "TT-1.2.0"

# ================== ENV ==================
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR / "licenses.db").resolve()

DB_PATH = os.getenv("LICENSE_DB", str(DEFAULT_DB)).strip()
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()

BASE_PUBLIC_URL = os.getenv("BASE_PUBLIC_URL", "").strip().rstrip("/")
MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN", "").strip()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()

# ================== COPY / PRODUTOS ==================
# Edite aqui a copy. Deixa em HTML porque vamos mandar com parse_mode=HTML.
SALES = {
    "robo_meet": {
        "title": "Robô Audiência Google Meet",
        "price": 97.00,
        "currency": "BRL",
        "credits": 1000,
        "days": 30,
        "max_devices": 1,
        "short": (
            "<b>Robô Audiência Google Meet</b>\n"
            "• Abre múltiplos perfis e entra na sala automaticamente\n"
            "• Ideal pra prova social / eventos / lançamentos\n"
            "• Licença por máquina + <b>1000 créditos</b>\n"
        )
    },
    # Você pode ir adicionando:
    # "robo_tiktok": {...},
    # "disparo_agenda": {...},
}

WELCOME_COPY = (
    "🚀 <b>Pyratas / TriboTools</b>\n\n"
    "Aqui você compra e ativa ferramentas oficiais da nossa stack.\n"
    "✅ Infra estável • ✅ Automação real • ✅ Histórico de entrega\n\n"
    "Escolha o produto abaixo pra continuar:"
)

ASK_EMAIL_COPY = (
    "Perfeito. Agora me manda <b>seu e-mail</b> (o mesmo do pagamento).\n"
    "Exemplo: nome@dominio.com"
)

AFTER_PIX_COPY = (
    "✅ Pagamento PIX criado.\n\n"
    "1) Escaneie o QR no seu banco ou copie o código\n"
    "2) Assim que confirmar, eu libero sua licença automaticamente.\n"
)

DELIVERY_COPY = (
    "🎉 <b>Pagamento aprovado!</b>\n\n"
    "Aqui está sua licença e instruções de ativação:\n\n"
    "<b>Chave:</b> <code>{license_key}</code>\n"
    "<b>Validade:</b> {days} dias\n"
    "<b>Créditos:</b> {credits}\n\n"
    "Se quiser trocar de máquina, me chama aqui que a gente resolve."
)

# ================== DB ==================
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

    cur.execute("""
        CREATE TABLE IF NOT EXISTS license (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT UNIQUE,
            status TEXT DEFAULT 'active',
            max_devices INTEGER DEFAULT 1,
            notes TEXT,
            created_at TEXT
        )
    """)

    cur.execute("""
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
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            license_key_hash TEXT,
            device_id TEXT,
            event TEXT,
            meta TEXT
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_license ON usage(license_key_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_device ON usage(device_id)")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS credit_wallet (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT UNIQUE,
            balance INTEGER NOT NULL DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS credit_tx (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT,
            change INTEGER,
            reason TEXT,
            meta TEXT,
            created_at TEXT
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_credit_tx_lic ON credit_tx(license_key_hash)")

    # Estado do Telegram (pra saber se o usuário tá “esperando email” etc.)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tg_state (
            telegram_id TEXT PRIMARY KEY,
            state TEXT,
            service TEXT,
            updated_at TEXT
        )
    """)

    # Pedidos
    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id TEXT,
            service TEXT,
            payer_email TEXT,
            mp_payment_id TEXT,
            mp_status TEXT,
            license_key TEXT,
            created_at TEXT,
            updated_at TEXT,
            UNIQUE(mp_payment_id)
        )
    """)

    conn.commit()

def ensure_wallet_for_license(lic_hash: str) -> None:
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT id FROM credit_wallet WHERE license_key_hash=?", (lic_hash,))
    if cur.fetchone():
        return
    now = now_utc_str()
    cur.execute(
        "INSERT INTO credit_wallet (license_key_hash, balance, created_at, updated_at) VALUES (?,?,?,?)",
        (lic_hash, 0, now, now),
    )
    conn.commit()

# ================== ADMIN AUTH ==================
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

# ================== APP ==================
app = FastAPI(title="TriboTools API", version=API_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

core = APIRouter()
admin = APIRouter(prefix="/admin", tags=["admin"])

@app.on_event("startup")
def _startup():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    init_db()

# ================== TELEGRAM HELPERS ==================
def tg_api(method: str) -> str:
    return f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}"

def tg_send(chat_id: str | int, text: str, reply_markup: dict | None = None):
    if not TELEGRAM_BOT_TOKEN:
        return
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        requests.post(tg_api("sendMessage"), json=payload, timeout=20)
    except Exception:
        pass

def tg_answer_callback(callback_query_id: str, text: str = ""):
    if not TELEGRAM_BOT_TOKEN:
        return
    payload = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = text
    try:
        requests.post(tg_api("answerCallbackQuery"), json=payload, timeout=20)
    except Exception:
        pass

def tg_menu_keyboard():
    buttons = []
    for k, s in SALES.items():
        buttons.append([{"text": f"🛒 {s['title']}", "callback_data": f"buy:{k}"}])
    return {"inline_keyboard": buttons}

def set_tg_state(telegram_id: str, state: str, service: str | None = None):
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO tg_state (telegram_id, state, service, updated_at) VALUES (?,?,?,?) "
        "ON CONFLICT(telegram_id) DO UPDATE SET state=excluded.state, service=excluded.service, updated_at=excluded.updated_at",
        (telegram_id, state, service or "", now_utc_str()),
    )
    conn.commit()

def get_tg_state(telegram_id: str) -> dict:
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT telegram_id, state, service FROM tg_state WHERE telegram_id=?", (telegram_id,))
    row = cur.fetchone()
    if not row:
        return {"state": "", "service": ""}
    return {"state": row["state"] or "", "service": row["service"] or ""}

def clear_tg_state(telegram_id: str):
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("DELETE FROM tg_state WHERE telegram_id=?", (telegram_id,))
    conn.commit()

def is_email(s: str) -> bool:
    s = (s or "").strip()
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", s))

# ================== MERCADO PAGO ==================
def mp_create_pix(service: str, telegram_id: str, payer_email: str):
    if not MP_ACCESS_TOKEN or not BASE_PUBLIC_URL:
        raise HTTPException(500, "MP_ACCESS_TOKEN ou BASE_PUBLIC_URL não configurado.")

    if service not in SALES:
        raise HTTPException(400, "Serviço inválido.")

    s = SALES[service]
    payload = {
        "transaction_amount": float(s["price"]),
        "description": f"[BOTv2] Licença {service} - TriboTools",
        "payment_method_id": "pix",
        "payer": {"email": payer_email},
        "notification_url": f"{BASE_PUBLIC_URL}/webhooks/mercadopago",
        "external_reference": f"tg:{telegram_id}|svc:{service}",
    }
    idem_key = str(uuid.uuid4())

    r = requests.post(
        "https://api.mercadopago.com/v1/payments",
        headers={
            "Authorization": f"Bearer {MP_ACCESS_TOKEN}",
            "Content-Type": "application/json",
            "X-Idempotency-Key": idem_key,
        },
        json=payload,
        timeout=30,
    )
    data = r.json()
    data["_debug_idem_key"] = idem_key
    data["_http_status"] = r.status_code
    if r.status_code >= 400:
        raise HTTPException(r.status_code, data)
    return data

def mp_get_payment(payment_id: str):
    r = requests.get(
        f"https://api.mercadopago.com/v1/payments/{payment_id}",
        headers={"Authorization": f"Bearer {MP_ACCESS_TOKEN}"},
        timeout=30,
    )
    return r.status_code, r.json()

def generate_license_key(prefix="TT"):
    # chave amigável pro cliente (não só hash)
    return f"{prefix}-{uuid.uuid4().hex[:6].upper()}-{uuid.uuid4().hex[:6].upper()}"

def upsert_license_and_credits(license_key: str, max_devices: int, credits: int, notes: str = ""):
    lic_hash = sha256(license_key)
    conn = connect_once()
    cur = conn.cursor()

    # cria licença se não existir
    cur.execute("SELECT id FROM license WHERE license_key_hash=?", (lic_hash,))
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO license (license_key_hash, status, max_devices, notes, created_at) VALUES (?,?,?,?,?)",
            (lic_hash, "active", int(max_devices or 1), notes, now_utc_str()),
        )
        conn.commit()

    ensure_wallet_for_license(lic_hash)

    # adiciona créditos
    now = now_utc_str()
    cur.execute(
        "UPDATE credit_wallet SET balance = balance + ?, updated_at=? WHERE license_key_hash=?",
        (int(credits or 0), now, lic_hash),
    )
    cur.execute(
        "INSERT INTO credit_tx (license_key_hash, change, reason, meta, created_at) VALUES (?,?,?,?,?)",
        (lic_hash, int(credits or 0), "purchase", json.dumps({"license_key": license_key}), now),
    )
    conn.commit()

# ================== ROTAS CORE ==================
@core.get("/")
def home():
    return {"status": "ok", "msg": "TriboTools API rodando", "version": API_VERSION}

@core.get("/healthz")
def healthz():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r["name"] for r in cur.fetchall()]
    return {"ok": True, "tables": tables, "db_path": str(DB_PATH)}

@core.post("/webhooks/telegram")
async def telegram_webhook(update: dict = Body(...), request: Request = None):
    # valida secret do Telegram (você já setou no setWebhook)
    if TELEGRAM_WEBHOOK_SECRET:
        received = (request.headers.get("x-telegram-bot-api-secret-token") or "").strip()
        if not received or not hmac.compare_digest(received, TELEGRAM_WEBHOOK_SECRET):
            raise HTTPException(status_code=401, detail="Webhook secret inválido.")

    # log mínimo
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
        (now_utc_str(), "TELEGRAM", "WEBHOOK", "telegram_update",
         json.dumps({"update_id": update.get("update_id")}, ensure_ascii=False)),
    )
    conn.commit()

    # --- mensagem normal ---
    message = update.get("message") or update.get("edited_message")
    if message and message.get("chat"):
        chat_id = message["chat"]["id"]
        text = (message.get("text") or "").strip()
        telegram_id = str(chat_id)

        # /start
        if text.startswith("/start"):
            clear_tg_state(telegram_id)
            tg_send(chat_id, WELCOME_COPY, reply_markup=tg_menu_keyboard())
            return {"ok": True}

        # se está aguardando e-mail:
        st = get_tg_state(telegram_id)
        if st.get("state") == "awaiting_email":
            if not is_email(text):
                tg_send(chat_id, "⚠️ Esse e-mail parece inválido. Me manda no formato <b>nome@dominio.com</b>.")
                return {"ok": True}

            service = st.get("service")
            if service not in SALES:
                clear_tg_state(telegram_id)
                tg_send(chat_id, "⚠️ Serviço inválido. Use /start e escolha de novo.")
                return {"ok": True}

            # cria PIX
            pay = mp_create_pix(service=service, telegram_id=telegram_id, payer_email=text)
            payment_id = str(pay.get("id"))

            # salva pedido
            cur.execute(
                "INSERT INTO orders (telegram_id, service, payer_email, mp_payment_id, mp_status, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                (telegram_id, service, text, payment_id, pay.get("status") or "pending", now_utc_str(), now_utc_str()),
            )
            conn.commit()

            poi = (pay.get("point_of_interaction") or {}).get("transaction_data") or {}
            qr = poi.get("qr_code")
            ticket_url = poi.get("ticket_url")

            msg = AFTER_PIX_COPY
            if ticket_url:
                msg += f"\n\n🔗 <b>Link do pagamento:</b>\n{ticket_url}"
            if qr:
                msg += f"\n\n<b>PIX Copia e Cola:</b>\n<code>{qr}</code>"

            tg_send(chat_id, msg)
            clear_tg_state(telegram_id)
            return {"ok": True}

        # fallback
        tg_send(chat_id, "Digite /start para ver os produtos.")
        return {"ok": True}

    # --- callback (botões) ---
    cb = update.get("callback_query")
    if cb:
        cb_id = cb.get("id")
        chat = (cb.get("message") or {}).get("chat") or {}
        chat_id = chat.get("id")
        telegram_id = str(chat_id)
        data = (cb.get("data") or "").strip()

        if data.startswith("buy:"):
            service = data.split("buy:", 1)[1].strip()
            if service not in SALES:
                tg_answer_callback(cb_id, "Serviço inválido.")
                return {"ok": True}

            tg_answer_callback(cb_id, "Certo!")
            tg_send(chat_id, SALES[service]["short"])
            tg_send(chat_id, ASK_EMAIL_COPY)
            set_tg_state(telegram_id, "awaiting_email", service=service)
            return {"ok": True}

        tg_answer_callback(cb_id, "Ok.")
        return {"ok": True}

    return {"ok": True}

# ================== LICENÇA / CRÉDITOS (mantive seu core) ==================
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

    cur.execute("""
        INSERT OR REPLACE INTO activation
            (license_key_hash, device_id, token, fingerprint, activated_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (lic_hash, device_id, token, json.dumps(fingerprint, ensure_ascii=False), now, expires_at))
    conn.commit()

    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
        (now, lic_hash, device_id, "activate",
         json.dumps({"fingerprint": fingerprint}, ensure_ascii=False)),
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
    cur.execute("""
        SELECT a.license_key_hash, a.expires_at, l.status AS lic_status
        FROM activation a
        LEFT JOIN license l ON l.license_key_hash = a.license_key_hash
        WHERE a.token = ? AND a.device_id = ?
    """, (token, device_id))
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

    cur.execute("SELECT license_key_hash FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Ativação não encontrada para este token/device_id.")

    lic_hash = row["license_key_hash"]
    ensure_wallet_for_license(lic_hash)

    cur.execute("SELECT balance FROM credit_wallet WHERE license_key_hash=?", (lic_hash,))
    row2 = cur.fetchone()
    balance = row2["balance"] if row2 else 0

    if balance < amount:
        raise HTTPException(402, f"Créditos insuficientes. Saldo atual: {balance}, necessário: {amount}")

    now = now_utc_str()
    cur.execute("UPDATE credit_wallet SET balance = balance - ?, updated_at=? WHERE license_key_hash=?",
                (amount, now, lic_hash))
    cur.execute("INSERT INTO credit_tx (license_key_hash, change, reason, meta, created_at) VALUES (?,?,?,?,?)",
                (lic_hash, -amount, reason, meta, now))
    conn.commit()

    cur.execute("SELECT balance FROM credit_wallet WHERE license_key_hash=?", (lic_hash,))
    new_balance = (cur.fetchone() or {}).get("balance", 0)

    return {"status": "ok", "license_key_hash": lic_hash, "debited": amount, "balance": new_balance}

# ================== MERCADO PAGO WEBHOOK ==================
@core.post("/webhooks/mercadopago")
async def mercadopago_webhook(request: Request):
    if not MP_ACCESS_TOKEN:
        return {"status": "missing_mp_token"}

    body = await request.json()

    # MercadoPago costuma mandar { "data": {"id": ...} } (como você mostrou)
    payment_id = (body.get("data") or {}).get("id")
    if not payment_id:
        return {"status": "ignored"}

    code, payment = mp_get_payment(str(payment_id))
    if code >= 400:
        return {"status": "mp_error", "http": code, "payment_id": payment_id, "mp": payment}

    status = payment.get("status") or ""
    ext_ref = payment.get("external_reference") or ""

    # atualiza pedido
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "UPDATE orders SET mp_status=?, updated_at=? WHERE mp_payment_id=?",
        (status, now_utc_str(), str(payment_id)),
    )
    conn.commit()

    if status != "approved":
        return {"status": status, "payment_id": payment_id}

    # extrai tg e svc
    # ext_ref = "tg:123|svc:robo_meet"
    tg_id = ""
    svc = ""
    try:
        parts = ext_ref.split("|")
        for p in parts:
            if p.startswith("tg:"):
                tg_id = p.split("tg:", 1)[1]
            if p.startswith("svc:"):
                svc = p.split("svc:", 1)[1]
    except Exception:
        pass

    if not tg_id or svc not in SALES:
        return {"status": "approved_but_missing_ref", "payment_id": payment_id, "external_reference": ext_ref}

    # já entregou?
    cur.execute("SELECT license_key FROM orders WHERE mp_payment_id=?", (str(payment_id),))
    row = cur.fetchone()
    if row and row["license_key"]:
        return {"status": "already_delivered", "payment_id": payment_id}

    # gera licença e aplica créditos
    s = SALES[svc]
    license_key = generate_license_key(prefix="TT")
    upsert_license_and_credits(
        license_key=license_key,
        max_devices=s.get("max_devices", 1),
        credits=s.get("credits", 0),
        notes=f"Order MP:{payment_id} tg:{tg_id} svc:{svc}",
    )

    cur.execute(
        "UPDATE orders SET license_key=?, updated_at=? WHERE mp_payment_id=?",
        (license_key, now_utc_str(), str(payment_id)),
    )
    conn.commit()

    # entrega no telegram
    tg_send(
        tg_id,
        DELIVERY_COPY.format(license_key=license_key, days=s.get("days", 30), credits=s.get("credits", 0)),
    )

    return {"status": "paid_confirmed", "payment_id": payment_id, "delivered": True}

# ================== ADMIN (mínimo) ==================
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

# ================== INCLUDE ROUTERS ==================
app.include_router(core)
app.include_router(admin, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("tribotools_api:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
