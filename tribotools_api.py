#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import threading
import typing as t
import uuid
import io
import csv
import hmac
import requests

from fastapi import FastAPI, HTTPException, Depends, Body, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, Response

API_VERSION = "PYR-2.0.0"

# ================== ENV ==================
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR / "licenses.db").resolve()
DB_PATH = os.getenv("LICENSE_DB", str(DEFAULT_DB))

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()

MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN", "").strip()
BASE_PUBLIC_URL = os.getenv("BASE_PUBLIC_URL", "").strip()

if BASE_PUBLIC_URL.endswith("/"):
    BASE_PUBLIC_URL = BASE_PUBLIC_URL[:-1]

TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

# ================== PRODUTOS ==================
SERVICES = {
    "robo_meet": {
        "name": "Robô Audiência Google Meet",
        "price": 497.00,
        "credits": 1000,
        "days": 30,
        "max_devices": 1,
        "sku": "PYR-ROBO-MEET",
    }
}

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

    # pedidos/pagamentos MP
    cur.execute("""
        CREATE TABLE IF NOT EXISTS mp_order (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            service TEXT,
            telegram_chat_id TEXT,
            payment_id TEXT UNIQUE,
            status TEXT,
            external_reference TEXT,
            license_key_plain TEXT,
            license_key_hash TEXT,
            processed INTEGER DEFAULT 0,
            meta TEXT
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_mp_order_payment ON mp_order(payment_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_mp_order_chat ON mp_order(telegram_chat_id)")

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

def grant_credits_internal(lic_hash: str, amount: int, reason: str, meta_obj: dict | None = None):
    ensure_wallet_for_license(lic_hash)
    meta = json.dumps(meta_obj or {}, ensure_ascii=False)
    conn = connect_once()
    cur = conn.cursor()
    now = now_utc_str()
    cur.execute(
        "UPDATE credit_wallet SET balance = balance + ?, updated_at=? WHERE license_key_hash=?",
        (amount, now, lic_hash),
    )
    cur.execute(
        "INSERT INTO credit_tx (license_key_hash, change, reason, meta, created_at) VALUES (?,?,?,?,?)",
        (lic_hash, amount, reason, meta, now),
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
app = FastAPI(title="Pyratas API", version=API_VERSION)

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
def tg_send(chat_id: int | str, text: str, reply_markup: dict | None = None):
    if not TELEGRAM_BOT_TOKEN:
        return
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        requests.post(f"{TELEGRAM_API}/sendMessage", json=payload, timeout=12)
    except Exception:
        pass

def tg_answer_callback(callback_query_id: str):
    if not TELEGRAM_BOT_TOKEN:
        return
    try:
        requests.post(
            f"{TELEGRAM_API}/answerCallbackQuery",
            json={"callback_query_id": callback_query_id},
            timeout=10,
        )
    except Exception:
        pass

def async_send(chat_id: int | str, text: str, reply_markup: dict | None = None):
    threading.Thread(target=tg_send, args=(chat_id, text, reply_markup), daemon=True).start()

# ================== MERCADO PAGO ==================
def mp_create_pix_payment(service_key: str, telegram_chat_id: str) -> dict:
    if not MP_ACCESS_TOKEN or not BASE_PUBLIC_URL:
        raise HTTPException(500, "MP_ACCESS_TOKEN/BASE_PUBLIC_URL não configurados.")

    if service_key not in SERVICES:
        raise HTTPException(400, "Serviço inválido.")

    s = SERVICES[service_key]

    # email “fake” apenas para passar validação do MP (formato válido)
    payer_email = f"tg{telegram_chat_id}@pyratas.bot"

    external_reference = f"tg:{telegram_chat_id}|svc:{service_key}"

    payload = {
        "transaction_amount": float(s["price"]),
        "description": f"[PYR] {s['name']} - {s['sku']}",
        "payment_method_id": "pix",
        "payer": {"email": payer_email},
        "notification_url": f"{BASE_PUBLIC_URL}/webhooks/mercadopago",
        "external_reference": external_reference,
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

    resp = r.json()
    resp["_http_status"] = r.status_code
    resp["_idem_key"] = idem_key

    if r.status_code >= 400:
        raise HTTPException(502, f"Erro Mercado Pago: {resp}")

    # salva no DB (ainda pendente)
    payment_id = str(resp.get("id") or "")
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR IGNORE INTO mp_order
        (created_at, service, telegram_chat_id, payment_id, status, external_reference, meta)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            now_utc_str(),
            service_key,
            str(telegram_chat_id),
            payment_id,
            resp.get("status") or "pending",
            external_reference,
            json.dumps({"mp": resp}, ensure_ascii=False),
        ),
    )
    conn.commit()

    return resp

def mp_fetch_payment(payment_id: str) -> dict:
    r = requests.get(
        f"https://api.mercadopago.com/v1/payments/{payment_id}",
        headers={"Authorization": f"Bearer {MP_ACCESS_TOKEN}"},
        timeout=30,
    )
    data = r.json()
    data["_http_status"] = r.status_code
    if r.status_code >= 400:
        raise HTTPException(502, f"Erro ao consultar pagamento MP: {data}")
    return data

def generate_license_plain(service_key: str) -> str:
    sku = SERVICES[service_key]["sku"]
    suffix = uuid.uuid4().hex[:10].upper()
    return f"{sku}-{suffix}"

def ensure_license_created(license_plain: str, max_devices: int, notes: str) -> tuple[str, str]:
    """Cria licença se não existir. Retorna (license_plain, license_hash)."""
    lic_hash = sha256(license_plain)
    conn = connect_once()
    cur = conn.cursor()

    cur.execute("SELECT id FROM license WHERE license_key_hash=?", (lic_hash,))
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO license (license_key_hash, status, max_devices, notes, created_at) VALUES (?,?,?,?,?)",
            (lic_hash, "active", int(max_devices), notes, now_utc_str()),
        )
        conn.commit()

    ensure_wallet_for_license(lic_hash)
    return license_plain, lic_hash

def mark_order_processed(payment_id: str, status: str, lic_plain: str, lic_hash: str):
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE mp_order
        SET status=?, license_key_plain=?, license_key_hash=?, processed=1
        WHERE payment_id=?
        """,
        (status, lic_plain, lic_hash, payment_id),
    )
    conn.commit()

def order_already_processed(payment_id: str) -> bool:
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT processed FROM mp_order WHERE payment_id=?", (payment_id,))
    row = cur.fetchone()
    if not row:
        return False
    return int(row["processed"] or 0) == 1

def get_order_chat_and_service(payment_id: str) -> tuple[str | None, str | None]:
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT telegram_chat_id, service FROM mp_order WHERE payment_id=?", (payment_id,))
    row = cur.fetchone()
    if not row:
        return None, None
    return str(row["telegram_chat_id"]), str(row["service"])

def parse_external_reference(external_reference: str) -> tuple[str | None, str | None]:
    # "tg:<id>|svc:<service>"
    try:
        parts = external_reference.split("|")
        tg_part = parts[0].split(":", 1)[1]
        svc_part = parts[1].split(":", 1)[1]
        return tg_part, svc_part
    except Exception:
        return None, None

# ================== ROTAS PÚBLICAS ==================
@core.get("/")
def home():
    return {"status": "ok", "msg": "Pyratas API rodando", "version": API_VERSION, "db_path": DB_PATH}

@core.get("/healthz")
def healthz():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r["name"] for r in cur.fetchall()]
    return {"ok": True, "tables": tables, "db_path": str(DB_PATH)}

# ================== TELEGRAM WEBHOOK ==================
@core.post("/webhooks/telegram")
async def telegram_webhook(request: Request):
    # valida secret do webhook
    if TELEGRAM_WEBHOOK_SECRET:
        received = (request.headers.get("x-telegram-bot-api-secret-token") or "").strip()
        if not received or not hmac.compare_digest(received, TELEGRAM_WEBHOOK_SECRET):
            raise HTTPException(status_code=401, detail="Webhook secret inválido.")

    update = await request.json()

    # log básico
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

    # /start e mensagens
    if "message" in update:
        msg = update["message"]
        chat_id = msg["chat"]["id"]
        text = (msg.get("text") or "").strip()

        if text == "/start":
            async_send(
                chat_id,
                "🚀 *PYRATAS*\n\n"
                "Bem-vindo.\n"
                "Aqui você compra e ativa ferramentas oficiais da nossa stack.\n\n"
                "✅ Infra estável\n"
                "✅ Automação real\n"
                "✅ Histórico de entrega\n\n"
                "*Escolha um produto:*",
                reply_markup={
                    "inline_keyboard": [
                        [{"text": "👥 Robô Audiência Google Meet — R$ 497", "callback_data": "buy_robo_meet"}]
                    ]
                }
            )
        return {"ok": True}

    # callbacks dos botões
    if "callback_query" in update:
        cb = update["callback_query"]
        cb_id = cb.get("id")
        data = cb.get("data") or ""
        chat_id = cb["message"]["chat"]["id"]

        if cb_id:
            tg_answer_callback(cb_id)

        if data == "buy_robo_meet":
            # cria cobrança PIX no MP e manda link + copia e cola
            try:
                payment = mp_create_pix_payment("robo_meet", str(chat_id))
                poi = (payment.get("point_of_interaction") or {}).get("transaction_data") or {}
                qr = poi.get("qr_code") or ""
                ticket_url = poi.get("ticket_url") or ""

                msg_text = (
                    "👥 *Robô Audiência Google Meet*\n\n"
                    "• Entra automaticamente em salas\n"
                    "• Simula presença real\n"
                    "• Infra estável e segura\n\n"
                    "*Valor:* R$ 497\n\n"
                    "✅ *Pagamento PIX gerado.*\n\n"
                    "*Copia e cola (PIX):*\n"
                    f"`{qr}`\n\n"
                    "Depois do pagamento, a licença chega aqui automaticamente."
                )

                async_send(
                    chat_id,
                    msg_text,
                    reply_markup={
                        "inline_keyboard": [
                            [{"text": "🔗 Abrir pagamento", "url": ticket_url}] if ticket_url else []
                        ]
                    } if ticket_url else None
                )
            except Exception as e:
                async_send(chat_id, f"❌ Erro ao gerar PIX. Tente novamente.\n\nDetalhe: `{str(e)[:180]}`")

        return {"ok": True}

    return {"ok": True}

# ================== WEBHOOK MERCADO PAGO ==================
@core.post("/webhooks/mercadopago")
async def mercadopago_webhook(request: Request):
    if not MP_ACCESS_TOKEN:
        return {"status": "missing_mp_token"}

    body = await request.json()

    # MP pode mandar em formatos diferentes
    payment_id = None
    if isinstance(body, dict):
        payment_id = (body.get("data") or {}).get("id") or body.get("id")

    if not payment_id:
        return {"status": "ignored", "reason": "no_payment_id"}

    payment_id = str(payment_id)

    # idempotência: se já processou, sai
    if order_already_processed(payment_id):
        return {"status": "already_processed", "payment_id": payment_id}

    # consulta status real
    payment = mp_fetch_payment(payment_id)
    status = (payment.get("status") or "").lower()

    # atualiza status no DB (se existir)
    try:
        conn = connect_once()
        cur = conn.cursor()
        cur.execute("UPDATE mp_order SET status=?, meta=? WHERE payment_id=?",
                    (status, json.dumps({"mp_fetch": payment}, ensure_ascii=False), payment_id))
        conn.commit()
    except Exception:
        pass

    if status != "approved":
        return {"status": status, "payment_id": payment_id}

    # resolve chat_id e service (prioriza DB, senão external_reference)
    ext = payment.get("external_reference") or ""
    chat_id, service_key = get_order_chat_and_service(payment_id)

    if (not chat_id or not service_key) and ext:
        chat_id2, svc2 = parse_external_reference(ext)
        chat_id = chat_id or chat_id2
        service_key = service_key or svc2

    if not chat_id or not service_key or service_key not in SERVICES:
        return {"status": "approved_but_unlinked", "payment_id": payment_id, "external_reference": ext}

    s = SERVICES[service_key]

    # gera licença, cria no banco, credita, entrega no telegram
    lic_plain = generate_license_plain(service_key)
    notes = f"MP approved | payment_id={payment_id} | tg={chat_id} | svc={service_key}"
    lic_plain, lic_hash = ensure_license_created(lic_plain, s["max_devices"], notes)

    # credita os créditos do produto
    grant_credits_internal(lic_hash, int(s["credits"]), "purchase", {"payment_id": payment_id, "service": service_key})

    # marca pedido como processado
    mark_order_processed(payment_id, status, lic_plain, lic_hash)

    # entrega no telegram
    async_send(
        chat_id,
        "✅ *Pagamento aprovado!*\n\n"
        f"Produto: *{s['name']}*\n"
        f"Validade: *{s['days']} dias*\n"
        f"Créditos: *{s['credits']}*\n\n"
        "*Sua licença (guarde):*\n"
        f"`{lic_plain}`\n\n"
        "Agora você pode ativar no robô usando essa licença. Se precisar, me chama aqui."
    )

    return {"status": "paid_confirmed", "payment_id": payment_id, "license_hash": lic_hash}

# ================== LICENÇA / CRÉDITOS (MESMO MODELO) ==================
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

    try:
        exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
        if datetime.utcnow() > exp:
            raise HTTPException(403, "Token expirado.")
    except Exception:
        pass

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

    try:
        exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
        if datetime.utcnow() > exp:
            raise HTTPException(403, "Token expirado.")
    except Exception:
        pass

    lic_hash = row["license_key_hash"]
    ensure_wallet_for_license(lic_hash)

    cur.execute("SELECT balance FROM credit_wallet WHERE license_key_hash=?", (lic_hash,))
    row2 = cur.fetchone()
    balance = row2["balance"] if row2 else 0

    if balance < amount:
        raise HTTPException(402, f"Créditos insuficientes. Saldo atual: {balance}, necessário: {amount}")

    now = now_utc_str()
    cur.execute("UPDATE credit_wallet SET balance = balance - ?, updated_at=? WHERE license_key_hash=?", (amount, now, lic_hash))
    cur.execute("INSERT INTO credit_tx (license_key_hash, change, reason, meta, created_at) VALUES (?,?,?,?,?)",
                (lic_hash, -amount, reason, meta, now))
    conn.commit()

    cur.execute("SELECT balance FROM credit_wallet WHERE license_key_hash=?", (lic_hash,))
    row3 = cur.fetchone()
    new_balance = row3["balance"] if row3 else 0

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

# ================== ADMIN ==================
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
    cur.execute("""
        SELECT
            l.license_key_hash,
            l.status,
            l.max_devices,
            COALESCE(l.notes, '') AS notes,
            COALESCE(cw.balance, 0) AS credits_balance,
            COUNT(u.id) AS total_events,
            SUM(CASE WHEN u.event='run_start' THEN 1 ELSE 0 END) AS runs,
            SUM(CASE WHEN u.event='activate' THEN 1 ELSE 0 END) AS activations,
            SUM(CASE WHEN u.event='validate_ok' THEN 1 ELSE 0 END) AS validations,
            COUNT(DISTINCT CASE WHEN u.device_id IS NOT NULL THEN u.device_id END) AS devices
        FROM license l
        LEFT JOIN usage u ON u.license_key_hash = l.license_key_hash
        LEFT JOIN credit_wallet cw ON cw.license_key_hash = l.license_key_hash
        GROUP BY l.license_key_hash, l.status, l.max_devices, l.notes, cw.balance
        ORDER BY runs DESC, activations DESC, l.license_key_hash ASC
    """)
    rows = []
    for r in cur.fetchall():
        rows.append({
            "license_key_hash": r["license_key_hash"],
            "status": r["status"],
            "max_devices": r["max_devices"],
            "notes": r["notes"],
            "credits_balance": r["credits_balance"] or 0,
            "total_events": r["total_events"] or 0,
            "runs": r["runs"] or 0,
            "activations": r["activations"] or 0,
            "validations": r["validations"] or 0,
            "devices": r["devices"] or 0,
        })
    return {"rows": rows, "count": len(rows)}

@admin.get("/usage-csv", dependencies=[Depends(require_admin)])
def usage_csv():
    summary = usage_summary()
    rows: list[dict] = summary["rows"]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["license_key_hash","status","max_devices","devices","runs","activations","validations","total_events","credits_balance","notes"])
    for r in rows:
        writer.writerow([
            r["license_key_hash"], r["status"], r["max_devices"], r["devices"],
            r["runs"], r["activations"], r["validations"], r["total_events"],
            r.get("credits_balance", 0), (r["notes"] or "").replace("\n"," ").replace("\r"," ")
        ])

    csv_bytes = output.getvalue().encode("utf-8-sig")
    headers = {"Content-Disposition": 'attachment; filename="pyratas_usage_summary.csv"'}
    return Response(content=csv_bytes, media_type="text/csv", headers=headers)

# ================== /panel (mantém funcionando) ==================
@core.get("/panel", response_class=HTMLResponse)
def panel():
    # mesmo HTML do seu painel (sem mexer na lógica) — mantido
    # para não quebrar o /panel no Render.
    html = """<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8"/>
    <title>Pyratas — Painel</title><style>
    body{margin:0;font-family:system-ui;background:#050816;color:#f9fafb}
    header{padding:16px 24px;background:#020617;border-bottom:1px solid #1f2933;display:flex;justify-content:space-between;align-items:center}
    main{padding:20px 24px;max-width:1200px;margin:0 auto}
    .badge{font-size:11px;padding:4px 8px;border-radius:999px;background:#111827;border:1px solid #4b5563}
    .token-box{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:16px}
    .token-box input{background:#020617;border-radius:999px;border:1px solid #4b5563;padding:6px 12px;color:#e5e7eb;min-width:260px}
    .token-box button{border-radius:999px;border:none;padding:6px 14px;font-size:13px;cursor:pointer;background:#22c55e;color:#022c22;font-weight:600}
    .token-box button.secondary{background:#111827;color:#e5e7eb;border:1px solid #374151}
    .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px}
    .card{padding:14px 16px;border-radius:16px;background:radial-gradient(circle at top left,#1f2933,#020617);border:1px solid #1f2937}
    .card h3{margin:0 0 4px 0;font-size:13px;color:#9ca3af}
    .card .value{font-size:22px;font-weight:600}
    .create-box{border-radius:16px;border:1px solid #1f2937;background:#020617;padding:12px 14px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
    .create-box input{background:#020617;border-radius:999px;border:1px solid #4b5563;padding:6px 10px;color:#e5e7eb;font-size:13px}
    .create-box input.small{width:80px}
    .create-box input.notes{flex:1;min-width:180px}
    .create-box button{border-radius:999px;border:none;padding:6px 14px;font-size:13px;cursor:pointer;background:#3b82f6;color:#e5e7eb;font-weight:600}
    .table-wrapper{border-radius:16px;border:1px solid #1f2937;overflow:hidden;background:#020617;max-height:480px;overflow-y:auto}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th,td{padding:8px 10px;border-bottom:1px solid #111827}
    th{text-align:left;background:#020617;position:sticky;top:0;z-index:1}
    tbody tr:nth-child(even){background:rgba(15,23,42,.75)}
    </style></head><body>
    <header><h1>Pyratas — Painel</h1><span class="badge">API v<span id="apiVersion">-</span></span></header>
    <main>
    <div class="token-box">
      <label>Admin Token:</label>
      <input id="tokenInput" type="password" placeholder="ADMIN_TOKEN" />
      <button id="saveTokenBtn">Salvar</button>
      <button id="loadBtn" class="secondary">Carregar</button>
      <div id="tokenStatus" style="color:#9ca3af;font-size:12px"></div>
    </div>

    <div class="cards">
      <div class="card"><h3>Total de licenças</h3><div class="value" id="cardTotalLic">-</div></div>
      <div class="card"><h3>Ativações ativas</h3><div class="value" id="cardActiveAct">-</div></div>
      <div class="card"><h3>Dispositivos únicos</h3><div class="value" id="cardDevices">-</div></div>
      <div class="card"><h3>Eventos 24h</h3><div class="value" id="cardUsage24h">-</div></div>
    </div>

    <div class="create-box">
      <input id="newKey" placeholder="Chave (ex.: PYR-CLIENTE-001)" />
      <input id="newMax" class="small" type="number" min="1" value="1" />
      <input id="newNotes" class="notes" placeholder="Notas (opcional)" />
      <button id="createLicBtn">Criar licença</button>
      <div id="createStatus" style="width:100%;font-size:12px;color:#9ca3af"></div>
    </div>

    <div class="table-wrapper">
      <table>
        <thead><tr>
          <th>Licença (hash)</th><th>Status</th><th>Máx</th><th>Devices</th><th>Runs</th><th>Ativações</th><th>Validações</th><th>Total</th><th>Créditos</th><th>Notas</th>
        </tr></thead>
        <tbody id="usageBody"><tr><td colspan="10">Clique em “Carregar”.</td></tr></tbody>
      </table>
    </div>

    </main>
    <script>
    const tokenInput=document.getElementById("tokenInput");
    const saveTokenBtn=document.getElementById("saveTokenBtn");
    const loadBtn=document.getElementById("loadBtn");
    const tokenStatus=document.getElementById("tokenStatus");
    const apiVersionSpan=document.getElementById("apiVersion");
    const usageBody=document.getElementById("usageBody");
    const cardTotalLic=document.getElementById("cardTotalLic");
    const cardActiveAct=document.getElementById("cardActiveAct");
    const cardDevices=document.getElementById("cardDevices");
    const cardUsage24h=document.getElementById("cardUsage24h");
    const newKey=document.getElementById("newKey");
    const newMax=document.getElementById("newMax");
    const newNotes=document.getElementById("newNotes");
    const createBtn=document.getElementById("createLicBtn");
    const createStatus=document.getElementById("createStatus");

    function getToken(){return window.localStorage.getItem("pyr_admin_token")||"";}
    function setToken(tok){ if(tok) window.localStorage.setItem("pyr_admin_token",tok); else window.localStorage.removeItem("pyr_admin_token");}
    function updateTokenStatus(){ tokenStatus.textContent = getToken() ? "Token salvo no navegador." : "Cole o ADMIN_TOKEN e clique em Salvar."; }

    async function fetchJSON(url, opts={}){
      const t=getToken();
      const headers=Object.assign({"Accept":"application/json"}, opts.headers||{});
      if(t) headers["Authorization"]="Bearer "+t;
      const fo={method:opts.method||"GET", headers};
      if(opts.body) fo.body=opts.body;
      const resp=await fetch(url, fo);
      if(!resp.ok){ const txt=await resp.text(); throw new Error(resp.status+" "+txt); }
      return resp.json();
    }

    async function carregarVersao(){ try{ const d=await fetchJSON("/"); apiVersionSpan.textContent=d.version||"-"; }catch(e){} }
    async function carregarStats(){
      try{ const s=await fetchJSON("/stats");
        cardTotalLic.textContent=s.total_licenses??"-";
        cardActiveAct.textContent=s.active_activations??"-";
        cardDevices.textContent=s.unique_devices??"-";
        cardUsage24h.textContent=s.usage_24h??"-";
      }catch(e){}
    }
    async function carregarUsage(){
      const data=await fetchJSON("/api/admin/usage-summary");
      const rows=data.rows||[];
      usageBody.innerHTML="";
      if(!rows.length){ usageBody.innerHTML='<tr><td colspan="10">Sem licenças.</td></tr>'; return; }
      for(const r of rows){
        const tr=document.createElement("tr");
        tr.innerHTML = `
          <td>${r.license_key_hash}</td>
          <td>${(r.status||"").toLowerCase()=="active" ? "Ativa" : "Inativa"}</td>
          <td>${r.max_devices ?? ""}</td>
          <td>${r.devices ?? 0}</td>
          <td>${r.runs ?? 0}</td>
          <td>${r.activations ?? 0}</td>
          <td>${r.validations ?? 0}</td>
          <td>${r.total_events ?? 0}</td>
          <td>${r.credits_balance ?? 0}</td>
          <td>${(r.notes||"")}</td>
        `;
        usageBody.appendChild(tr);
      }
    }

    saveTokenBtn.addEventListener("click", ()=>{ setToken(tokenInput.value.trim()); updateTokenStatus(); });
    loadBtn.addEventListener("click", async ()=>{ await carregarVersao(); await carregarStats(); await carregarUsage(); });

    createBtn.addEventListener("click", async ()=>{
      createStatus.textContent="";
      const key=newKey.value.trim();
      const max=parseInt(newMax.value||"1",10);
      const notes=newNotes.value.trim();
      if(!key){ createStatus.textContent="Informe uma chave."; return; }
      try{
        await fetchJSON("/api/admin/licenses", {method:"POST", headers:{"Content-Type":"application/json"},
          body: JSON.stringify({license_key:key, max_devices: max||1, notes})
        });
        createStatus.textContent="Licença criada.";
        newKey.value=""; newNotes.value="";
        await carregarStats(); await carregarUsage();
      }catch(e){ createStatus.textContent="Erro: "+e.message; }
    });

    tokenInput.value=getToken(); updateTokenStatus();
    carregarVersao(); carregarStats();
    </script></body></html>"""
    return HTMLResponse(content=html)

# include routers
app.include_router(core)
app.include_router(admin, prefix="/api")

# local run
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("tribotools_api:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
