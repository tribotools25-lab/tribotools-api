#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TriboTools API (Licenças + Créditos) + Bot Telegram + Mercado Pago PIX
+ /panel (HTML) para: criar chave, listar chaves, ver uso e contagem por licença.

ENV VARS (Render):
- LICENSE_DB
- ADMIN_TOKEN
- BASE_PUBLIC_URL              (ex: https://tribotools-api.onrender.com)
- MP_ACCESS_TOKEN
- TELEGRAM_BOT_TOKEN
- TELEGRAM_WEBHOOK_SECRET
- PANEL_PASSWORD               (opcional; se setar, exige /panel?p=... e demais rotas do painel)

Obs:
- Admin API continua em /api/admin/... (porque include_router(admin, prefix="/api"))
- /panel é separado e protegido via PANEL_PASSWORD (recomendado)
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
import re
import requests
import hmac

from fastapi import FastAPI, HTTPException, Depends, Body, Query, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse

API_VERSION = "TT-1.3.0"

# ================== ENV ==================
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR / "licenses.db").resolve()

DB_PATH = os.getenv("LICENSE_DB", str(DEFAULT_DB)).strip()
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()

BASE_PUBLIC_URL = os.getenv("BASE_PUBLIC_URL", "").strip().rstrip("/")
MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN", "").strip()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()

PANEL_PASSWORD = os.getenv("PANEL_PASSWORD", "").strip()

# ================== COPY / PRODUTOS ==================
# Edite aqui a copy. HTML porque mandamos com parse_mode=HTML.
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
    # adicione mais produtos aqui:
    # "robo_tiktok": {...},
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
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_event ON usage(event)")

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

    # Telegram state
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tg_state (
            telegram_id TEXT PRIMARY KEY,
            state TEXT,
            service TEXT,
            updated_at TEXT
        )
    """)

    # Orders
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

# ================== PANEL AUTH ==================
def panel_auth(request: Request):
    if PANEL_PASSWORD:
        p = (request.query_params.get("p") or "").strip()
        if not p or not hmac.compare_digest(p, PANEL_PASSWORD):
            raise HTTPException(401, "Acesso negado. Use /panel?p=SENHA")

def panel_qs(request: Request) -> str:
    """Mantém ?p=... nas URLs internas do painel."""
    if not PANEL_PASSWORD:
        return ""
    p = (request.query_params.get("p") or "").strip()
    return f"?p={p}" if p else ""

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
    return f"{prefix}-{uuid.uuid4().hex[:6].upper()}-{uuid.uuid4().hex[:6].upper()}"

def upsert_license_and_credits(license_key: str, max_devices: int, credits: int, notes: str = ""):
    lic_hash = sha256(license_key)
    conn = connect_once()
    cur = conn.cursor()

    cur.execute("SELECT id FROM license WHERE license_key_hash=?", (lic_hash,))
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO license (license_key_hash, status, max_devices, notes, created_at) VALUES (?,?,?,?,?)",
            (lic_hash, "active", int(max_devices or 1), notes, now_utc_str()),
        )
        conn.commit()

    ensure_wallet_for_license(lic_hash)

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

# ================== PANEL (HTML) ==================
def _panel_layout(title: str, body_html: str) -> str:
    return f"""
    <html>
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>{title}</title>
      <style>
        body {{ font-family: Arial, sans-serif; padding: 24px; background:#0b0b0b; color:#ffd400; }}
        a {{ color:#ffd400; text-decoration:none; }}
        a:hover {{ text-decoration:underline; }}
        .top {{ display:flex; gap:12px; flex-wrap:wrap; align-items:center; margin-bottom:16px; }}
        .card {{ background:#111; border:1px solid #333; border-radius:14px; padding:16px; margin-bottom:16px; }}
        .kpi {{ display:flex; gap:12px; flex-wrap:wrap; }}
        .kpi .card {{ flex:1; min-width:220px; }}
        table {{ width:100%; border-collapse: collapse; }}
        th, td {{ border-bottom: 1px solid #222; padding: 10px; text-align:left; color:#eee; }}
        th {{ color:#ffd400; }}
        input, select {{ width:100%; padding:10px; border-radius:10px; border:1px solid #333; background:#0f0f0f; color:#fff; }}
        button {{ padding:12px 14px; border-radius:12px; border:1px solid #333; background:#ffd400; color:#000; font-weight:700; cursor:pointer; }}
        button:hover {{ filter:brightness(0.95); }}
        code {{ color:#fff; }}
        .grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap:12px; }}
        .small {{ color:#bbb; font-size:12px; }}
      </style>
    </head>
    <body>
      {body_html}
    </body>
    </html>
    """

@core.get("/panel", response_class=HTMLResponse)
async def panel_home(request: Request):
    panel_auth(request)
    qs = panel_qs(request)

    conn = connect_once()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM license")
    total_licenses = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM activation WHERE datetime(expires_at) > datetime('now')")
    active_activations = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM usage WHERE datetime(ts) > datetime('now','-1 day')")
    usage_24h = cur.fetchone()["c"]

    products_opts = ""
    for k, s in SALES.items():
        products_opts += f"<option value='{k}'>{s['title']} ({k})</option>"

    html = f"""
    <div class="top">
      <h1 style="margin:0">🧭 TriboTools • Panel</h1>
      <div class="small">DB: <code>{DB_PATH}</code></div>
    </div>

    <div class="card">
      <b>Navegação:</b>
      <div style="margin-top:8px; display:flex; gap:12px; flex-wrap:wrap;">
        <a href="/panel{qs}">Home</a>
        <a href="/panel/licenses{qs}">Licenças</a>
        <a href="/panel/usage{qs}">Uso (logs)</a>
        <a href="/panel/usage_by_license{qs}">Uso por licença</a>
        <a href="/docs">/docs</a>
        <a href="/healthz">/healthz</a>
      </div>
    </div>

    <div class="kpi">
      <div class="card"><h3 style="margin:0 0 8px 0">Total licenças</h3><div style="font-size:30px">{total_licenses}</div></div>
      <div class="card"><h3 style="margin:0 0 8px 0">Ativações válidas</h3><div style="font-size:30px">{active_activations}</div></div>
      <div class="card"><h3 style="margin:0 0 8px 0">Eventos (24h)</h3><div style="font-size:30px">{usage_24h}</div></div>
    </div>

    <div class="card">
      <h2 style="margin:0 0 12px 0">Criar chave (rápido)</h2>
      <form method="post" action="/panel/create_license{qs}">
        <div class="grid">
          <div>
            <label class="small">Produto (pra aplicar créditos/limites)</label>
            <select name="service">{products_opts}</select>
          </div>
          <div>
            <label class="small">Max devices (override opcional)</label>
            <input name="max_devices" placeholder="vazio = usa do produto" />
          </div>
          <div>
            <label class="small">Créditos (override opcional)</label>
            <input name="credits" placeholder="vazio = usa do produto" />
          </div>
          <div>
            <label class="small">Prefixo da licença</label>
            <input name="prefix" value="TT" />
          </div>
        </div>
        <div style="margin-top:12px;">
          <button type="submit">Gerar licença agora</button>
        </div>
        <div class="small" style="margin-top:10px;">
          * Cria licença e já credita a carteira. (Não depende do ADMIN_TOKEN)
        </div>
      </form>
    </div>
    """
    return HTMLResponse(_panel_layout("TriboTools • Panel", html))

@core.post("/panel/create_license", response_class=HTMLResponse)
async def panel_create_license(
    request: Request,
    service: str = Form(...),
    max_devices: str = Form(""),
    credits: str = Form(""),
    prefix: str = Form("TT"),
):
    panel_auth(request)
    qs = panel_qs(request)

    if service not in SALES:
        raise HTTPException(400, "Serviço inválido.")

    s = SALES[service]
    md = int(max_devices) if (max_devices or "").strip().isdigit() else int(s.get("max_devices", 1))
    cr = int(credits) if (credits or "").strip().isdigit() else int(s.get("credits", 0))
    px = (prefix or "TT").strip() or "TT"

    license_key = generate_license_key(prefix=px)
    upsert_license_and_credits(
        license_key=license_key,
        max_devices=md,
        credits=cr,
        notes=f"Panel manual svc:{service}",
    )

    lic_hash = sha256(license_key)
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT balance FROM credit_wallet WHERE license_key_hash=?", (lic_hash,))
    bal = (cur.fetchone() or {}).get("balance", 0)

    html = f"""
    <div class="card">
      <h2 style="margin:0 0 12px 0">✅ Licença criada</h2>
      <div><b>Produto:</b> {s['title']} ({service})</div>
      <div style="margin-top:10px;"><b>Chave:</b> <code style="font-size:16px">{license_key}</code></div>
      <div style="margin-top:10px;"><b>Hash:</b> <code>{lic_hash}</code></div>
      <div style="margin-top:10px;"><b>Max devices:</b> {md}</div>
      <div style="margin-top:10px;"><b>Créditos creditados:</b> {cr} (saldo agora: {bal})</div>
      <div style="margin-top:14px; display:flex; gap:12px; flex-wrap:wrap;">
        <a href="/panel/licenses{qs}">Ver licenças</a>
        <a href="/panel{qs}">Voltar</a>
      </div>
    </div>
    """
    return HTMLResponse(_panel_layout("Licença criada", html))

@core.get("/panel/licenses", response_class=HTMLResponse)
async def panel_licenses(request: Request, limit: int = 200):
    panel_auth(request)
    qs = panel_qs(request)

    conn = connect_once()
    cur = conn.cursor()
    cur.execute("""
      SELECT l.id, l.license_key_hash, l.status, l.max_devices, l.notes, l.created_at,
             COALESCE(w.balance, 0) AS balance
      FROM license l
      LEFT JOIN credit_wallet w ON w.license_key_hash = l.license_key_hash
      ORDER BY l.id DESC
      LIMIT ?
    """, (int(limit),))
    rows = cur.fetchall()

    trs = ""
    for r in rows:
        trs += f"""
        <tr>
          <td>{r['id']}</td>
          <td style="font-family:monospace">{r['license_key_hash']}</td>
          <td>{r['status']}</td>
          <td>{r['max_devices']}</td>
          <td>{r['balance']}</td>
          <td>{(r['notes'] or '')[:120]}</td>
          <td>{r['created_at']}</td>
        </tr>
        """

    html = f"""
    <div class="card">
      <b>Navegação:</b>
      <div style="margin-top:8px; display:flex; gap:12px; flex-wrap:wrap;">
        <a href="/panel{qs}">Home</a>
        <a href="/panel/licenses{qs}">Licenças</a>
        <a href="/panel/usage{qs}">Uso (logs)</a>
        <a href="/panel/usage_by_license{qs}">Uso por licença</a>
      </div>
    </div>

    <div class="card">
      <h2 style="margin:0 0 12px 0">Licenças (últimas {min(limit, 200)})</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>License Hash</th>
            <th>Status</th>
            <th>Max</th>
            <th>Créditos</th>
            <th>Notes</th>
            <th>Criada</th>
          </tr>
        </thead>
        <tbody>
          {trs or "<tr><td colspan='7'>Nenhuma licença ainda.</td></tr>"}
        </tbody>
      </table>
    </div>
    """
    return HTMLResponse(_panel_layout("Licenças", html))

@core.get("/panel/usage", response_class=HTMLResponse)
async def panel_usage(
    request: Request,
    license_hash: str = "",
    device_id: str = "",
    event: str = "",
    limit: int = 200,
):
    panel_auth(request)
    qs = panel_qs(request)

    lh = (license_hash or "").strip()
    dv = (device_id or "").strip()
    ev = (event or "").strip()

    where = []
    params = []

    if lh:
        where.append("license_key_hash = ?")
        params.append(lh)
    if dv:
        where.append("device_id = ?")
        params.append(dv)
    if ev:
        where.append("event LIKE ?")
        params.append(f"%{ev}%")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    params.append(int(limit))

    conn = connect_once()
    cur = conn.cursor()
    cur.execute(f"""
      SELECT ts, license_key_hash, device_id, event, meta
      FROM usage
      {where_sql}
      ORDER BY datetime(ts) DESC
      LIMIT ?
    """, tuple(params))
    rows = cur.fetchall()

    trs = ""
    for r in rows:
        meta = (r["meta"] or "")
        if len(meta) > 160:
            meta = meta[:160] + "..."
        trs += f"""
        <tr>
          <td>{r['ts']}</td>
          <td style="font-family:monospace">{r['license_key_hash']}</td>
          <td style="font-family:monospace">{r['device_id']}</td>
          <td>{r['event']}</td>
          <td style="font-family:monospace">{meta}</td>
        </tr>
        """

    html = f"""
    <div class="card">
      <b>Navegação:</b>
      <div style="margin-top:8px; display:flex; gap:12px; flex-wrap:wrap;">
        <a href="/panel{qs}">Home</a>
        <a href="/panel/licenses{qs}">Licenças</a>
        <a href="/panel/usage{qs}">Uso (logs)</a>
        <a href="/panel/usage_by_license{qs}">Uso por licença</a>
      </div>
    </div>

    <div class="card">
      <h2 style="margin:0 0 12px 0">Logs de uso</h2>
      <form method="get" action="/panel/usage{qs}">
        <div class="grid">
          <div>
            <label class="small">license_hash (exato)</label>
            <input name="license_hash" value="{lh}"/>
          </div>
          <div>
            <label class="small">device_id (exato)</label>
            <input name="device_id" value="{dv}"/>
          </div>
          <div>
            <label class="small">event (contém)</label>
            <input name="event" value="{ev}"/>
          </div>
          <div>
            <label class="small">limit</label>
            <input name="limit" value="{int(limit)}"/>
          </div>
        </div>
        <div style="margin-top:12px;">
          <button type="submit">Filtrar</button>
        </div>
      </form>
    </div>

    <div class="card">
      <table>
        <thead>
          <tr>
            <th>TS</th>
            <th>License Hash</th>
            <th>Device</th>
            <th>Event</th>
            <th>Meta</th>
          </tr>
        </thead>
        <tbody>
          {trs or "<tr><td colspan='5'>Sem eventos.</td></tr>"}
        </tbody>
      </table>
    </div>
    """
    return HTMLResponse(_panel_layout("Uso (logs)", html))

@core.get("/panel/usage_by_license", response_class=HTMLResponse)
async def panel_usage_by_license(request: Request, limit: int = 300):
    panel_auth(request)
    qs = panel_qs(request)

    conn = connect_once()
    cur = conn.cursor()
    cur.execute("""
      SELECT license_key_hash, COUNT(*) AS c
      FROM usage
      WHERE license_key_hash NOT IN ('TELEGRAM')
      GROUP BY license_key_hash
      ORDER BY c DESC
      LIMIT ?
    """, (int(limit),))
    rows = cur.fetchall()

    trs = ""
    for r in rows:
        trs += f"""
        <tr>
          <td style="font-family:monospace">{r['license_key_hash']}</td>
          <td>{r['c']}</td>
          <td><a href="/panel/usage{qs}&license_hash={r['license_key_hash']}">ver logs</a></td>
        </tr>
        """

    html = f"""
    <div class="card">
      <b>Navegação:</b>
      <div style="margin-top:8px; display:flex; gap:12px; flex-wrap:wrap;">
        <a href="/panel{qs}">Home</a>
        <a href="/panel/licenses{qs}">Licenças</a>
        <a href="/panel/usage{qs}">Uso (logs)</a>
        <a href="/panel/usage_by_license{qs}">Uso por licença</a>
      </div>
    </div>

    <div class="card">
      <h2 style="margin:0 0 12px 0">Uso por licença</h2>
      <table>
        <thead>
          <tr>
            <th>License Hash</th>
            <th>Eventos</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {trs or "<tr><td colspan='3'>Sem dados ainda.</td></tr>"}
        </tbody>
      </table>
    </div>
    """
    return HTMLResponse(_panel_layout("Uso por licença", html))

# ================== TELEGRAM WEBHOOK ==================
@core.post("/webhooks/telegram")
async def telegram_webhook(update: dict = Body(...), request: Request = None):
    # valida secret do Telegram (setWebhook)
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

    # mensagem normal
    message = update.get("message") or update.get("edited_message")
    if message and message.get("chat"):
        chat_id = message["chat"]["id"]
        text = (message.get("text") or "").strip()
        telegram_id = str(chat_id)

        if text.startswith("/start"):
            clear_tg_state(telegram_id)
            tg_send(chat_id, WELCOME_COPY, reply_markup=tg_menu_keyboard())
            return {"ok": True}

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

            pay = mp_create_pix(service=service, telegram_id=telegram_id, payer_email=text)
            payment_id = str(pay.get("id"))

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

        tg_send(chat_id, "Digite /start para ver os produtos.")
        return {"ok": True}

    # callback (botões)
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

# ================== LICENÇA / CRÉDITOS ==================
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

    payment_id = (body.get("data") or {}).get("id")
    if not payment_id:
        return {"status": "ignored"}

    code, payment = mp_get_payment(str(payment_id))
    if code >= 400:
        return {"status": "mp_error", "http": code, "payment_id": payment_id, "mp": payment}

    status = payment.get("status") or ""
    ext_ref = payment.get("external_reference") or ""

    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "UPDATE orders SET mp_status=?, updated_at=? WHERE mp_payment_id=?",
        (status, now_utc_str(), str(payment_id)),
    )
    conn.commit()

    if status != "approved":
        return {"status": status, "payment_id": payment_id}

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

    cur.execute("SELECT license_key FROM orders WHERE mp_payment_id=?", (str(payment_id),))
    row = cur.fetchone()
    if row and row["license_key"]:
        return {"status": "already_delivered", "payment_id": payment_id}

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

# ================== INCLUDE ROUTERS ==================
app.include_router(core)
app.include_router(admin, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("tribotools_api:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
