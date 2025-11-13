#!/usr/bin/env python
# coding: utf-8

# In[10]:


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TriboTools License API
- Ativação por 30 dias a partir da primeira ativação
- 1 licença pode ter N dispositivos (default=1). Para "1 máquina", deixe max_devices=1
- Token salvo no cliente: validado em /validate (não precisa digitar chave novamente)
- Métricas de uso (/usage)
- Travar/destravar licença (status active/inactive)
- Endpoints espelhados em / e /api (compatível com seu painel HTML)

ENV:
  LICENSE_DB   -> caminho do sqlite (default: ./licenses.db)
  ADMIN_TOKEN  -> token para rotas administrativas (Bearer)
"""

from __future__ import annotations
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRouter
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3, hashlib, uuid, json, os, threading, typing as t
import secrets, string  # para geração de chaves

API_VERSION = "TT-1.0.0"

# ===== ENV/DB =====
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR / "licenses.db").resolve()
DB_PATH = os.getenv("LICENSE_DB", str(DEFAULT_DB))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()

_conn: sqlite3.Connection | None = None
_conn_lock = threading.Lock()

def connect_once() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        with _conn_lock:
            if _conn is None:
                # garante diretório do DB
                Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
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
    # tabela de licenças (hash only)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS license (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT UNIQUE,
            status TEXT DEFAULT 'active',     -- 'active' | 'inactive'
            max_devices INTEGER DEFAULT 1,
            notes TEXT,
            created_at TEXT
        )
    """)
    # ativações (device bind + 30d)
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
    # métricas
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            license_key_hash TEXT,
            device_id TEXT,
            event TEXT,      -- 'run','activate','validate_ok','validate_expired','renew'
            meta TEXT
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_license ON usage(license_key_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_device ON usage(device_id)")
    conn.commit()

# ===== Auth admin =====
def require_admin(authorization: t.Optional[str] = Header(None)):
    if not ADMIN_TOKEN:
        raise HTTPException(500, detail="ADMIN_TOKEN não configurado no servidor.")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, detail="Bearer token ausente.")
    token = authorization.split(" ", 1)[1].strip()
    if token != ADMIN_TOKEN:
        raise HTTPException(403, detail="Token inválido.")
    return True

# ===== Geração de chaves =====
def gen_license_key(prefix: str = "TT", size: int = 16) -> str:
    alphabet = string.ascii_uppercase + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(size))
    parts = [body[i:i+4] for i in range(0, len(body), 4)]
    return f"{prefix}-" + "-".join(parts)

# ===== App & Routers =====
app = FastAPI(title="TriboTools License API", version=API_VERSION)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

core = APIRouter()
admin = APIRouter(prefix="/admin")

@app.on_event("startup")
def _startup():
    init_db()

# ========== CORE ==========
@core.get("/")
def home():
    return {"status": "ok", "msg": "API TriboTools rodando.", "version": API_VERSION, "db_path": DB_PATH}

@core.get("/healthz")
def healthz():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r["name"] for r in cur.fetchall()]
    # compatível com seu painel antigo
    total = None
    if "license" in tables:
        cur.execute("SELECT COUNT(1) AS c FROM license")
        total = cur.fetchone()["c"]
    return {"ok": True, "db_path": DB_PATH, "tables": tables, "licenses_in_license": total}

@core.post("/activate")
def activate(data: dict):
    """
    body: { license_key, device_id, fingerprint }
    Regras:
     - licença deve existir e estar 'active'
     - respeita max_devices (se atingido, só reusa mesmo device_id)
     - gera token + expires_at = agora + 30d
    """
    license_key = (data.get("license_key") or "").strip()
    device_id   = (data.get("device_id") or "").strip()
    fingerprint = data.get("fingerprint", {})

    if not license_key or not device_id:
        raise HTTPException(400, "Campos obrigatórios: license_key, device_id")

    lic_hash = sha256(license_key)
    conn = connect_once(); cur = conn.cursor()

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
    expires_at = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
        INSERT OR REPLACE INTO activation
            (license_key_hash, device_id, token, fingerprint, activated_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (lic_hash, device_id, token, json.dumps(fingerprint, ensure_ascii=False), now_utc_str(), expires_at))
    conn.commit()

    cur.execute("INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
                (now_utc_str(), lic_hash, device_id, "activate", "{}"))
    conn.commit()

    return {"status": "ok", "token": token, "expires_at": expires_at, "max_devices": max_devices}

@core.post("/validate")
def validate(data: dict):
    """
    body: { token, device_id }
    """
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(400, "Token e device_id são obrigatórios.")

    conn = connect_once(); cur = conn.cursor()
    cur.execute("SELECT license_key_hash, expires_at FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    if not row:
        return {"valid": False, "reason": "Token não encontrado."}

    exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    valid = datetime.utcnow() <= exp

    cur.execute("INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
                (now_utc_str(), row["license_key_hash"], device_id, "validate_ok" if valid else "validate_expired", "{}"))
    conn.commit()

    if not valid:
        return {"valid": False, "reason": "Token expirado."}
    return {"valid": True, "reason": "Token válido."}

@core.post("/renew")
def renew(data: dict):
    """
    body: { token, device_id }
    """
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(400, "Campos obrigatórios: token, device_id.")

    conn = connect_once(); cur = conn.cursor()
    cur.execute("SELECT license_key_hash FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Ativação não encontrada.")

    new_exp = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("UPDATE activation SET expires_at=? WHERE token=?", (new_exp, token))
    conn.commit()

    cur.execute("INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
                (now_utc_str(), row["license_key_hash"], device_id, "renew", json.dumps({"new_expires_at": new_exp})))
    conn.commit()

    return {"status": "ok", "new_expires_at": new_exp}

# ========== LISTAGENS (compatíveis com seu painel) ==========
@core.get("/licenses")
def list_licenses():
    conn = connect_once(); cur = conn.cursor()
    cur.execute("SELECT license_key_hash, status, max_devices FROM license ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    return {"count": len(rows), "licenses": rows}

@core.get("/activations")
def list_activations(limit: int = 100):
    conn = connect_once(); cur = conn.cursor()
    cur.execute("""
        SELECT id, license_key_hash, device_id, token, activated_at, expires_at
        FROM activation
        ORDER BY id DESC
        LIMIT ?
    """, (max(1, min(limit, 1000)),))
    rows = [dict(r) for r in cur.fetchall()]
    return {"rows": rows}

@core.get("/activations/by-license/{lic_hash}")
def activations_by_license(lic_hash: str, limit: int = 200):
    conn = connect_once(); cur = conn.cursor()
    cur.execute("""
        SELECT id, device_id, token, activated_at, expires_at
        FROM activation
        WHERE license_key_hash=?
        ORDER BY id DESC
        LIMIT ?
    """, (lic_hash, max(1, min(limit, 2000))))
    rows = [dict(r) for r in cur.fetchall()]
    return {"license_key_hash": lic_hash, "rows": rows}

@core.post("/usage")
def add_usage(data: dict):
    """
    body: { license_key_hash, device_id, event='run', meta: {...} }
    (o cliente calcula o hash localmente a partir da chave)
    """
    lic_hash = (data.get("license_key_hash") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    event = (data.get("event") or "run").strip()
    meta = json.dumps(data.get("meta", {}), ensure_ascii=False)
    if not lic_hash or not device_id:
        raise HTTPException(400, "license_key_hash e device_id obrigatórios.")
    conn = connect_once(); cur = conn.cursor()
    cur.execute("INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
                (now_utc_str(), lic_hash, device_id, event, meta))
    conn.commit()
    return {"status": "ok"}

@core.get("/stats")
def stats():
    conn = connect_once(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM license")
    total_licenses = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM activation WHERE datetime(expires_at) > datetime('now')")
    active_activations = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(DISTINCT device_id) AS c FROM activation WHERE datetime(expires_at) > datetime('now')")
    unique_devices = cur.fetchone()["c"]
    cur.execute("""
        SELECT COUNT(*) AS c FROM activation
        WHERE datetime(expires_at) BETWEEN datetime('now') AND datetime('now','+7 days')
    """)
    expiring_7d = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM usage WHERE datetime(ts) > datetime('now','-1 day')")
    usage_24h = cur.fetchone()["c"]
    return {
        "total_licenses": total_licenses,
        "active_activations": active_activations,
        "unique_devices": unique_devices,
        "expiring_7d": expiring_7d,
        "usage_24h": usage_24h,
    }

# ========== ADMIN ==========
@admin.get("/ping")
def admin_ping(_: bool = Depends(require_admin)):
    return {"ok": True, "version": API_VERSION, "db_path": DB_PATH}

@admin.post("/license/issue")
def admin_issue_one(body: dict | None = None, _: bool = Depends(require_admin)):
    """
    Gera UMA nova licença e grava apenas o hash.
    body: {"max_devices":1, "notes":"opcional", "prefix":"TT"}
    """
    body = body or {}
    max_dev = int(body.get("max_devices", 1)) or 1
    notes   = (body.get("notes") or "").strip()
    prefix  = (body.get("prefix") or "TT").strip() or "TT"

    lk = gen_license_key(prefix=prefix, size=16)
    lic_hash = sha256(lk)

    conn = connect_once(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO license (license_key_hash, status, max_devices, notes, created_at)
        VALUES (?,?,?,?,?)
    """, (lic_hash, "active", max_dev, notes, now_utc_str()))
    conn.commit()

    return {
        "license_key": lk,                   # entregue ao cliente
        "license_key_hash": lic_hash,        # armazenado
        "status": "active",
        "max_devices": max_dev,
    }

@admin.post("/license/bulk_issue")
def admin_bulk_issue(body: dict, _: bool = Depends(require_admin)):
    """
    Gera várias licenças de uma vez.
    body: {"qty": 10, "max_devices": 1, "notes": "opc", "prefix": "TT"}
    """
    qty     = max(1, min(int(body.get("qty", 1)), 1000))
    max_dev = int(body.get("max_devices", 1)) or 1
    notes   = (body.get("notes") or "").strip()
    prefix  = (body.get("prefix") or "TT").strip() or "TT"

    conn = connect_once(); cur = conn.cursor()
    out = []
    for _ in range(qty):
        lk = gen_license_key(prefix=prefix, size=16)
        h  = sha256(lk)
        cur.execute("""
            INSERT INTO license (license_key_hash, status, max_devices, notes, created_at)
            VALUES (?,?,?,?,?)
        """, (h, "active", max_dev, notes, now_utc_str()))
        out.append({
            "license_key": lk,
            "license_key_hash": h,
            "status": "active",
            "max_devices": max_dev
        })
    conn.commit()
    return {"count": qty, "items": out}

@admin.post("/license/bulk_insert_hashes")
def admin_bulk_insert_hashes(body: dict, _: bool = Depends(require_admin)):
    """
    Importa licenças já existentes enviando SOMENTE os hashes.
    body: {"items":[{"license_key_hash":"<sha256hex>","status":"active","max_devices":1,"notes":""}, ...]}
    """
    items = body.get("items") or []
    if not isinstance(items, list) or not items:
        raise HTTPException(400, "items vazio.")

    conn = connect_once(); cur = conn.cursor()
    n = 0
    for it in items:
        h   = (it.get("license_key_hash") or "").strip()
        st  = (it.get("status") or "active").strip().lower()
        md  = int(it.get("max_devices", 1)) or 1
        nts = (it.get("notes") or "").strip()
        if len(h) != 64:
            continue
        if st not in ("active", "inactive"):
            st = "active"
        cur.execute("""
            INSERT OR REPLACE INTO license (license_key_hash, status, max_devices, notes, created_at)
            VALUES (?,?,?,?, COALESCE((SELECT created_at FROM license WHERE license_key_hash=?), ?))
        """, (h, st, md, nts, h, now_utc_str()))
        n += 1
    conn.commit()
    return {"inserted": n}

@admin.patch("/licenses/{lic_hash}/status")
def set_license_status(lic_hash: str, body: dict, _: bool = Depends(require_admin)):
    """
    body: { "status": "active" | "inactive" }
    """
    status = (body.get("status") or "").strip().lower()
    if status not in ("active","inactive"):
        raise HTTPException(400, "status deve ser 'active' ou 'inactive'")
    conn = connect_once(); cur = conn.cursor()
    cur.execute("UPDATE license SET status=? WHERE license_key_hash=?", (status, lic_hash))
    if cur.rowcount == 0:
        raise HTTPException(404, "Licença não encontrada")
    conn.commit()
    return {"status":"ok", "license_key_hash": lic_hash, "new_status": status}

@admin.get("/licenses")
def list_licenses_admin(_: bool = Depends(require_admin)):
    conn = connect_once(); cur = conn.cursor()
    cur.execute("SELECT license_key_hash, status, max_devices, created_at, notes FROM license ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    return {"count": len(rows), "licenses": rows}

@admin.post("/activations/revoke")
def admin_revoke(body: dict, _: bool = Depends(require_admin)):
    """
    Revoga ativações.
    body:  { "license_key_hash": "<hash>" }                   -> remove TODAS as ativações da licença
       ou  { "license_key_hash":"<hash>", "device_id":"ABC" } -> remove só daquele device
    """
    lic_hash = (body.get("license_key_hash") or "").strip()
    device_id = (body.get("device_id") or "").strip()
    if not lic_hash:
        raise HTTPException(400, "license_key_hash obrigatório.")

    conn = connect_once(); cur = conn.cursor()
    if device_id:
        cur.execute("DELETE FROM activation WHERE license_key_hash=? AND device_id=?", (lic_hash, device_id))
        removed = cur.rowcount
    else:
        cur.execute("DELETE FROM activation WHERE license_key_hash=?", (lic_hash,))
        removed = cur.rowcount
    conn.commit()
    return {"status":"ok", "removed": removed}

@admin.post("/maintenance/cleanup_expired")
def admin_cleanup_expired(_: bool = Depends(require_admin)):
    """
    Remove ativações expiradas (housekeeping manual).
    """
    conn = connect_once(); cur = conn.cursor()
    cur.execute("DELETE FROM activation WHERE datetime(expires_at) <= datetime('now')")
    removed = cur.rowcount
    conn.commit()
    return {"status":"ok", "expired_removed": removed}

# Monta rotas em "/" e espelha em "/api" (compatível com seu HTML)
app.include_router(core)
api = APIRouter()
api.include_router(core)
api.include_router(admin)
app.include_router(api, prefix="/api")

# Exec local (opcional)
if __name__ == "__main__":
    import uvicorn
    # já garantimos diretório do DB em connect_once(); aqui é só subir
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))


# In[ ]:




