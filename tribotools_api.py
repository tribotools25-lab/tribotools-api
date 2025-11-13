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
- Painel HTML usa rotas públicas: /healthz, /stats, /licenses, /activations
- Rotas de admin ficam em /api/admin/...

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

API_VERSION = "TT-1.0.2"

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
    # tabela de licenças
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS license (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT UNIQUE,
            status TEXT DEFAULT 'active',     -- 'active' | 'inactive'
            max_devices INTEGER DEFAULT 1,
            notes TEXT,
            created_at TEXT
        )
        """
    )
    # ativações (device bind + 30d)
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
    # métricas
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            license_key_hash TEXT,
            device_id TEXT,
            event TEXT,      -- 'run','activate','validate_ok','validate_expired','renew'
            meta TEXT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_license ON usage(license_key_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_usage_device ON usage(device_id)")
    conn.commit()


# ===== Auth admin =====
def require_admin(authorization: t.Optional[str] = Header(None)):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=500, detail="ADMIN_TOKEN não configurado no servidor.")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token ausente.")
    token = authorization.split(" ", 1)[1].strip()
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Token inválido.")
    return True


# ===== App & Routers =====
app = FastAPI(title="TriboTools License API", version=API_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

public = APIRouter()                 # rotas que o painel e os robôs usam
admin = APIRouter(prefix="/admin")   # rotas protegidas (sempre atrás de /api)


@app.on_event("startup")
def _startup():
    """
    Tenta criar a pasta do DB. Se não tiver permissão (ex: /data no Render),
    faz fallback para o caminho padrão ./licenses.db dentro do projeto.
    """
    global DB_PATH, _conn

    dbpath = Path(DB_PATH)
    dbdir = dbpath.parent

    try:
        dbdir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        # fallback: usa DEFAULT_DB dentro do projeto (normalmente gravável)
        DB_PATH = str(DEFAULT_DB)
        dbpath = Path(DB_PATH)
        dbdir = dbpath.parent
        # aqui o BASE_DIR já existe, então não precisa de mkdir
        _conn = None  # garante que o connect_once use o novo caminho

    init_db()


# ========== ROTAS PÚBLICAS (painel/robô) ==========
@public.get("/")
def home():
    return {"status": "ok", "msg": "TriboTools API rodando.", "version": API_VERSION, "db_path": DB_PATH}


@public.get("/healthz")
def healthz():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r["name"] for r in cur.fetchall()]
    return {"ok": True, "tables": tables, "db_path": DB_PATH}


# ---- CLIENTE: ativar / validar / renovar ----
@public.post("/activate")
def activate(data: dict):
    """
    body: { license_key, device_id, fingerprint? }
    """
    license_key = (data.get("license_key") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    fingerprint = data.get("fingerprint", {})

    if not license_key or not device_id:
        raise HTTPException(status_code=400, detail="Campos obrigatórios: license_key, device_id")

    lic_hash = sha256(license_key)
    conn = connect_once()
    cur = conn.cursor()

    cur.execute("SELECT status, max_devices FROM license WHERE license_key_hash=?", (lic_hash,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Licença inválida.")
    if (row["status"] or "") != "active":
        raise HTTPException(status_code=403, detail="Licença inativa.")
    max_devices = row["max_devices"] or 1

    # quantos devices já ativados
    cur.execute("SELECT COUNT(*) AS c FROM activation WHERE license_key_hash=?", (lic_hash,))
    qtd = cur.fetchone()["c"]

    if qtd >= max_devices:
        # deixa reusar na MESMA máquina, se já tiver ativado antes
        cur.execute(
            "SELECT 1 FROM activation WHERE license_key_hash=? AND device_id=?",
            (lic_hash, device_id),
        )
        if cur.fetchone() is None:
            raise HTTPException(status_code=403, detail="Licença já está em uso em outro computador.")

    token = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

    cur.execute(
        """
        INSERT OR REPLACE INTO activation
            (license_key_hash, device_id, token, fingerprint, activated_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (lic_hash, device_id, token, json.dumps(fingerprint, ensure_ascii=False), now_utc_str(), expires_at),
    )
    conn.commit()

    # log
    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
        (now_utc_str(), lic_hash, device_id, "activate", "{}"),
    )
    conn.commit()

    return {"status": "ok", "token": token, "expires_at": expires_at, "max_devices": max_devices}


@public.post("/validate")
def validate(data: dict):
    """
    body: { token, device_id }
    """
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(status_code=400, detail="Token e device_id são obrigatórios.")

    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "SELECT license_key_hash, expires_at FROM activation WHERE token=? AND device_id=?",
        (token, device_id),
    )
    row = cur.fetchone()
    if not row:
        return {"valid": False, "reason": "Token não encontrado."}

    exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    valid = datetime.utcnow() <= exp

    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
        (
            now_utc_str(),
            row["license_key_hash"],
            device_id,
            "validate_ok" if valid else "validate_expired",
            "{}",
        ),
    )
    conn.commit()

    if not valid:
        return {"valid": False, "reason": "Token expirado."}
    return {"valid": True, "reason": "Token válido."}


@public.post("/renew")
def renew(data: dict):
    """
    body: { token, device_id }
    """
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(status_code=400, detail="Campos obrigatórios: token, device_id.")

    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "SELECT license_key_hash FROM activation WHERE token=? AND device_id=?",
        (token, device_id),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Ativação não encontrada.")

    new_exp = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("UPDATE activation SET expires_at=? WHERE token=?", (new_exp, token))
    conn.commit()

    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
        (
            now_utc_str(),
            row["license_key_hash"],
            device_id,
            "renew",
            json.dumps({"new_expires_at": new_exp}),
        ),
    )
    conn.commit()

    return {"status": "ok", "new_expires_at": new_exp}


# ---- listagens para o painel (PÚBLICO) ----
@public.get("/licenses")
def list_licenses_public():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT license_key_hash, status, max_devices FROM license ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    return {"count": len(rows), "licenses": rows}


@public.get("/activations")
def list_activations(limit: int = 100):
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, license_key_hash, device_id, token, activated_at, expires_at
        FROM activation
        ORDER BY id DESC
        LIMIT ?
        """,
        (max(1, min(limit, 1000)),),
    )
    rows = [dict(r) for r in cur.fetchall()]
    return {"rows": rows}


@public.get("/stats")
def stats():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM license")
    total_licenses = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM activation WHERE datetime(expires_at) > datetime('now')")
    active_activations = cur.fetchone()["c"]
    cur.execute(
        "SELECT COUNT(DISTINCT device_id) AS c FROM activation WHERE datetime(expires_at) > datetime('now')"
    )
    unique_devices = cur.fetchone()["c"]
    cur.execute(
        """
        SELECT COUNT(*) AS c FROM activation
        WHERE datetime(expires_at) BETWEEN datetime('now') AND datetime('now','+7 days')
        """
    )
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


@public.post("/usage")
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
        raise HTTPException(status_code=400, detail="license_key_hash e device_id obrigatórios.")
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
        (now_utc_str(), lic_hash, device_id, event, meta),
    )
    conn.commit()
    return {"status": "ok"}


# ========== ROTAS ADMIN (atrás de /api/admin/...) ==========
@admin.post("/licenses")
def create_license(body: dict, _: bool = Depends(require_admin)):
    """
    body: { "license_key": "TT-XXXX-...", "max_devices": 1, "notes": "opcional" }
    Armazena APENAS o hash.
    """
    lk = (body.get("license_key") or "").strip()
    if not lk:
        raise HTTPException(status_code=400, detail="license_key obrigatório")
    max_dev = int(body.get("max_devices", 1)) or 1
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
        raise HTTPException(status_code=409, detail="Licença já existe")

    return {"status": "ok", "license_key_hash": lic_hash, "max_devices": max_dev}


@admin.patch("/licenses/{lic_hash}/status")
def set_license_status(lic_hash: str, body: dict, _: bool = Depends(require_admin)):
    """
    body: { "status": "active" | "inactive" }
    """
    status = (body.get("status") or "").strip().lower()
    if status not in ("active", "inactive"):
        raise HTTPException(status_code=400, detail="status deve ser 'active' ou 'inactive'")
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("UPDATE license SET status=? WHERE license_key_hash=?", (status, lic_hash))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Licença não encontrada")
    conn.commit()
    return {"status": "ok", "license_key_hash": lic_hash, "new_status": status}


@admin.get("/licenses")
def list_licenses_admin(_: bool = Depends(require_admin)):
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "SELECT license_key_hash, status, max_devices, created_at, notes FROM license ORDER BY id DESC"
    )
    rows = [dict(r) for r in cur.fetchall()]
    return {"count": len(rows), "licenses": rows}


# ==== monta as rotas ====
app.include_router(public)        # públicas na raiz
app.include_router(admin, prefix="/api")  # admin em /api/admin/...

# Exec local
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("tribotools_api:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))


# In[ ]:




