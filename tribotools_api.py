#!/usr/bin/env python
# coding: utf-8

# In[10]:


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TriboTools API — licenças com ativação 30d + métricas/uso
- 1 chave = 1 máquina (por padrão via max_devices=1)
- Ativa na 1ª vez (gera token, amarra device_id/fingerprint, expira em 30d)
- Próximas execuções validam por token+device_id (sem pedir chave)
- Admin pode criar licença e travar/destravar ('active' | 'inactive')
- Telemetria de uso (/usage) e estatísticas em /stats
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3, hashlib, uuid, json, os, threading

API_VERSION = "1.3.1"

# ===== DB =====
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR / "licenses.db").resolve()
DB_PATH = os.getenv("LICENSE_DB", str(DEFAULT_DB))

_conn = None
_conn_lock = threading.Lock()

def _connect_once() -> sqlite3.Connection:
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

def _exec(conn: sqlite3.Connection, sql: str, params: tuple = ()):
    cur = conn.cursor()
    cur.execute(sql, params)
    conn.commit()
    return cur

def ensure_schema(conn: sqlite3.Connection):
    # Tabela de licenças (admin controla status e limite de dispositivos)
    _exec(conn, """
        CREATE TABLE IF NOT EXISTS license (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT UNIQUE,
            status TEXT DEFAULT 'active',      -- 'active' | 'inactive'
            max_devices INTEGER DEFAULT 1,
            created_at TEXT
        )
    """)
    # Ativações (vincula chave à máquina)
    _exec(conn, """
        CREATE TABLE IF NOT EXISTS activation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT,
            device_id TEXT,
            token TEXT,
            fingerprint TEXT,                 -- JSON com hostname, mac, uuid etc
            activated_at TEXT,
            expires_at TEXT,
            UNIQUE(license_key_hash, device_id)
        )
    """)
    # Telemetria de uso
    _exec(conn, """
        CREATE TABLE IF NOT EXISTS usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            license_key_hash TEXT,
            device_id TEXT,
            event TEXT,      -- 'run', 'run_start', 'run_done', 'activate', 'validate_ok', 'validate_expired', 'renew'
            meta TEXT
        )
    """)
    _exec(conn, "CREATE INDEX IF NOT EXISTS idx_license_hash ON license(license_key_hash)")
    _exec(conn, "CREATE INDEX IF NOT EXISTS idx_activation_hash ON activation(license_key_hash)")
    _exec(conn, "CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage(ts)")
    _exec(conn, "CREATE INDEX IF NOT EXISTS idx_usage_license ON usage(license_key_hash)")
    _exec(conn, "CREATE INDEX IF NOT EXISTS idx_usage_device ON usage(device_id)")

def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
    return cur.fetchone() is not None

def require_license_table(conn: sqlite3.Connection):
    if not table_exists(conn, "license"):
        raise HTTPException(status_code=500, detail="Banco de licenças não inicializado.")

# ===== APP =====
app = FastAPI(title="TriboTools License API", version=API_VERSION)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def _startup():
    conn = _connect_once()
    ensure_schema(conn)

# ===== HELPERS =====
def _get_license(conn: sqlite3.Connection, lic_hash: str):
    cur = _exec(conn, "SELECT * FROM license WHERE license_key_hash=?", (lic_hash,))
    return cur.fetchone()

def _license_must_exist_and_active(conn: sqlite3.Connection, lic_hash: str):
    row = _get_license(conn, lic_hash)
    if not row:
        raise HTTPException(status_code=404, detail="Licença inválida.")
    if (row["status"] or "") != "active":
        raise HTTPException(status_code=403, detail="Licença inativa.")
    return row

def _count_activations(conn: sqlite3.Connection, lic_hash: str) -> int:
    cur = _exec(conn, "SELECT COUNT(*) AS c FROM activation WHERE license_key_hash=?", (lic_hash,))
    return cur.fetchone()["c"]

def _insert_usage(conn: sqlite3.Connection, lic_hash: str, device_id: str, event: str, meta: dict | None = None):
    _exec(conn,
          "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
          (now_utc_str(), lic_hash, device_id, event, json.dumps(meta or {}, ensure_ascii=False)))

# ===== ENDPOINTS PÚBLICOS =====
@app.get("/")
def home():
    return {"status": "ok", "msg": "API TriboTools rodando.", "version": API_VERSION, "db_path": DB_PATH}

@app.get("/healthz")
def healthz():
    conn = _connect_once()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('license','activation','usage')")
    tables = [r["name"] for r in cur.fetchall()]
    total = None
    if "license" in tables:
        cur.execute("SELECT COUNT(1) AS c FROM license")
        total = cur.fetchone()["c"]
    return {"ok": True, "db_path": DB_PATH, "tables": tables, "licenses_in_license": total}

@app.post("/activate")
def activate(data: dict):
    license_key = (data.get("license_key") or "").strip()
    device_id   = (data.get("device_id") or "").strip()
    fingerprint = data.get("fingerprint", {})

    if not license_key or not device_id:
        raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes.")

    lic_hash = sha256(license_key)
    conn = _connect_once()
    ensure_schema(conn)  # garante todas as tabelas

    lic = _license_must_exist_and_active(conn, lic_hash)
    max_devices = int(lic["max_devices"] or 1)

    # Já existe ativação para ESTA máquina?
    cur = _exec(conn, "SELECT * FROM activation WHERE license_key_hash=? AND device_id=?", (lic_hash, device_id))
    row = cur.fetchone()
    token = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

    if row:
        # Mantém activated_at, renova token/expiração
        _exec(conn, "UPDATE activation SET token=?, expires_at=?, fingerprint=? WHERE id=?",
              (token, expires_at, json.dumps(fingerprint, ensure_ascii=False), row["id"]))
        _insert_usage(conn, lic_hash, device_id, "activate", {"mode": "already_had_activation"})
        return {"status": "ok", "token": token, "expires_at": expires_at, "max_devices": max_devices}

    # Limite de dispositivos
    qtd = _count_activations(conn, lic_hash)
    if qtd >= max_devices:
        # se outra máquina usa, bloqueia (1 chave = 1 máquina por padrão)
        raise HTTPException(status_code=403, detail="Licença já está em uso em outro computador.")

    # Cria nova ativação (1ª vez)
    _exec(conn, """
        INSERT INTO activation (license_key_hash, device_id, token, fingerprint, activated_at, expires_at)
        VALUES (?,?,?,?,?,?)
    """, (lic_hash, device_id, token, json.dumps(fingerprint, ensure_ascii=False), now_utc_str(), expires_at))
    _insert_usage(conn, lic_hash, device_id, "activate", {"mode": "first_time"})
    return {"status": "ok", "token": token, "expires_at": expires_at, "max_devices": max_devices}

@app.post("/validate")
def validate(data: dict):
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(status_code=400, detail="Token e device_id são obrigatórios.")

    conn = _connect_once()
    cur = _exec(conn, "SELECT license_key_hash, expires_at FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    if not row:
        return {"valid": False, "reason": "Token não encontrado."}

    # Se licença foi travada após ativação, invalida
    lic = _get_license(conn, row["license_key_hash"])
    if not lic or (lic["status"] or "") != "active":
        _insert_usage(conn, row["license_key_hash"], device_id, "validate_expired", {"reason": "license_inactive"})
        return {"valid": False, "reason": "Licença inativa."}

    exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
    valid = datetime.utcnow() <= exp
    _insert_usage(conn, row["license_key_hash"], device_id, "validate_ok" if valid else "validate_expired", {})
    if not valid:
        return {"valid": False, "reason": "Token expirado."}
    return {"valid": True, "reason": "Token válido."}

@app.post("/renew")
def renew(data: dict):
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(status_code=400, detail="Campos obrigatórios ausentes.")

    conn = _connect_once()
    cur = _exec(conn, "SELECT id, license_key_hash FROM activation WHERE token=? AND device_id=?", (token, device_id))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Ativação não encontrada.")

    # exige licença ativa
    lic = _get_license(conn, row["license_key_hash"])
    if not lic or (lic["status"] or "") != "active":
        raise HTTPException(status_code=403, detail="Licença inativa.")

    new_exp = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    _exec(conn, "UPDATE activation SET expires_at=? WHERE id=?", (new_exp, row["id"]))
    _insert_usage(conn, row["license_key_hash"], device_id, "renew", {"new_expires_at": new_exp})
    return {"status": "ok", "new_expires_at": new_exp}

@app.post("/usage")
def add_usage(data: dict):
    lic_hash = (data.get("license_key_hash") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    event = (data.get("event") or "run").strip()
    meta = json.dumps(data.get("meta", {}), ensure_ascii=False)
    if not lic_hash or not device_id:
        raise HTTPException(status_code=400, detail="license_key_hash e device_id obrigatórios.")
    conn = _connect_once()
    _exec(conn,
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
        (now_utc_str(), lic_hash, device_id, event, meta)
    )
    return {"status": "ok"}

# ===== ENDPOINTS ADMIN =====
@app.post("/license/create")
def license_create(data: dict):
    """
    Body: { "license_key": "...", "max_devices": 1, "status": "active" }
    """
    license_key = (data.get("license_key") or "").strip()
    if not license_key:
        raise HTTPException(status_code=400, detail="license_key obrigatório.")
    max_devices = int(data.get("max_devices") or 1)
    status = (data.get("status") or "active").strip()

    lic_hash = sha256(license_key)
    conn = _connect_once()
    now = now_utc_str()
    _exec(conn, """
        INSERT INTO license (license_key_hash, status, max_devices, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(license_key_hash) DO UPDATE SET
            status=excluded.status,
            max_devices=excluded.max_devices
    """, (lic_hash, status, max_devices, now))
    return {"status": "ok", "license_key_hash": lic_hash, "max_devices": max_devices, "saved_status": status}

@app.post("/license/status")
def license_set_status(data: dict):
    """
    Body: { "license_key": "...", "status": "active" | "inactive" }
       ou { "license_key_hash": "...", "status": ... }
    """
    status = (data.get("status") or "").strip()
    if status not in ("active", "inactive"):
        raise HTTPException(status_code=400, detail="status inválido (use 'active' ou 'inactive').")

    lic_hash = (data.get("license_key_hash") or "").strip()
    if not lic_hash:
        license_key = (data.get("license_key") or "").strip()
        if not license_key:
            raise HTTPException(status_code=400, detail="Informe license_key ou license_key_hash.")
        lic_hash = sha256(license_key)

    conn = _connect_once()
    cur = _exec(conn, "UPDATE license SET status=? WHERE license_key_hash=?", (status, lic_hash))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Licença não encontrada.")
    return {"status": "ok", "license_key_hash": lic_hash, "new_status": status}

@app.get("/licenses")
def list_licenses():
    conn = _connect_once()
    ensure_schema(conn)
    cur = _exec(conn, "SELECT license_key_hash, status, max_devices, created_at FROM license ORDER BY id DESC")
    rows = cur.fetchall()
    return {"count": len(rows), "licenses": [dict(r) for r in rows]}

@app.get("/activations")
def list_activations(limit: int = 100, license_key_hash: str = None):
    conn = _connect_once()
    if license_key_hash:
        cur = _exec(conn, """
            SELECT id, license_key_hash, device_id, token, activated_at, expires_at, fingerprint
            FROM activation
            WHERE license_key_hash=?
            ORDER BY id DESC
            LIMIT ?
        """, (license_key_hash, max(1, min(limit, 1000))))
    else:
        cur = _exec(conn, """
            SELECT id, license_key_hash, device_id, token, activated_at, expires_at, fingerprint
            FROM activation
            ORDER BY id DESC
            LIMIT ?
        """, (max(1, min(limit, 1000)),))
    rows = cur.fetchall()
    return {"rows": [dict(r) for r in rows]}

@app.get("/stats")
def stats():
    conn = _connect_once()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS c FROM license")
    total_licenses = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) AS c FROM activation WHERE datetime(expires_at) > datetime('now')")
    active_activations = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(DISTINCT device_id) AS c FROM activation WHERE datetime(expires_at) > datetime('now')")
    unique_devices = cur.fetchone()["c"]

    cur.execute("""
        SELECT COUNT(*) AS c
        FROM activation
        WHERE datetime(expires_at) BETWEEN datetime('now') AND datetime('now','+7 days')
    """)
    expiring_7d = cur.fetchone()["c"]

    cur.execute("""
        SELECT COUNT(*) AS c
        FROM usage
        WHERE datetime(ts) > datetime('now','-1 day')
    """)
    usage_24h = cur.fetchone()["c"]

    cur.execute("""
        SELECT COUNT(*) AS c
        FROM usage
        WHERE event IN ('run','run_start','run_done')
          AND datetime(ts) > datetime('now','-1 day')
    """)
    runs_24h = cur.fetchone()["c"]

    return {
        "total_licenses": total_licenses,
        "active_activations": active_activations,
        "unique_devices": unique_devices,
        "expiring_7d":   expiring_7d,
        "usage_24h":     usage_24h,
        "runs_24h":      runs_24h,
    }

# Exec local (opcional)
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("tribotools_api:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))


# In[ ]:




