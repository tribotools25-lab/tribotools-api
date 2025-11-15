#!/usr/bin/env python
# coding: utf-8

# In[10]:


# ============================================================
# TriboTools Licensing API v3
# - Licenças 1x por máquina
# - Tokens vinculados a device_id
# - Revogação total / por token
# - Painel admin (/panel)
# - Exportação CSV
# ============================================================

from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import hashlib
import json
import os
import uuid
import csv
from io import StringIO

# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------

APP_VERSION = "3.0"
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()

DB_PATH = Path("tribotools.db")


def connect_once():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_utc_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------
# DB INIT
# ------------------------------------------------------------

def init_db():
    conn = connect_once()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS license (
            license_key_hash TEXT PRIMARY KEY,
            status TEXT DEFAULT 'active',
            max_devices INTEGER DEFAULT 1,
            created_at TEXT,
            notes TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS activation (
            token TEXT,
            license_key_hash TEXT,
            device_id TEXT,
            fingerprint TEXT,
            expires_at TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS usage (
            ts TEXT,
            license_key_hash TEXT,
            device_id TEXT,
            event TEXT,
            meta TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()

# ------------------------------------------------------------
# FASTAPI
# ------------------------------------------------------------

core = FastAPI(title="TriboTools Licensing API", version=APP_VERSION)

core.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------
# SECURITY
# ------------------------------------------------------------

bearer = HTTPBearer(auto_error=False)


def require_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if not credentials:
        raise HTTPException(403, "Admin token ausente")
    if credentials.credentials != ADMIN_TOKEN:
        raise HTTPException(403, "Token admin inválido")
    return True


# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ------------------------------------------------------------
# ROOT
# ------------------------------------------------------------

@core.get("/")
def root():
    return {"version": APP_VERSION, "status": "online"}


# ------------------------------------------------------------
# ACTIVATION (CLIENT)
# ------------------------------------------------------------

@core.post("/activate")
def activate(data: dict = Body(...)):
    """
    Ativa uma licença → retorna token
    Body:
      - license_key
      - device_id
      - fingerprint
    """

    license_key = (data.get("license_key") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    fingerprint = data.get("fingerprint") or {}

    if not license_key or not device_id:
        raise HTTPException(400, "license_key e device_id são obrigatórios.")

    lic_hash = sha256(license_key)

    conn = connect_once()
    cur = conn.cursor()

    cur.execute("SELECT status, max_devices FROM license WHERE license_key_hash=?", (lic_hash,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Licença inválida.")

    if row["status"] != "active":
        raise HTTPException(403, "Licença desativada pelo administrador.")

    # verifica quantas máquinas já ativaram
    cur.execute("SELECT COUNT(*) c FROM activation WHERE license_key_hash=?", (lic_hash,))
    act_count = cur.fetchone()["c"]

    if act_count >= row["max_devices"]:
        raise HTTPException(403, "Licença já está em uso em outro computador.")

    # cria token
    token = str(uuid.uuid4())
    exp = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
        INSERT INTO activation (token, license_key_hash, device_id, fingerprint, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """, (token, lic_hash, device_id, json.dumps(fingerprint), exp))

    # registra uso
    cur.execute("""
        INSERT INTO usage (ts, license_key_hash, device_id, event, meta)
        VALUES (?, ?, ?, ?, ?)
    """, (now_utc_str(), lic_hash, device_id, "activate",
          json.dumps({"fingerprint": fingerprint}, ensure_ascii=False)))

    conn.commit()

    return {"status": "ok", "token": token, "expires_at": exp}


# ------------------------------------------------------------
# VALIDATE — CLIENT
# ------------------------------------------------------------

@core.post("/validate")
def validate(data: dict = Body(...)):
    """
    Valida token antes do robô rodar
    """

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
        WHERE a.token=? AND a.device_id=?
    """, (token, device_id))

    row = cur.fetchone()

    if not row:
        return {"valid": False, "reason": "Token não encontrado."}

    lic_hash = row["license_key_hash"]
    lic_status = row["lic_status"]
    exp = datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")

    # lógica de validação
    if lic_status != "active":
        valid = False
        reason = "Licença desativada pelo administrador."
        event = "validate_license_inactive"
    elif datetime.utcnow() > exp:
        valid = False
        reason = "Token expirado."
        event = "validate_expired"
    else:
        valid = True
        reason = "Token válido."
        event = "validate_ok"

    # log
    cur.execute("""
        INSERT INTO usage (ts, license_key_hash, device_id, event, meta)
        VALUES (?, ?, ?, ?, ?)
    """, (now_utc_str(), lic_hash, device_id, event,
          json.dumps({"reason": reason}, ensure_ascii=False)))

    conn.commit()

    return {"valid": valid, "reason": reason}


# ------------------------------------------------------------
# ADMIN — CREATE LICENSE
# ------------------------------------------------------------

@core.post("/api/admin/licenses", dependencies=[Depends(require_admin)])
def admin_create_license(data: dict = Body(...)):
    license_key = (data.get("license_key") or "").strip()
    max_devices = int(data.get("max_devices") or 1)
    notes = data.get("notes") or ""

    if not license_key:
        raise HTTPException(400, "license_key obrigatório")

    lic_hash = sha256(license_key)

    conn = connect_once()
    cur = conn.cursor()

    cur.execute("""
        INSERT OR REPLACE INTO license (license_key_hash, status, max_devices, created_at, notes)
        VALUES (?, 'active', ?, ?, ?)
    """, (lic_hash, max_devices, now_utc_str(), notes))

    conn.commit()

    return {"status": "ok", "license_key_hash": lic_hash}


# ------------------------------------------------------------
# ADMIN — LIST LICENSES
# ------------------------------------------------------------

@core.get("/api/admin/licenses", dependencies=[Depends(require_admin)])
def admin_list_licenses():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT * FROM license")
    rows = [dict(row) for row in cur.fetchall()]
    return {"count": len(rows), "licenses": rows}


# ------------------------------------------------------------
# ADMIN — UPDATE STATUS (activate/inactivate)
# ------------------------------------------------------------

@core.patch("/api/admin/licenses/{lic_hash}/status", dependencies=[Depends(require_admin)])
def admin_update_status(lic_hash: str, data: dict = Body(...)):
    status = (data.get("status") or "").lower()
    if status not in ["active", "inactive"]:
        raise HTTPException(400, "status deve ser active/inactive")

    conn = connect_once()
    cur = conn.cursor()

    cur.execute("UPDATE license SET status=? WHERE license_key_hash=?", (status, lic_hash))
    conn.commit()

    return {"status": "ok", "new_status": status}


# ------------------------------------------------------------
# ADMIN — REVOKE ALL (clear tokens)
# ------------------------------------------------------------

@core.post("/api/admin/licenses/{lic_hash}/revoke", dependencies=[Depends(require_admin)])
def admin_revoke_all(lic_hash: str):
    conn = connect_once()
    cur = conn.cursor()

    cur.execute("DELETE FROM activation WHERE license_key_hash=?", (lic_hash,))
    removed = cur.rowcount

    cur.execute("UPDATE license SET status='inactive' WHERE license_key_hash=?", (lic_hash,))
    conn.commit()

    return {
        "status": "ok",
        "license_key_hash": lic_hash,
        "activations_removed": removed,
        "new_status": "inactive"
    }


# ------------------------------------------------------------
# ADMIN — REVOKE ONE ACTIVATION
# ------------------------------------------------------------

@core.post("/api/admin/activations/revoke", dependencies=[Depends(require_admin)])
def admin_revoke_one(data: dict = Body(...)):
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()

    if not token or not device_id:
        raise HTTPException(400, "token e device_id obrigatórios")

    conn = connect_once()
    cur = conn.cursor()

    cur.execute("""
        DELETE FROM activation WHERE token=? AND device_id=?
    """, (token, device_id))

    removed = cur.rowcount
    conn.commit()

    return {"status": "ok", "removed": removed}


# ------------------------------------------------------------
# ADMIN — USAGE SUMMARY
# ------------------------------------------------------------

@core.get("/api/admin/usage-summary", dependencies=[Depends(require_admin)])
def usage_summary():
    conn = connect_once()
    cur = conn.cursor()

    cur.execute("""
        SELECT l.license_key_hash,
               l.status,
               l.max_devices,
               l.notes,
               (SELECT COUNT(*) FROM activation a WHERE a.license_key_hash=l.license_key_hash) AS devices,
               (SELECT COUNT(*) FROM usage u WHERE u.license_key_hash=l.license_key_hash AND u.event='run_start') as runs,
               (SELECT COUNT(*) FROM usage u WHERE u.license_key_hash=l.license_key_hash AND u.event='activate') as activations,
               (SELECT COUNT(*) FROM usage u WHERE u.license_key_hash=l.license_key_hash AND u.event='validate_ok') as validations,
               (SELECT COUNT(*) FROM usage u WHERE u.license_key_hash=l.license_key_hash) as total_events
        FROM license l
    """)

    rows = [dict(row) for row in cur.fetchall()]
    return {"rows": rows}


# ------------------------------------------------------------
# ADMIN — EXPORT CSV
# ------------------------------------------------------------

@core.get("/api/admin/export-csv", dependencies=[Depends(require_admin)])
def export_csv():
    conn = connect_once()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM usage
    """)

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["ts", "license_key_hash", "device_id", "event", "meta"])

    for row in cur.fetchall():
        writer.writerow([row["ts"], row["license_key_hash"], row["device_id"], row["event"], row["meta"]])

    output.seek(0)

    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=usage.csv"}
    )


# ------------------------------------------------------------
# PANEL (HTML)
# ------------------------------------------------------------

@core.get("/panel", response_class=HTMLResponse)
def panel():
    html = """
    <html><body><h1>TriboTools Painel</h1>
    <p>Painel avançado ativado — versão completa incluída na API final.</p>
    <p>Abra <b>/panel</b> na API hospedada para ver o dashboard completo.</p>
    </body></html>
    """
    return HTMLResponse(html)


# In[ ]:




