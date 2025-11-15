#!/usr/bin/env python
# coding: utf-8

# In[10]:


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TriboTools License API — VERSÃO FINAL

- Licença 1x por máquina (max_devices configurável por licença)
- Endpoints públicos para o robô:
    - POST /activate
    - POST /validate
    - POST /renew
    - POST /usage
    - GET  /stats
- Endpoints admin (protegidos por ADMIN_TOKEN, via Bearer):
    - POST /api/admin/licenses                (criar licença)
    - GET  /api/admin/licenses                (listar)
    - PATCH /api/admin/licenses/{lic_hash}/status  (ativar/desativar)
    - POST /api/admin/licenses/{lic_hash}/revoke   (derrubar geral)
    - POST /api/admin/activations/revoke           (derrubar 1 device)
    - GET  /api/admin/usage-summary          (resumo por licença)
    - GET  /api/admin/usage-csv              (CSV do resumo)
- Painel web em /panel com:
    - Login por token admin (salvo em localStorage)
    - Cards de métricas
    - Tabela de licenças com runs/activations/validations
    - Botões: criar, ativar/desativar, derrubar, exportar CSV
    - Campo de busca na tabela
"""

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

from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, Response

API_VERSION = "TT-1.0.5"

# ================== ENV / DB ==================

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = (BASE_DIR / "licenses.db").resolve()
DB_PATH = os.getenv("LICENSE_DB", str(DEFAULT_DB))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()

_conn: sqlite3.Connection | None = None
_conn_lock = threading.Lock()


def connect_once() -> sqlite3.Connection:
    """Singleton connection."""
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

    # Licenças (hash somente)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS license (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key_hash TEXT UNIQUE,
            status TEXT DEFAULT 'active',   -- 'active' | 'inactive'
            max_devices INTEGER DEFAULT 1,
            notes TEXT,
            created_at TEXT
        )
        """
    )

    # Ativações por dispositivo
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

    # Métricas
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
    conn.commit()


# ================== ADMIN AUTH ==================

admin_scheme = HTTPBearer(auto_error=False)


def require_admin(
    credentials: HTTPAuthorizationCredentials = Depends(admin_scheme),
):
    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="ADMIN_TOKEN não configurado no servidor.",
        )
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Bearer token ausente.")
    token = credentials.credentials.strip()
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Token inválido.")
    return True


# ================== APP / ROUTERS ==================

app = FastAPI(title="TriboTools License API", version=API_VERSION)

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


# ================== ROTAS PÚBLICAS ==================


@core.get("/")
def home():
    return {
        "status": "ok",
        "msg": "TriboTools API rodando",
        "version": API_VERSION,
        "db_path": DB_PATH,
    }


@core.get("/healthz")
def healthz():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r["name"] for r in cur.fetchall()]
    return {"ok": True, "tables": tables, "db_path": str(DB_PATH)}


# -------- LICENÇA: CLIENTE --------


@core.post("/activate")
def activate(data: dict = Body(...)):
    """
    body: { license_key, device_id, fingerprint, ... }
    - compatível com o robô (pode mandar client_version, product etc.)
    """
    license_key = (data.get("license_key") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    fingerprint = data.get("fingerprint", {})

    if not license_key or not device_id:
        raise HTTPException(400, "Campos obrigatórios: license_key, device_id")

    lic_hash = sha256(license_key)
    conn = connect_once()
    cur = conn.cursor()

    # verifica licença
    cur.execute(
        "SELECT status, max_devices FROM license WHERE license_key_hash=?",
        (lic_hash,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Licença inválida.")
    if (row["status"] or "") != "active":
        raise HTTPException(403, "Licença inativa.")
    max_devices = row["max_devices"] or 1

    # conta devices já usados
    cur.execute(
        "SELECT COUNT(*) AS c FROM activation WHERE license_key_hash=?",
        (lic_hash,),
    )
    qtd = cur.fetchone()["c"]

    if qtd >= max_devices:
        # permite reusar no MESMO device_id
        cur.execute(
            "SELECT 1 FROM activation WHERE license_key_hash=? AND device_id=?",
            (lic_hash, device_id),
        )
        if cur.fetchone() is None:
            raise HTTPException(
                403, "Licença já está em uso em outro computador."
            )

    token = str(uuid.uuid4())
    now = now_utc_str()
    expires_at = (datetime.utcnow() + timedelta(days=30)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cur.execute(
        """
        INSERT OR REPLACE INTO activation
            (license_key_hash, device_id, token, fingerprint, activated_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            lic_hash,
            device_id,
            token,
            json.dumps(fingerprint, ensure_ascii=False),
            now,
            expires_at,
        ),
    )
    conn.commit()

    # registra uso
    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) "
        "VALUES (?,?,?,?,?)",
        (
            now,
            lic_hash,
            device_id,
            "activate",
            json.dumps({"fingerprint": fingerprint}, ensure_ascii=False),
        ),
    )
    conn.commit()

    return {
        "status": "ok",
        "token": token,
        "expires_at": expires_at,
        "max_devices": max_devices,
    }


@core.post("/validate")
def validate(data: dict = Body(...)):
    """
    body: { token, device_id }
    Verifica:
      - se o token existe
      - se a licença está ativa
      - se não expirou
    """
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(400, "Token e device_id são obrigatórios.")

    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            a.license_key_hash,
            a.expires_at,
            l.status AS lic_status
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

    # Decide o resultado
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

    # Log no usage
    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) VALUES (?,?,?,?,?)",
        (
            now_utc_str(),
            lic_hash,
            device_id,
            event_name,
            json.dumps({"reason": reason}, ensure_ascii=False),
        ),
    )
    conn.commit()

    return {"valid": valid, "reason": reason}


@core.post("/renew")
def renew(data: dict = Body(...)):
    """
    body: { token, device_id }
    - opcional, se você quiser renovar 30 dias via painel/robô.
    """
    token = (data.get("token") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(400, "Campos obrigatórios: token, device_id.")

    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "SELECT license_key_hash FROM activation WHERE token=? AND device_id=?",
        (token, device_id),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Ativação não encontrada.")

    new_exp = (datetime.utcnow() + timedelta(days=30)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    cur.execute("UPDATE activation SET expires_at=? WHERE token=?", (new_exp, token))
    conn.commit()

    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) "
        "VALUES (?,?,?,?,?)",
        (
            now_utc_str(),
            row["license_key_hash"],
            device_id,
            "renew",
            json.dumps({"new_expires_at": new_exp}, ensure_ascii=False),
        ),
    )
    conn.commit()

    return {"status": "ok", "new_expires_at": new_exp}


# -------- LISTAGENS PÚBLICAS ÚTEIS --------


@core.get("/licenses")
def list_licenses_public():
    """Lista básica (sem notas) – útil para debug rápido."""
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "SELECT license_key_hash, status, max_devices "
        "FROM license ORDER BY id DESC"
    )
    rows = [dict(r) for r in cur.fetchall()]
    return {"count": len(rows), "licenses": rows}


@core.get("/activations")
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


@core.get("/activations/by-license/{lic_hash}")
def activations_by_license(lic_hash: str, limit: int = 200):
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, device_id, token, activated_at, expires_at
        FROM activation
        WHERE license_key_hash=?
        ORDER BY id DESC
        LIMIT ?
        """,
        (lic_hash, max(1, min(limit, 2000))),
    )
    rows = [dict(r) for r in cur.fetchall()]
    return {"license_key_hash": lic_hash, "rows": rows}


@core.post("/usage")
def add_usage(data: dict = Body(...)):
    """
    body: { license_key_hash, device_id, event='run', meta: {...} }
    - compatível com ping_usage do robô.
    """
    lic_hash = (data.get("license_key_hash") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    event = (data.get("event") or "run").strip()
    meta = json.dumps(data.get("meta", {}), ensure_ascii=False)
    if not lic_hash or not device_id:
        raise HTTPException(
            400, "license_key_hash e device_id obrigatórios."
        )
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO usage (ts, license_key_hash, device_id, event, meta) "
        "VALUES (?,?,?,?,?)",
        (now_utc_str(), lic_hash, device_id, event, meta),
    )
    conn.commit()
    return {"status": "ok"}


@core.get("/stats")
def stats():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM license")
    total_licenses = cur.fetchone()["c"]
    cur.execute(
        "SELECT COUNT(*) AS c FROM activation "
        "WHERE datetime(expires_at) > datetime('now')"
    )
    active_activations = cur.fetchone()["c"]
    cur.execute(
        "SELECT COUNT(DISTINCT device_id) AS c FROM activation "
        "WHERE datetime(expires_at) > datetime('now')"
    )
    unique_devices = cur.fetchone()["c"]
    cur.execute(
        """
        SELECT COUNT(*) AS c FROM activation
        WHERE datetime(expires_at) BETWEEN datetime('now')
                                      AND datetime('now','+7 days')
        """
    )
    expiring_7d = cur.fetchone()["c"]
    cur.execute(
        "SELECT COUNT(*) AS c FROM usage "
        "WHERE datetime(ts) > datetime('now','-1 day')"
    )
    usage_24h = cur.fetchone()["c"]
    return {
        "total_licenses": total_licenses,
        "active_activations": active_activations,
        "unique_devices": unique_devices,
        "expiring_7d": expiring_7d,
        "usage_24h": usage_24h,
    }


# ================== ROTAS ADMIN ==================


@admin.post("/licenses", dependencies=[Depends(require_admin)])
def create_license(body: dict = Body(...)):
    """
    body: { "license_key": "TT-XXXX", "max_devices": 1, "notes": "opcional" }
    """
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
            "INSERT INTO license (license_key_hash, status, max_devices, notes, created_at) "
            "VALUES (?,?,?,?,?)",
            (lic_hash, "active", max_dev, notes, now_utc_str()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Licença já existe")

    return {"status": "ok", "license_key_hash": lic_hash, "max_devices": max_dev}


@admin.patch("/licenses/{lic_hash}/status", dependencies=[Depends(require_admin)])
def set_license_status(lic_hash: str, body: dict = Body(...)):
    """
    body: { "status": "active" | "inactive" }
    """
    status = (body.get("status") or "").strip().lower()
    if status not in ("active", "inactive"):
        raise HTTPException(400, "status deve ser 'active' ou 'inactive'")
    conn = connect_once()
    cur = conn.cursor()
    cur.execute("UPDATE license SET status=? WHERE license_key_hash=?", (status, lic_hash))
    if cur.rowcount == 0:
        raise HTTPException(404, "Licença não encontrada")
    conn.commit()
    return {"status": "ok", "license_key_hash": lic_hash, "new_status": status}


@admin.get("/licenses", dependencies=[Depends(require_admin)])
def list_licenses_admin():
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        "SELECT license_key_hash, status, max_devices, created_at, notes "
        "FROM license ORDER BY id DESC"
    )
    rows = [dict(r) for r in cur.fetchall()]
    return {"count": len(rows), "licenses": rows}


@admin.post("/licenses/{lic_hash}/revoke", dependencies=[Depends(require_admin)])
def revoke_license(lic_hash: str):
    """
    Revoga todas as ativações dessa licença:
      - apaga tokens da tabela activation
      - marca licença como 'inactive'
    Resultado: ninguém mais valida nem reativa essa chave.
    """
    conn = connect_once()
    cur = conn.cursor()

    cur.execute("DELETE FROM activation WHERE license_key_hash = ?", (lic_hash,))
    deletadas = cur.rowcount

    cur.execute("UPDATE license SET status='inactive' WHERE license_key_hash = ?", (lic_hash,))
    conn.commit()

    return {
        "status": "ok",
        "license_key_hash": lic_hash,
        "activations_removed": deletadas,
        "new_status": "inactive",
    }


@admin.post("/activations/revoke", dependencies=[Depends(require_admin)])
def revoke_activation(body: dict = Body(...)):
    """
    Revoga UMA ativação específica.
    body: { "token": "...", "device_id": "..." }
    """
    token = (body.get("token") or "").strip()
    device_id = (body.get("device_id") or "").strip()
    if not token or not device_id:
        raise HTTPException(400, "token e device_id são obrigatórios.")

    conn = connect_once()
    cur = conn.cursor()

    cur.execute(
        "SELECT license_key_hash FROM activation WHERE token=? AND device_id=?",
        (token, device_id),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Ativação não encontrada.")

    lic_hash = row["license_key_hash"]

    cur.execute(
        "DELETE FROM activation WHERE token=? AND device_id=?",
        (token, device_id),
    )
    deletadas = cur.rowcount
    conn.commit()

    return {
        "status": "ok",
        "license_key_hash": lic_hash,
        "token": token,
        "device_id": device_id,
        "activations_removed": deletadas,
    }


@admin.get("/usage-summary", dependencies=[Depends(require_admin)])
def usage_summary():
    """
    Resumo por licença:
    - status, max_devices, notes
    - total_events
    - runs (run_start)
    - activations (activate)
    - validations (validate_ok)
    - unique_devices
    """
    conn = connect_once()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            l.license_key_hash,
            l.status,
            l.max_devices,
            COALESCE(l.notes, '') AS notes,
            COUNT(u.id)                           AS total_events,
            SUM(CASE WHEN u.event='run_start' THEN 1 ELSE 0 END) AS runs,
            SUM(CASE WHEN u.event='activate' THEN 1 ELSE 0 END)  AS activations,
            SUM(CASE WHEN u.event='validate_ok' THEN 1 ELSE 0 END) AS validations,
            COUNT(DISTINCT CASE WHEN u.device_id IS NOT NULL THEN u.device_id END) AS devices
        FROM license l
        LEFT JOIN usage u ON u.license_key_hash = l.license_key_hash
        GROUP BY l.license_key_hash, l.status, l.max_devices, l.notes
        ORDER BY runs DESC, activations DESC, l.license_key_hash ASC
        """
    )
    rows = []
    for r in cur.fetchall():
        rows.append(
            {
                "license_key_hash": r["license_key_hash"],
                "status": r["status"],
                "max_devices": r["max_devices"],
                "notes": r["notes"],
                "total_events": r["total_events"] or 0,
                "runs": r["runs"] or 0,
                "activations": r["activations"] or 0,
                "validations": r["validations"] or 0,
                "devices": r["devices"] or 0,
            }
        )
    return {"rows": rows, "count": len(rows)}


@admin.get("/usage-csv", dependencies=[Depends(require_admin)])
def usage_csv():
    """
    Exporta o mesmo resumo do usage-summary em CSV.
    """
    summary = usage_summary()  # já faz a query
    rows: list[dict] = summary["rows"]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "license_key_hash",
            "status",
            "max_devices",
            "devices",
            "runs",
            "activations",
            "validations",
            "total_events",
            "notes",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r["license_key_hash"],
                r["status"],
                r["max_devices"],
                r["devices"],
                r["runs"],
                r["activations"],
                r["validations"],
                r["total_events"],
                (r["notes"] or "").replace("\n", " ").replace("\r", " "),
            ]
        )

    csv_bytes = output.getvalue().encode("utf-8-sig")
    headers = {
        "Content-Disposition": 'attachment; filename="tribotools_usage_summary.csv"'
    }
    return Response(content=csv_bytes, media_type="text/csv", headers=headers)


# ================== PAINEL HTML ==================


@core.get("/panel", response_class=HTMLResponse)
def panel():
    """
    Painel visual:
    - salva ADMIN_TOKEN em localStorage
    - mostra stats
    - mostra resumo de uso por licença
    - cria nova licença
    - exporta CSV de usage-summary
    - campo de busca
    """
    html = """
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
      <meta charset="UTF-8" />
      <title>TriboTools - Painel de Licenças</title>
      <style>
        body {
          margin: 0;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #050816;
          color: #f9fafb;
        }
        header {
          padding: 16px 24px;
          background: #020617;
          border-bottom: 1px solid #1f2933;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        header h1 {
          font-size: 20px;
          margin: 0;
        }
        .badge {
          font-size: 11px;
          padding: 4px 8px;
          border-radius: 999px;
          background: #111827;
          border: 1px solid #4b5563;
        }
        main {
          padding: 20px 24px 40px 24px;
          max-width: 1200px;
          margin: 0 auto;
        }
        .token-box {
          display: flex;
          gap: 8px;
          align-items: center;
          margin-bottom: 20px;
          flex-wrap: wrap;
        }
        .token-box label {
          font-size: 13px;
          color: #9ca3af;
        }
        .token-box input {
          background: #020617;
          border-radius: 999px;
          border: 1px solid #4b5563;
          padding: 6px 12px;
          color: #e5e7eb;
          min-width: 260px;
          outline: none;
        }
        .token-box button {
          border-radius: 999px;
          border: none;
          padding: 6px 14px;
          font-size: 13px;
          cursor: pointer;
          background: #22c55e;
          color: #022c22;
          font-weight: 600;
        }
        .token-box button.secondary {
          background: #111827;
          color: #e5e7eb;
          border: 1px solid #374151;
        }
        .token-status {
          font-size: 12px;
          color: #9ca3af;
        }
        .cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
          gap: 12px;
          margin-bottom: 24px;
        }
        .card {
          padding: 14px 16px;
          border-radius: 16px;
          background: radial-gradient(circle at top left, #1f2933, #020617);
          border: 1px solid #1f2937;
        }
        .card h3 {
          margin: 0 0 4px 0;
          font-size: 13px;
          color: #9ca3af;
        }
        .card .value {
          font-size: 22px;
          font-weight: 600;
        }
        .card .sub {
          font-size: 11px;
          color: #6b7280;
          margin-top: 4px;
        }
        .section {
          margin-top: 20px;
          margin-bottom: 4px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 8px;
        }
        .section-title {
          font-size: 14px;
          color: #e5e7eb;
        }
        .section-sub {
          font-size: 12px;
          color: #6b7280;
        }
        .pill {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          padding: 2px 8px;
          border-radius: 999px;
          background: #111827;
          font-size: 11px;
          color: #9ca3af;
        }
        .dot {
          width: 6px;
          height: 6px;
          border-radius: 999px;
          background: #22c55e;
        }
        .create-box {
          border-radius: 16px;
          border: 1px solid #1f2937;
          background: #020617;
          padding: 12px 14px;
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
          align-items: center;
          margin-bottom: 16px;
        }
        .create-box input {
          background: #020617;
          border-radius: 999px;
          border: 1px solid #4b5563;
          padding: 6px 10px;
          color: #e5e7eb;
          font-size: 13px;
        }
        .create-box input.small {
          width: 80px;
        }
        .create-box input.notes {
          flex: 1;
          min-width: 180px;
        }
        .create-box button {
          border-radius: 999px;
          border: none;
          padding: 6px 14px;
          font-size: 13px;
          cursor: pointer;
          background: #3b82f6;
          color: #e5e7eb;
          font-weight: 600;
        }
        .create-status {
          font-size: 12px;
          color: #9ca3af;
          width: 100%;
        }
        .create-status.error {
          color: #f97373;
        }
        .table-wrapper {
          border-radius: 16px;
          border: 1px solid #1f2937;
          overflow: hidden;
          background: #020617;
          max-height: 480px;
          overflow-y: auto;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 8px;
          font-size: 13px;
        }
        th, td {
          padding: 8px 10px;
          border-bottom: 1px solid #111827;
        }
        th {
          text-align: left;
          background: #020617;
          position: sticky;
          top: 0;
          z-index: 1;
        }
        tbody tr:nth-child(even) {
          background: rgba(15, 23, 42, 0.75);
        }
        .status-pill {
          padding: 2px 8px;
          border-radius: 999px;
          font-size: 11px;
          display: inline-block;
        }
        .status-active {
          background: rgba(34, 197, 94, 0.12);
          color: #4ade80;
        }
        .status-inactive {
          background: rgba(239, 68, 68, 0.16);
          color: #f87171;
        }
        .error-msg {
          font-size: 12px;
          color: #f97373;
          margin-top: 4px;
        }
        .toolbar-right {
          display: flex;
          gap: 8px;
          align-items: center;
        }
        .btn-small {
          border-radius: 999px;
          border: 1px solid #374151;
          background: #111827;
          color: #e5e7eb;
          padding: 4px 10px;
          font-size: 12px;
          cursor: pointer;
        }
        .search-input {
          background: #020617;
          border-radius: 999px;
          border: 1px solid #4b5563;
          padding: 4px 10px;
          font-size: 12px;
          color: #e5e7eb;
          min-width: 200px;
        }
      </style>
    </head>
    <body>
      <header>
        <h1>TriboTools &mdash; Painel de Licenças</h1>
        <span class="badge">API v<span id="apiVersion">-</span></span>
      </header>
      <main>
        <div class="token-box">
          <label for="tokenInput">Admin Token (mesmo usado no Swagger):</label>
          <input id="tokenInput" type="password" placeholder="ex.: tribotools_master_2025" />
          <button id="saveTokenBtn">Salvar token</button>
          <button id="loadBtn" class="secondary">Carregar dados</button>
          <div class="token-status" id="tokenStatus"></div>
        </div>

        <div class="cards">
          <div class="card">
            <h3>Total de licenças</h3>
            <div class="value" id="cardTotalLic">-</div>
            <div class="sub">Registradas no banco</div>
          </div>
          <div class="card">
            <h3>Ativações ativas</h3>
            <div class="value" id="cardActiveAct">-</div>
            <div class="sub">Tokens ainda válidos</div>
          </div>
          <div class="card">
            <h3>Dispositivos únicos</h3>
            <div class="value" id="cardDevices">-</div>
            <div class="sub">Máquinas com licença ativa</div>
          </div>
          <div class="card">
            <h3>Eventos últimas 24h</h3>
            <div class="value" id="cardUsage24h">-</div>
            <div class="sub">run / activate / validate</div>
          </div>
        </div>

        <div class="section">
          <div>
            <div class="section-title">Criar nova licença</div>
            <div class="section-sub">Gere chaves para clientes sem precisar do Swagger.</div>
          </div>
          <span class="pill"><span class="dot"></span> Requer ADMIN_TOKEN válido</span>
        </div>

        <div class="create-box">
          <input id="newKey" placeholder="Chave (ex.: TT-CLIENTE-001)" />
          <input id="newMax" class="small" type="number" min="1" value="1" />
          <input id="newNotes" class="notes" placeholder="Notas (opcional)" />
          <button id="createLicBtn">Criar licença</button>
          <div id="createStatus" class="create-status"></div>
        </div>

        <div class="section">
          <div class="section-title">Licenças & uso</div>
          <div class="toolbar-right">
            <input id="searchInput" class="search-input" placeholder="Buscar por hash ou notas..." />
            <button id="exportCsvBtn" class="btn-small">Exportar CSV</button>
            <span class="section-sub">
              <span class="pill"><span class="dot"></span> Atualizado em <span id="lastUpdated">-</span></span>
            </span>
          </div>
        </div>

        <div id="usageError" class="error-msg"></div>

        <div class="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Licença (hash)</th>
                <th>Status</th>
                <th>Máx. devices</th>
                <th>Devices usados</th>
                <th>Execuções (run)</th>
                <th>Ativações</th>
                <th>Validações</th>
                <th>Eventos total</th>
                <th>Notas</th>
                <th>Ações</th>
              </tr>
            </thead>
            <tbody id="usageBody">
              <tr><td colspan="10">Nenhum dado ainda. Clique em "Carregar dados".</td></tr>
            </tbody>
          </table>
        </div>
      </main>

      <script>
        const tokenInput = document.getElementById("tokenInput");
        const saveTokenBtn = document.getElementById("saveTokenBtn");
        const loadBtn = document.getElementById("loadBtn");
        const tokenStatus = document.getElementById("tokenStatus");
        const usageBody = document.getElementById("usageBody");
        const usageError = document.getElementById("usageError");
        const apiVersionSpan = document.getElementById("apiVersion");
        const lastUpdatedSpan = document.getElementById("lastUpdated");

        const cardTotalLic = document.getElementById("cardTotalLic");
        const cardActiveAct = document.getElementById("cardActiveAct");
        const cardDevices   = document.getElementById("cardDevices");
        const cardUsage24h  = document.getElementById("cardUsage24h");

        const newKey   = document.getElementById("newKey");
        const newMax   = document.getElementById("newMax");
        const newNotes = document.getElementById("newNotes");
        const createBtn = document.getElementById("createLicBtn");
        const createStatus = document.getElementById("createStatus");
        const exportCsvBtn = document.getElementById("exportCsvBtn");
        const searchInput = document.getElementById("searchInput");

        let currentRows = [];

        function getToken() {
          return window.localStorage.getItem("tt_admin_token") || "";
        }

        function setToken(tok) {
          if (tok) {
            window.localStorage.setItem("tt_admin_token", tok);
          } else {
            window.localStorage.removeItem("tt_admin_token");
          }
        }

        function updateTokenStatus() {
          const t = getToken();
          if (t) {
            tokenStatus.textContent = "Token salvo localmente (localStorage).";
          } else {
            tokenStatus.textContent = "Nenhum token salvo. Cole o ADMIN_TOKEN e clique em Salvar.";
          }
        }

        saveTokenBtn.addEventListener("click", () => {
          const v = tokenInput.value.trim();
          setToken(v);
          updateTokenStatus();
        });

        loadBtn.addEventListener("click", async () => {
          await carregarTudo();
        });

        tokenInput.value = getToken();
        updateTokenStatus();

        async function fetchJSON(url, opts = {}) {
          const token = getToken();
          const headers = Object.assign(
            { "Accept": "application/json" },
            opts.headers || {},
          );
          if (token) {
            headers["Authorization"] = "Bearer " + token;
          }
          const fetchOptions = {
            method: opts.method || "GET",
            headers,
          };
          if (opts.body) {
            fetchOptions.body = opts.body;
          }
          const resp = await fetch(url, fetchOptions);
          if (!resp.ok) {
            const txt = await resp.text();
            throw new Error(resp.status + " " + txt);
          }
          return resp.json();
        }

        async function fetchCSV(url) {
          const token = getToken();
          const headers = {};
          if (token) {
            headers["Authorization"] = "Bearer " + token;
          }
          const resp = await fetch(url, {
            method: "GET",
            headers,
          });
          if (!resp.ok) {
            const txt = await resp.text();
            throw new Error(resp.status + " " + txt);
          }
          return await resp.blob();
        }

        async function carregarStats() {
          try {
            const s = await fetchJSON("/stats");
            cardTotalLic.textContent = s.total_licenses ?? "-";
            cardActiveAct.textContent = s.active_activations ?? "-";
            cardDevices.textContent = s.unique_devices ?? "-";
            cardUsage24h.textContent = s.usage_24h ?? "-";
          } catch (e) {
            console.error(e);
          }
        }

        function renderUsageTable(rows) {
          currentRows = rows || [];
          usageBody.innerHTML = "";
          if (!rows || !rows.length) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 10;
            td.textContent = "Nenhuma licença encontrada.";
            tr.appendChild(td);
            usageBody.appendChild(tr);
            return;
          }
          for (const r of rows) {
            const tr = document.createElement("tr");

            const tdKey = document.createElement("td");
            tdKey.textContent = r.license_key_hash;
            tr.appendChild(tdKey);

            const tdStatus = document.createElement("td");
            const span = document.createElement("span");
            span.classList.add("status-pill");
            if ((r.status || "").toLowerCase() === "active") {
              span.classList.add("status-active");
              span.textContent = "Ativa";
            } else {
              span.classList.add("status-inactive");
              span.textContent = "Inativa";
            }
            tdStatus.appendChild(span);
            tr.appendChild(tdStatus);

            const tdMax = document.createElement("td");
            tdMax.textContent = r.max_devices ?? "-";
            tr.appendChild(tdMax);

            const tdDev = document.createElement("td");
            tdDev.textContent = r.devices ?? 0;
            tr.appendChild(tdDev);

            const tdRuns = document.createElement("td");
            tdRuns.textContent = r.runs ?? 0;
            tr.appendChild(tdRuns);

            const tdAct = document.createElement("td");
            tdAct.textContent = r.activations ?? 0;
            tr.appendChild(tdAct);

            const tdVal = document.createElement("td");
            tdVal.textContent = r.validations ?? 0;
            tr.appendChild(tdVal);

            const tdTotal = document.createElement("td");
            tdTotal.textContent = r.total_events ?? 0;
            tr.appendChild(tdTotal);

            const tdNotes = document.createElement("td");
            tdNotes.textContent = r.notes || "";
            tr.appendChild(tdNotes);

            const tdActions = document.createElement("td");
            const btnToggle = document.createElement("button");
            btnToggle.textContent = (r.status || "").toLowerCase() === "active" ? "Desativar" : "Ativar";
            btnToggle.className = "btn-small";
            btnToggle.style.marginRight = "4px";
            btnToggle.onclick = () => toggleLicense(r.license_key_hash, r.status);

            const btnRevoke = document.createElement("button");
            btnRevoke.textContent = "Derrubar";
            btnRevoke.className = "btn-small";
            btnRevoke.onclick = () => revokeLicense(r.license_key_hash);

            tdActions.appendChild(btnToggle);
            tdActions.appendChild(btnRevoke);
            tr.appendChild(tdActions);

            usageBody.appendChild(tr);
          }
        }

        function applyFilter() {
          const term = (searchInput.value || "").toLowerCase();
          if (!term) {
            renderUsageTable(currentRows);
            return;
          }
          const filtered = currentRows.filter(r => {
            const h = (r.license_key_hash || "").toLowerCase();
            const n = (r.notes || "").toLowerCase();
            return h.includes(term) || n.includes(term);
          });
          renderUsageTable(filtered);
        }

        searchInput.addEventListener("input", () => {
          applyFilter();
        });

        async function carregarUsage() {
          usageError.textContent = "";
          try {
            const data = await fetchJSON("/api/admin/usage-summary");
            renderUsageTable(data.rows || []);
          } catch (e) {
            console.error(e);
            usageError.textContent = "Erro ao carregar uso: " + e.message;
          }
        }

        async function carregarVersao() {
          try {
            const d = await fetchJSON("/");
            if (d && d.version) {
              apiVersionSpan.textContent = d.version;
            }
          } catch (e) {}
        }

        async function carregarTudo() {
          await Promise.all([
            carregarVersao(),
            carregarStats(),
            carregarUsage(),
          ]);
          const now = new Date();
          lastUpdatedSpan.textContent = now.toLocaleString("pt-BR");
        }

        createBtn.addEventListener("click", async () => {
          createStatus.textContent = "";
          createStatus.classList.remove("error");

          const key = newKey.value.trim();
          const max = parseInt(newMax.value || "1", 10);
          const notes = newNotes.value.trim();

          if (!key) {
            createStatus.textContent = "Informe uma chave (ex.: TT-CLIENTE-001).";
            createStatus.classList.add("error");
            return;
          }

          try {
            await fetchJSON("/api/admin/licenses", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                license_key: key,
                max_devices: max || 1,
                notes: notes,
              }),
            });
            createStatus.textContent = "Licença criada com sucesso.";
            newKey.value = "";
            newNotes.value = "";
            await carregarTudo();
          } catch (e) {
            console.error(e);
            createStatus.textContent = "Erro ao criar licença: " + e.message;
            createStatus.classList.add("error");
          }
        });

        exportCsvBtn.addEventListener("click", async () => {
          try {
            const blob = await fetchCSV("/api/admin/usage-csv");
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "tribotools_usage_summary.csv";
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
          } catch (e) {
            console.error(e);
            alert("Erro ao exportar CSV: " + e.message);
          }
        });

        async function toggleLicense(licHash, status) {
          const newStatus = (status || "").toLowerCase() === "active" ? "inactive" : "active";
          try {
            await fetchJSON("/api/admin/licenses/" + encodeURIComponent(licHash) + "/status", {
              method: "PATCH",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ status: newStatus }),
            });
            await carregarTudo();
          } catch (e) {
            alert("Erro ao alterar status: " + e.message);
          }
        }

        async function revokeLicense(licHash) {
          if (!confirm("Tem certeza que deseja DERRUBAR todas as ativações dessa licença e marcá-la como inativa?")) {
            return;
          }
          try {
            await fetchJSON("/api/admin/licenses/" + encodeURIComponent(licHash) + "/revoke", {
              method: "POST",
            });
            await carregarTudo();
          } catch (e) {
            alert("Erro ao derrubar licença: " + e.message);
          }
        }

        // carrega stats básicos ao abrir (mesmo sem token)
        carregarVersao();
        carregarStats();
      </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


# ================== INCLUDE ROUTERS ==================

app.include_router(core)                  # rotas públicas em "/"
app.include_router(admin, prefix="/api")  # rotas admin em "/api/admin/..."


# Exec local
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("tribotools_api:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))


# In[ ]:




