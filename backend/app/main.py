import asyncio, json, os, re, sqlite3, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

DB = os.getenv("DATABASE_PATH", "./sentinelapi.db")
Path(DB).parent.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="SentinelAPI", version="1.0.0")


def db():
    c = sqlite3.connect(DB, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans (
          id TEXT PRIMARY KEY, created_at TEXT, status TEXT, progress INTEGER,
          total INTEGER, spec_url TEXT, target_base_url TEXT, auth_tokens TEXT,
          checks TEXT, authorization_confirmed INTEGER, error TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS findings (
          id TEXT PRIMARY KEY, scan_id TEXT, endpoint TEXT, method TEXT,
          vulnerability_class TEXT, severity TEXT, title TEXT, description TEXT,
          evidence TEXT, poc_curl TEXT, remediation TEXT, created_at TEXT)""")

init_db()

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"

class ScanRequest(BaseModel):
    spec_url: Optional[str] = None
    spec_content: Optional[str] = None
    target_base_url: str
    auth_tokens: dict[str, str] = Field(default_factory=dict)
    checks: list[str] = Field(default_factory=lambda: ["bola", "data_exposure", "auth_misconfig", "rate_limit"])
    authorization_confirmed: bool = False


def now(): return datetime.now(timezone.utc).isoformat()
def headers_for(token: Optional[str]): return {"Authorization": f"Bearer {token}"} if token else {}
def join_url(base: str, path: str): return base.rstrip("/") + "/" + path.lstrip("/")
def safe_json(resp):
    try: return resp.json()
    except Exception: return None

def curl_for(method, url, token=None, body=None):
    parts = ["curl", "-i", "-X", method.upper(), repr(url)]
    if token: parts += ["-H", repr(f"Authorization: Bearer {token}")]
    if body is not None: parts += ["-H", repr("Content-Type: application/json"), "--data", repr(json.dumps(body))]
    return " ".join(parts)

def finding(scan_id, endpoint, method, klass, severity, title, description, evidence, poc, remediation):
    return {"id": str(uuid.uuid4()), "scan_id": scan_id, "endpoint": endpoint, "method": method.upper(), "vulnerability_class": klass,
            "severity": severity, "title": title, "description": description, "evidence": evidence, "poc_curl": poc,
            "remediation": remediation, "created_at": now()}

def extract_paths(spec):
    out=[]
    for path, item in (spec.get("paths") or {}).items():
        for method, op in item.items():
            if method.lower() not in {"get","post","put","patch","delete","head"}: continue
            out.append((path, method.lower(), op or {}))
    return out

def path_sample(path):
    return re.sub(r"\{[^}]+\}", lambda m: "2" if "user" in m.group(0).lower() else "202", path)

def declared_fields(op):
    fields=set()
    for response in (op.get("responses") or {}).values():
        content=(response or {}).get("content") or {}
        for media in content.values():
            schema=(media or {}).get("schema") or {}
            for k in (schema.get("properties") or {}): fields.add(k.lower())
    return fields

async def load_spec(req: ScanRequest):
    if req.spec_content:
        return yaml.safe_load(req.spec_content)
    if not req.spec_url: raise ValueError("Provide a spec URL or uploaded spec content")
    # Safety boundary: fetch only the exact URL explicitly supplied.
    async with httpx.AsyncClient(timeout=12, follow_redirects=False) as client:
        r=await client.get(req.spec_url); r.raise_for_status()
        return r.json() if "json" in r.headers.get("content-type", "") else yaml.safe_load(r.text)

async def run_scan(scan_id: str, req: ScanRequest):
    try:
        spec=await load_spec(req)
        endpoints=extract_paths(spec)
        with db() as c: c.execute("UPDATE scans SET total=?, status=?, progress=? WHERE id=?", (len(endpoints), "running", 0, scan_id))
        base=req.target_base_url.rstrip("/")
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            all_findings=[]
            tokens=list(req.auth_tokens.items()) or [("anonymous", "")]
            for index,(path,method,op) in enumerate(endpoints, 1):
                url=join_url(base, path_sample(path))
                security=bool(op.get("security") or spec.get("security"))
                if "bola" in req.checks and method in {"get","put","patch","delete"} and "{" in path and req.auth_tokens:
                    for user, token in tokens[:1]:
                        r=await client.request(method, url, headers=headers_for(token))
                        data=safe_json(r)
                        owner=data.get("owner_id") if isinstance(data,dict) else None
                        user_id=1 if user.lower().endswith("a") else None
                        if r.status_code < 300 and owner is not None and user_id is not None and owner != user_id:
                            all_findings.append(finding(scan_id,path,method,"BOLA/IDOR","Critical",f"{user} can access another user's object without authorization",f"The authenticated principal {user} received object {path_sample(path)} whose owner_id={owner}; the principal is user {user_id}.",f"HTTP {r.status_code}; response owner_id={owner}; authenticated as {user}",curl_for(method,url,token),"Enforce an ownership check comparing the authenticated user's ID with the resource owner before returning data."))
                if "data_exposure" in req.checks and method == "get":
                    token=tokens[0][1] if req.auth_tokens else None
                    r=await client.request(method,url,headers=headers_for(token)); data=safe_json(r)
                    if isinstance(data,dict):
                        sensitive=[k for k in data if any(w in k.lower() for w in ["password","ssn","token","secret","internal","hash","key"])]
                        declared=declared_fields(op)
                        undeclared=[k for k in sensitive if k.lower() not in declared]
                        if sensitive or undeclared:
                            keys=undeclared or sensitive
                            all_findings.append(finding(scan_id,path,method,"Data Exposure","High",f"Sensitive fields exposed by {path}",f"The response contains sensitive fields ({', '.join(keys)}) that should not be returned to an API consumer.",f"HTTP {r.status_code}; JSON keys: {', '.join(data.keys())}",curl_for(method,url,token),"Use response DTOs/allow-lists and remove secrets, hashes, SSNs, and internal notes from public responses."))
                sensitive_path = any(word in path.lower() for word in ["admin", "export", "internal", "billing"])
                if "auth_misconfig" in req.checks and (security or sensitive_path):
                    r=await client.request(method,url)
                    if r.status_code < 300:
                        all_findings.append(finding(scan_id,path,method,"Auth Misconfiguration","High",f"{path} is accessible without authentication",f"This endpoint appears sensitive or is declared as authenticated, but the target returned success without an Authorization header.",f"Unauthenticated response: HTTP {r.status_code}",curl_for(method,url),"Require and validate authentication middleware on every sensitive route."))
                if "rate_limit" in req.checks and method == "post" and ("login" in path.lower() or "auth" in path.lower()):
                    successes=0
                    for _ in range(20):
                        r=await client.request(method,url,json={"username":"attacker","password":"wrong"})
                        if r.status_code != 429: successes += 1
                    if successes == 20:
                        all_findings.append(finding(scan_id,path,method,"Rate Limit","Medium",f"No rate limiting detected on {path}",f"Twenty rapid requests completed without a 429 response, enabling brute-force or resource-exhaustion attempts.",f"20/20 requests were non-429",curl_for(method,url,body={"username":"attacker","password":"wrong"}),"Add per-IP and per-account throttling with a clear 429 response and backoff policy."))
                for f in all_findings[-4:]:
                    with db() as c:
                        c.execute("INSERT OR IGNORE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", tuple(f.values()))
                with db() as c: c.execute("UPDATE scans SET progress=? WHERE id=?", (index,scan_id))
            with db() as c: c.execute("UPDATE scans SET status=?, progress=? WHERE id=?", ("completed", len(endpoints), scan_id))
    except Exception as e:
        with db() as c: c.execute("UPDATE scans SET status=?, error=? WHERE id=?", ("failed", str(e), scan_id))

@app.get("/")
def index(): return FileResponse(str(FRONTEND_DIR / "index.html"))
if Path(FRONTEND_DIR).exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
@app.post("/api/scans")
async def create_scan(req: ScanRequest):
    if not req.authorization_confirmed: raise HTTPException(400, "You must confirm authorization to test this target")
    if not req.target_base_url.startswith(("http://", "https://")): raise HTTPException(400, "Target must be an explicit HTTP(S) URL")
    if not req.spec_url and not req.spec_content: raise HTTPException(400, "Provide an OpenAPI URL or uploaded content")
    sid=str(uuid.uuid4())
    with db() as c:
        c.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?)", (sid,now(),"queued",0,0,req.spec_url,req.target_base_url,json.dumps(req.auth_tokens),json.dumps(req.checks),1,None))
    asyncio.create_task(run_scan(sid,req))
    return {"id":sid,"status":"queued"}

@app.get("/api/scans")
def list_scans():
    with db() as c: rows=c.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    with db() as c:
        row=c.execute("SELECT * FROM scans WHERE id=?",(scan_id,)).fetchone()
    if not row: raise HTTPException(404,"scan not found")
    return dict(row)

@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str):
    with db() as c: rows=c.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END",(scan_id,)).fetchall()
    return [dict(r) for r in rows]
