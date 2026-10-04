from fastapi import FastAPI, Depends, HTTPException, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Annotated, List, Optional, Any, Dict, Literal
from datetime import datetime, timezone
import json
import os
import time
import uuid
import hashlib
import secrets
import jwt
import asyncio
from pathlib import Path

# --- CONFIGURACIÓN Y RUTAS ---
API_TOKEN = ""
JWT_SECRET = ""
JWT_ALGORITHM = "HS256"
MAX_GLOBAL_RESULTS = ""
MAX_SECURITY_EVENTS = ""
RESULTS_RETENTION_DAYS = ""
ROOT_PATH = ""
OFFLINE_THRESHOLD_DAYS = ""

# DATA_DIR = Path(os.getenv("ORBIT_DATA_DIR", "/var/lib/orbit-server")
DATA_DIR = Path("/var/lib/orbit-server")
NODES_DIR = DATA_DIR / "nodes"
TASKS_DIR = DATA_DIR / "tasks"
SECURITY_LOG_FILE = DATA_DIR / "security_events.json"
USERS_FILE = DATA_DIR / "users.json"

VERSION_FILE = Path(__file__).resolve().parent / "VERSION"
APP_VERSION = VERSION_FILE.read_text().strip() if VERSION_FILE.exists() else "1.0.0"

DATA_DIR.mkdir(parents=True, exist_ok=True)
NODES_DIR.mkdir(parents=True, exist_ok=True)
TASKS_DIR.mkdir(parents=True, exist_ok=True)

RoleType = Literal["administrator", "operator", "user"]

CONFIG_METADATA = {
    "api_token": {
        "label": "API Access Token",
        "description": "Bearer token used exclusively by fleet agents to authenticate automated reporting and polling.",
        "type": "password"
    },
    "jwt_secret": {
        "label": "Web Session Secret (JWT)",
        "description": "Secret key used to encrypt user web sessions. Note: Changing this value will immediately invalidate all active web sessions.",
        "type": "password"
    },
    "max_global_results": {
        "label": "Max Global Results",
        "description": "Maximum number of recent task execution results retained for global reporting.",
        "type": "number"
    },
    "max_security_events": {
        "label": "Max Security Events",
        "description": "Maximum number of authentication violation audit events stored in security_events.json.",
        "type": "number"
    },
    "results_retention_days": {
        "label": "Results Retention (Days)",
        "description": "Number of days to keep completed task execution logs before automatic purging.",
        "type": "number"
    },
    "offline_threshold_days": {
        "label": "Offline Threshold (Days)",
        "description": "Days without a successful check-in before a host is classified as unreachable/offline.",
        "type": "number"
    },
    "root_path": {
        "label": "Reverse Proxy Root Path",
        "description": "URL context path prefix when Orbit is served behind a reverse proxy (e.g., /orbit-server). Note: Changing this value requires restarting the Orbit service and updating your reverse proxy configuration.",
        "type": "text"
    }
}

app = FastAPI(title="Orbit Enterprise API", version=APP_VERSION, root_path=ROOT_PATH)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# Sesiones de usuario web activas en memoria: token -> {username, role, expires}
# ACTIVE_SESSIONS: Dict[str, dict] = {}

# --- UTILIDADES DE ALMACENAMIENTO Y CRIPTOGRAFÍA ---

def _dump_model(model: BaseModel) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    return json.loads(model.json())

def hash_password(password: str, salt: Optional[str] = None) -> str:
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"{salt}${key.hex()}"

def verify_password(stored_password: str, provided_password: str) -> bool:
    try:
        salt, key = stored_password.split("$")
        check_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
        return secrets.compare_digest(key, check_key)
    except Exception:
        return False

def get_users_list() -> List[dict]:
    if not USERS_FILE.exists():
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def save_users_list(users: List[dict]):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

def init_default_users():
    if not USERS_FILE.exists():
        initial_admin = [{
            "id": str(uuid.uuid4()),
            "username": "admin",
            "password": hash_password("orbitadmin"),
            "role": "administrator",
            "created_at": datetime.now(timezone.utc).isoformat()
        }]
        save_users_list(initial_admin)

init_default_users()

def load_system_config() -> dict:
    defaults = {
        "api_token": os.getenv("ORBIT_API_TOKEN", secrets.token_urlsafe(32)),
        "jwt_secret": os.getenv("ORBIT_JWT_SECRET", secrets.token_urlsafe(32)),
        "max_global_results": int(os.getenv("ORBIT_MAX_GLOBAL_RESULTS", "20")),
        "max_security_events": int(os.getenv("ORBIT_MAX_SECURITY_EVENTS", "200")),
        "results_retention_days": int(os.getenv("ORBIT_RESULTS_RETENTION_DAYS", "30")),
        "offline_threshold_days": int(os.getenv("ORBIT_OFFLINE_THRESHOLD_DAYS", "30")),
        "root_path": os.getenv("ORBIT_ROOT_PATH", "")
    }
    return defaults

active_config = load_system_config()
API_TOKEN = active_config["api_token"]
MAX_GLOBAL_RESULTS = active_config["max_global_results"]
MAX_SECURITY_EVENTS = active_config["max_security_events"]
RESULTS_RETENTION_DAYS = active_config["results_retention_days"]
OFFLINE_THRESHOLD_DAYS = active_config["offline_threshold_days"]
ROOT_PATH = active_config["root_path"]
JWT_SECRET = active_config["jwt_secret"]

def _load_tasks_file(node_id: str) -> List[Dict[str, Any]]:
    tasks_file = TASKS_DIR / f"{node_id}.json"
    if not tasks_file.exists():
        return []
    try:
        with open(tasks_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def _save_tasks_file(node_id: str, tasks: List[Dict[str, Any]]) -> None:
    tasks_file = TASKS_DIR / f"{node_id}.json"
    with open(tasks_file, "w", encoding="utf-8") as f:
        json.dump(tasks, f, indent=2, ensure_ascii=False)

def cleanup_old_results():
    if RESULTS_RETENTION_DAYS <= 0:
        return
    cutoff_time = time.time() - (RESULTS_RETENTION_DAYS * 86400)
    for file_path in TASKS_DIR.glob("*_*_result.json"):
        try:
            if file_path.stat().st_mtime < cutoff_time:
                file_path.unlink()
        except Exception as e:
            print(f"[WARN] Failed to delete old result file {file_path}: {e}")

def log_security_violation(request: Request, reason: str, provided_token: Optional[str] = None):
    client_ip = request.client.host if request.client else "Unknown"
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "endpoint": request.url.path,
        "method": request.method,
        "reason": reason,
        "token_preview": f"{provided_token[:3]}..." if provided_token and len(provided_token) >= 3 else (provided_token or "none")
    }

    events = []
    if SECURITY_LOG_FILE.exists():
        try:
            with open(SECURITY_LOG_FILE, "r", encoding="utf-8") as f:
                events = json.load(f)
                if not isinstance(events, list):
                    events = []
        except Exception:
            events = []

    events.append(event)
    if len(events) > MAX_SECURITY_EVENTS:
        events = events[-MAX_SECURITY_EVENTS:]
    try:
        with open(SECURITY_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

# --- CONTROL DE ACCESO Y ROLES ---

def verify_agent_token(
    request: Request,
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
):
    """Valida token Bearer exclusivamente para agentes."""
    if not credentials or credentials.credentials != API_TOKEN:
        token_val = credentials.credentials if credentials else None
        log_security_violation(request, reason="Invalid agent authentication token", provided_token=token_val)
        raise HTTPException(status_code=401, detail="Invalid agent authentication token")
    return credentials.credentials

def get_current_user(
    request: Request,
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
) -> dict:
    """Valida sesión interactiva de usuario web usando JWT."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication credentials required")
    
    try:
        # Desencriptar y validar el token
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload  # Devuelve el diccionario con username, role y exp
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid session token")

def require_role(allowed_roles: List[str]):
    def role_checker(user: Annotated[dict, Depends(get_current_user)]):
        if user["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient privileges for this operation")
        return user
    return role_checker

# --- MODELOS PYDANTIC ---

class PackageInfo(BaseModel):
    name: str
    version: str
    release: str = "0"
    arch: str = "unknown"
    is_security: bool = False
    security_level: Optional[str] = "NONE"

class NodeReport(BaseModel):
    agent_version: Optional[str] = "1.0.0 (Legacy)"
    fqdn: str
    ip_address: str
    timestamp: str
    os_version: str
    kernel_version: str
    uptime_seconds: float
    cpu_cores: int
    ram_total_mb: int
    installed_packages: Optional[List[PackageInfo]] = []
    available_updates: Optional[List[PackageInfo]] = []
    needs_reboot: Optional[bool] = False
    last_action_status: Optional[str] = "none" 
    last_action_message: Optional[str] = ""
    tags: Optional[list[str]] = []

class TaskResult(BaseModel):
    task_id: str
    status: str = Field(..., pattern="^(success|failed)$")
    log: str

class AdminTaskCreate(BaseModel):
    action: str = Field(..., pattern="^(update|reboot)$")
    packages: Optional[List[str]] = []
    scheduled_at: Optional[datetime] = None 

class BulkTaskCreate(BaseModel):
    node_ids: List[str]
    action: str = Field(..., pattern="^(update|reboot)$")
    packages: Optional[List[str]] = []
    scheduled_at: Optional[datetime] = None

class BulkCancelTasks(BaseModel):
    items: List[dict]
    
class SystemConfigUpdate(BaseModel):
    api_token: str = Field(..., min_length=16)
    jwt_secret: str = Field(..., min_length=16)
    max_global_results: int = Field(..., ge=1, le=500)
    max_security_events: int = Field(..., ge=10, le=5000)
    results_retention_days: int = Field(..., ge=0, le=365)
    offline_threshold_days: int = Field(..., ge=1, le=365)
    root_path: Optional[str] = ""

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str = Field(..., min_length=5)
    password: str = Field(..., min_length=15)
    role: RoleType

class UserUpdate(BaseModel):
    username: str = Field(..., min_length=5)
    role: RoleType
    password: Optional[str] = None

# --- AUTENTICACIÓN WEB ---

@app.post(
    "/api/v1/auth/login",
    responses={401: {"description": "Invalid username or password"}},
)
async def web_login(payload: LoginRequest, request: Request):
    users = get_users_list()
    user = next((u for u in users if u["username"] == payload.username), None)
    
    if not user or not verify_password(user["password"], payload.password):
        log_security_violation(request, reason=f"Failed login attempt for user: {payload.username}")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # NUEVO: Generar JWT en lugar de token aleatorio
    payload_data = {
        "username": user["username"],
        "role": user["role"],
        "exp": time.time() + (12 * 3600) # Caduca en 12 horas
    }
    
    session_token = jwt.encode(payload_data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    return {
        "token": session_token,
        "username": user["username"],
        "role": user["role"]
    }

# --- GESTIÓN DE USUARIOS (SOLO ADMINISTRATOR) ---

@app.get("/api/v1/admin/users", dependencies=[Depends(require_role(["administrator"]))])
async def list_users():
    users = get_users_list()
    return {"users": [{"id": u["id"], "username": u["username"], "role": u["role"], "created_at": u.get("created_at")} for u in users]}

@app.post(
    "/api/v1/admin/users",
    dependencies=[Depends(require_role(["administrator"]))],
    responses={400: {"description": "Username already exists"}},
)
async def create_user(payload: UserCreate):
    users = get_users_list()
    if any(u["username"] == payload.username for u in users):
        raise HTTPException(status_code=400, detail="Username already exists")
        
    new_user = {
        "id": str(uuid.uuid4()),
        "username": payload.username,
        "password": hash_password(payload.password),
        "role": payload.role,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    users.append(new_user)
    save_users_list(users)
    return {"status": "created", "user_id": new_user["id"]}

@app.delete(
    "/api/v1/admin/users/{user_id}",
    dependencies=[Depends(require_role(["administrator"]))],
    responses={
        400: {"description": "Cannot delete your own account or the sole administrator"},
        404: {"description": "User not found"},
    },
)
async def delete_user(
    user_id: str,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    users = get_users_list()
    target = next((u for u in users if u["id"] == user_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target["username"] == current_user["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own active user account")
    if target["role"] == "administrator" and len([u for u in users if u["role"] == "administrator"]) <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the sole administrator account")
        
    users = [u for u in users if u["id"] != user_id]
    save_users_list(users)
    return {"status": "deleted"}

@app.put(
    "/api/v1/admin/users/{user_id}",
    dependencies=[Depends(require_role(["administrator"]))],
    responses={
        400: {"description": "Invalid user update"},
        404: {"description": "User not found"},
        500: {"description": "Internal error updating user"},
    },
)
async def update_user(
    user_id: str,
    payload: UserUpdate,
    current_user: Annotated[dict, Depends(get_current_user)],
):
    try:
        users = get_users_list()
        target = next((u for u in users if str(u.get("id")) == str(user_id)), None)
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
            
        # El usuario "admin" principal no puede ser renombrado
        if target.get("username") == "admin" and payload.username and payload.username.strip() != "admin":
            raise HTTPException(status_code=400, detail="The primary 'admin' username cannot be modified.")
            
        # Validar si el nuevo username ya está en uso por otra cuenta
        if payload.username and payload.username.strip():
            new_username = payload.username.strip()
            if new_username != target.get("username"):
                if any(u.get("username") == new_username and str(u.get("id")) != str(user_id) for u in users):
                    raise HTTPException(status_code=400, detail="Username is already in use by another account.")
                target["username"] = new_username

        # Validar rol y evitar degradar al último administrador
        if payload.role and payload.role != target.get("role"):
            if target.get("role") == "administrator" and payload.role != "administrator":
                admin_count = len([u for u in users if u.get("role") == "administrator"])
                if admin_count <= 1:
                    raise HTTPException(status_code=400, detail="Cannot downgrade the only remaining administrator.")
            target["role"] = payload.role

        # Actualizar contraseña únicamente si se proporcionó un valor no vacío
        if payload.password and payload.password.strip():
            pwd_clean = payload.password.strip()
            if len(pwd_clean) < 6:
                raise HTTPException(status_code=400, detail="Password must be at least 6 characters long.")
            target["password"] = hash_password(pwd_clean)

        save_users_list(users)
        return {"status": "updated", "user_id": target["id"]}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR] Failed to update user: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error updating user: {str(e)}")

# --- ENDPOINTS AGENTE (VERIFICACIÓN EXCLUSIVA DE TOKEN DE AGENTE) ---

@app.post("/api/v1/agent/{node_id}/report", dependencies=[Depends(verify_agent_token)])
async def agent_report(node_id: str, report: NodeReport):
    file_path = NODES_DIR / f"{node_id}.json"
    data = _dump_model(report)
    data['last_check'] = datetime.now(timezone.utc).isoformat()
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        
    return {"status": "ok", "message": "Report saved successfully"}

@app.get("/api/v1/agent/{node_id}/tasks", dependencies=[Depends(verify_agent_token)])
async def agent_get_tasks(node_id: str):
    all_tasks = _load_tasks_file(node_id)
    if not all_tasks:
        return {"tasks": []}
        
    now = datetime.now(timezone.utc)
    tasks_to_execute = []
    tasks_pending = []
    
    for task in all_tasks:
        scheduled_raw = task.get("scheduled_at")
        if not scheduled_raw:
            tasks_to_execute.append(task)
            continue
            
        try:
            iso_str = scheduled_raw.replace("Z", "+00:00")
            scheduled_time = datetime.fromisoformat(iso_str)
            if scheduled_time.tzinfo is None:
                scheduled_time = scheduled_time.replace(tzinfo=timezone.utc)
                
            if now >= scheduled_time:
                tasks_to_execute.append(task)
            else:
                tasks_pending.append(task)
        except Exception:
            tasks_to_execute.append(task)
                
    _save_tasks_file(node_id, tasks_pending)
    return {"tasks": tasks_to_execute}

@app.post("/api/v1/agent/{node_id}/results", dependencies=[Depends(verify_agent_token)])
async def agent_task_result(node_id: str, result: TaskResult):
    log_path = TASKS_DIR / f"{node_id}_{result.task_id}_result.json"
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(_dump_model(result), f, indent=2, default=str, ensure_ascii=False)
        
    cleanup_old_results()
    return {"status": "acknowledged"}

# --- ENDPOINTS ADMIN / WEB (LECTURA: ADMINISTRATOR, OPERATOR, USER) ---

@app.get("/api/v1/admin/results/global", dependencies=[Depends(require_role(["administrator", "operator", "user"]))])
async def admin_get_global_results():
    results = []
    node_names = {}
    
    for node_file in NODES_DIR.glob("*.json"):
        try:
            with open(node_file, "r", encoding="utf-8") as nf:
                data = json.load(nf)
                node_names[node_file.stem] = data.get("fqdn", "Unknown Host")
        except Exception:
            pass

    for file_path in TASKS_DIR.glob("*_*_result.json"):
        try:
            parts = file_path.stem.split('_')
            if len(parts) >= 3:
                node_uuid = parts[0]
                with open(file_path, "r", encoding="utf-8") as f:
                    result_data = json.load(f)
                    result_data["node_uuid"] = node_uuid
                    result_data["fqdn"] = node_names.get(node_uuid, "Unknown Host")
                    result_data["timestamp"] = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc).isoformat()
                    results.append(result_data)
        except Exception:
            pass
            
    results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"results": results[:MAX_GLOBAL_RESULTS]}

@app.get("/api/v1/admin/nodes", dependencies=[Depends(require_role(["administrator", "operator", "user"]))])
async def admin_get_nodes():
    nodes = []
    for file_path in NODES_DIR.glob("*.json"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                node_data = json.load(f)
                node_uuid = file_path.stem
                node_data["uuid"] = node_uuid 
                
                tasks = _load_tasks_file(node_uuid)
                node_data["has_scheduled_tasks"] = bool(tasks)
                nodes.append(node_data)
        except Exception:
            pass
    return {"nodes": nodes}

@app.get("/api/v1/admin/nodes/{node_id}/tasks", dependencies=[Depends(require_role(["administrator", "operator", "user"]))])
async def admin_get_node_tasks(node_id: str):
    return {"tasks": _load_tasks_file(node_id)}

@app.get("/api/v1/admin/nodes/{node_id}/results", dependencies=[Depends(require_role(["administrator", "operator", "user"]))])
async def admin_get_node_results(node_id: str):
    results = []
    for file_path in TASKS_DIR.glob(f"{str(node_id)}_*_result.json"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                result_data = json.load(f)
                result_data["timestamp"] = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc).isoformat()
                results.append(result_data)
        except Exception:
            pass
            
    results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"results": results}

@app.get("/api/v1/admin/tasks/scheduled", dependencies=[Depends(require_role(["administrator", "operator", "user"]))])
async def admin_get_all_scheduled_tasks():
    all_scheduled = []
    node_names = {}
    for node_file in NODES_DIR.glob("*.json"):
        try:
            with open(node_file, "r", encoding="utf-8") as nf:
                data = json.load(nf)
                node_names[node_file.stem] = data.get("fqdn", "Unknown Host")
        except Exception:
            pass

    for tasks_file in TASKS_DIR.glob("*.json"):
        if "_result" in tasks_file.name:
            continue
        node_uuid = tasks_file.stem
        try:
            with open(tasks_file, "r", encoding="utf-8") as tf:
                tasks = json.load(tf)
                if isinstance(tasks, list):
                    for task in tasks:
                        all_scheduled.append({
                            "node_uuid": node_uuid,
                            "fqdn": node_names.get(node_uuid, "Unknown Host"),
                            "task_id": task.get("task_id"),
                            "action": task.get("action"),
                            "packages": task.get("packages", []),
                            "scheduled_at": task.get("scheduled_at")
                        })
        except Exception:
            pass

    return {"scheduled_tasks": all_scheduled}

@app.get("/api/v1/admin/packages/pending", dependencies=[Depends(require_role(["administrator", "operator", "user"]))])
async def admin_get_global_pending_packages():
    package_map = {}
    for file_path in NODES_DIR.glob("*.json"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                node_data = json.load(f)
                node_uuid = file_path.stem
                fqdn = node_data.get("fqdn", "Unknown Host")
                
                for update in node_data.get("available_updates", []):
                    pkg_key = f"{update['name']}-{update['version']}-{update['release']}.{update['arch']}"
                    
                    if pkg_key not in package_map:
                        package_map[pkg_key] = {
                            "name": update["name"],
                            "version": update["version"],
                            "release": update["release"],
                            "arch": update["arch"],
                            "is_security": update["is_security"],
                            "security_level": update["security_level"],
                            "affected_nodes": []
                        }
                        
                    package_map[pkg_key]["affected_nodes"].append({
                        "uuid": node_uuid,
                        "fqdn": fqdn
                    })
        except Exception:
            pass

    result_list = []
    for pkg_key, data in package_map.items():
        data["affected_nodes_count"] = len(data["affected_nodes"])
        result_list.append(data)

    result_list.sort(key=lambda x: x["affected_nodes_count"], reverse=True)
    return {"pending_packages": result_list}

@app.get("/api/v1/admin/security/events", dependencies=[Depends(require_role(["administrator", "operator", "user"]))])
async def admin_get_security_events():
    if not SECURITY_LOG_FILE.exists():
        return {"events": []}
    try:
        with open(SECURITY_LOG_FILE, "r", encoding="utf-8") as f:
            events = json.load(f)
            return {"events": events if isinstance(events, list) else []}
    except Exception:
        return {"events": []}

@app.get("/api/v1/admin/config", dependencies=[Depends(require_role(["administrator", "operator", "user"]))])
async def get_admin_config():
    return {
        "offline_threshold_days": OFFLINE_THRESHOLD_DAYS,
        "app_version": APP_VERSION
    }

# --- ENDPOINTS OPERATIVOS / TAREAS (ADMINISTRATOR Y OPERATOR) ---

@app.delete("/api/v1/admin/nodes/{node_id}", dependencies=[Depends(require_role(["administrator", "operator"]))])
async def admin_decommission_node(node_id: str):
    node_file = NODES_DIR / f"{node_id}.json"
    tasks_file = TASKS_DIR / f"{node_id}.json"
    
    if node_file.exists():
        node_file.unlink()
    if tasks_file.exists():
        tasks_file.unlink()
        
    for log_file in TASKS_DIR.glob(f"{node_id}_*_result.json"):
        try:
            log_file.unlink()
        except Exception:
            pass
            
    return {"status": "decommissioned", "node_id": str(node_id)}

@app.post("/api/v1/admin/nodes/{node_id}/schedule_task", dependencies=[Depends(require_role(["administrator", "operator"]))])
async def admin_schedule_task(node_id: str, task: AdminTaskCreate):
    all_tasks = _load_tasks_file(node_id)
    new_task = {
        "task_id": str(uuid.uuid4()),
        "action": task.action,
        "packages": task.packages or [],
        "scheduled_at": task.scheduled_at.isoformat() if task.scheduled_at else None
    }
    all_tasks.append(new_task)
    _save_tasks_file(node_id, all_tasks)
    return {"status": "scheduled", "task_id": new_task["task_id"]}

@app.delete("/api/v1/admin/nodes/{node_id}/tasks/{task_id}", dependencies=[Depends(require_role(["administrator", "operator"]))], responses={404: {"description": "Task not found"}})
async def admin_delete_task(node_id: str, task_id: str):
    tasks = _load_tasks_file(node_id)
    initial_count = len(tasks)
    tasks = [t for t in tasks if t.get("task_id") != task_id]
    
    if len(tasks) == initial_count:
        raise HTTPException(status_code=404, detail="Task not found")
        
    _save_tasks_file(node_id, tasks)
    return {"status": "cancelled"}

@app.delete("/api/v1/admin/nodes/{node_id}/tasks", dependencies=[Depends(require_role(["administrator", "operator"]))])
async def admin_delete_all_node_tasks(node_id: str):
    tasks_file = TASKS_DIR / f"{node_id}.json"
    if tasks_file.exists():
        tasks_file.unlink()
    return {"status": "all_tasks_cancelled"}

@app.post("/api/v1/admin/tasks/bulk_cancel", dependencies=[Depends(require_role(["administrator", "operator"]))])
async def admin_bulk_cancel_tasks(payload: BulkCancelTasks):
    cancelled_count = 0
    tasks_by_node = {}
    for item in payload.items:
        node_id = item.get("node_id")
        task_id = item.get("task_id")
        if node_id and task_id:
            tasks_by_node.setdefault(node_id, []).append(task_id)

    for node_id, task_ids in tasks_by_node.items():
        tasks = _load_tasks_file(node_id)
        if tasks:
            initial_len = len(tasks)
            tasks = [t for t in tasks if t.get("task_id") not in task_ids]
            cancelled_count += (initial_len - len(tasks))
            _save_tasks_file(node_id, tasks)

    return {"status": "bulk_cancelled", "cancelled_count": cancelled_count}

@app.post("/api/v1/admin/bulk/schedule_task", dependencies=[Depends(require_role(["administrator", "operator"]))])
async def admin_bulk_schedule_task(task: BulkTaskCreate):
    scheduled_str = task.scheduled_at.isoformat() if task.scheduled_at else None
    success_count = 0

    for node_id in task.node_ids:
        try:
            all_tasks = _load_tasks_file(node_id)
            new_task = {
                "task_id": str(uuid.uuid4()),
                "action": task.action,
                "packages": task.packages or [],
                "scheduled_at": scheduled_str
            }
            all_tasks.append(new_task)
            _save_tasks_file(node_id, all_tasks)
            success_count += 1
        except Exception:
            pass
            
    return {"status": "bulk_scheduled", "affected_nodes": success_count}

# --- CONFIGURACIÓN DEL SISTEMA (SOLO ADMINISTRATOR) ---

@app.get("/api/v1/admin/settings", dependencies=[Depends(require_role(["administrator"]))])
async def admin_get_settings():
    current = load_system_config()
    items = []
    for key, meta in CONFIG_METADATA.items():
        items.append({
            "key": key,
            "label": meta["label"],
            "description": meta["description"],
            "type": meta["type"],
            "value": current.get(key)
        })
    return {"settings": items}

# --- RUTAS DE FRONTEND ---

# app.mount("/static", StaticFiles(directory="web"), name="web")
app.mount("/", StaticFiles(directory="web", html=True), name="web")

@app.get("/")
async def serve_frontend():
    return FileResponse("web/index.html")
