"""FastAPI service for the Code Agent."""

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from app.agent_router import VALID_MODES, route
from app.config import (
    API_KEY,
    LOCAL_LLM_URL,
    LOCAL_LLM_MODEL,
    LOCAL_LLM_TIMEOUT,
    LOG_DIR,
    MAX_STEPS,
    PLATFORM_NAME,
    PLATFORM_VERSION,
    SCHEMA_VERSION,
)
from app.environment_probe import invalidate_cache, probe_environment
from tools.audit_log import get_recent_calls, get_run_list, get_tool_stats
from tools.registry import list_all_tools, toggle_tool

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ai_kavach.agent_server")

app = FastAPI(
    title=PLATFORM_NAME,
    description="Local Code Agent service",
    version=PLATFORM_VERSION,
    docs_url=None,
    redoc_url=None,
)

security = HTTPBearer(auto_error=False)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    if not API_KEY:
        return ""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization header required")
    if credentials.credentials != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials.credentials


class AgentRunRequest(BaseModel):
    task: str = Field(..., description="Natural language task description")
    task_id: Optional[str] = Field(None, description="Unique run ID")
    max_steps: int = Field(MAX_STEPS, ge=1, le=50)
    mode: str = Field("auto", description="Code Agent mode")
    target: Optional[str] = Field(None, description="Code path or HTTP target")
    log_path: Optional[str] = Field(None, description="Output or log path")


class ToolToggleRequest(BaseModel):
    enabled: bool


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    request_id = str(uuid.uuid4())[:8]
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Duration-Ms"] = str(round((time.time() - start) * 1000))
        return response
    except Exception:
        logger.exception("[%s] request failed", request_id)
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "Internal server error", "request_id": request_id},
        )


@app.post("/v1/agent/run")
async def run_agent(request: AgentRunRequest, token: str = Depends(verify_token)):
    if request.mode not in VALID_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode '{request.mode}'. Valid modes: {sorted(VALID_MODES)}",
        )

    task_id = request.task_id or f"{request.mode}_{uuid.uuid4().hex[:8]}"
    logger.info("[%s] task received | mode=%s | target=%s", task_id, request.mode, request.target)

    try:
        return route(
            task=request.task,
            task_id=task_id,
            mode=request.mode,
            target=request.target,
            log_path=request.log_path,
            max_steps=request.max_steps,
        )
    except Exception as exc:
        logger.exception("[%s] pipeline failed", task_id)
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "task_id": task_id,
                "mode": request.mode,
                "final_answer": {},
                "stages": {},
                "steps_taken": 0,
                "duration_seconds": 0,
                "tools_used": [],
                "error": f"{type(exc).__name__}: {exc}",
            },
        )


@app.post("/v1/chat/completions")
async def chat_completions(request: Request, token: str = Depends(verify_token)):
    body = await request.json()
    body["model"] = LOCAL_LLM_MODEL
    async with httpx.AsyncClient(timeout=LOCAL_LLM_TIMEOUT) as client:
        response = await client.post(
            f"{LOCAL_LLM_URL}/v1/chat/completions",
            json=body,
            headers={"Content-Type": "application/json"},
        )
    return JSONResponse(content=response.json(), status_code=response.status_code)


@app.get("/health")
async def health_check():
    env = probe_environment()
    llm_ok = env.get("ollama_running", False)
    model_ok = env.get("model_loaded", False)
    disk_ok = env.get("disk_free_gb", 0) > 1.0
    healthy = llm_ok and model_ok and disk_ok
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={
            "status": "healthy" if healthy else "degraded",
            "platform": PLATFORM_NAME,
            "version": PLATFORM_VERSION,
            "schema_version": SCHEMA_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": {
                "agent_server": "running",
                "local_llm": "running" if llm_ok else "unreachable",
                "model": env.get("model_name"),
                "model_loaded": model_ok,
            },
            "system": {
                "os": env.get("os"),
                "cpu_count": env.get("cpu_count"),
                "ram_total_gb": env.get("ram_total_gb"),
                "ram_available_gb": env.get("ram_available_gb"),
                "disk_free_gb": env.get("disk_free_gb"),
            },
            "tools": {
                "available": env.get("tools_available", []),
                "missing": env.get("tools_missing", []),
            },
            "warnings": env.get("warnings", []),
        },
    )


@app.get("/v1/tools")
async def get_tools(token: str = Depends(verify_token)):
    tools = list_all_tools()
    env = probe_environment()
    return {
        "tools": tools,
        "tool_count": len(tools),
        "enabled_count": sum(1 for tool in tools if tool.get("enabled")),
        "available_count": sum(1 for tool in tools if tool.get("available")),
        "tools_available": env.get("tools_available", []),
        "tools_missing": env.get("tools_missing", []),
    }


@app.post("/v1/tools/{tool_name}/toggle")
async def toggle_tool_endpoint(tool_name: str, request: ToolToggleRequest, token: str = Depends(verify_token)):
    try:
        return toggle_tool(tool_name, request.enabled)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/v1/runs")
async def list_runs(token: str = Depends(verify_token)):
    return {"runs": get_run_list()}


@app.get("/v1/runs/{task_id}")
async def get_run(task_id: str, token: str = Depends(verify_token)):
    calls = get_recent_calls(task_id=task_id, limit=1000)
    if not calls:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"task_id": task_id, "tool_calls": calls}


@app.get("/v1/tools/stats")
async def tool_stats(token: str = Depends(verify_token)):
    return get_tool_stats()


@app.post("/v1/environment/refresh")
async def refresh_environment(token: str = Depends(verify_token)):
    invalidate_cache()
    return probe_environment()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.agent_server:app", host="0.0.0.0", port=8082, reload=False)
