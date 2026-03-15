"""
PromptWall: OpenAI-compatible proxy that detects and blocks prompt injection.
FastAPI app with /health, /v1/models, /v1/chat/completions, and dashboard endpoints.
"""

import logging
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse

import config
from detection.ml_classifier import MLClassifier
from detection.pipeline import DetectionPipeline
from hardener.prompt_hardener import PromptHardener
from session.manager import SessionManager, _tenant_key

logger = logging.getLogger(__name__)

START_TIME = time.time()
pipeline: DetectionPipeline | None = None
session_manager: SessionManager | None = None
hardener: PromptHardener | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize settings, detection pipeline, session manager; log startup."""
    global pipeline, session_manager, hardener
    try:
        logger.info("Starting PromptWall...")
        config.init_settings()
        pipeline = DetectionPipeline()
        pipeline.ml_classifier = MLClassifier(model_path=config.settings.ML_MODEL_PATH)
        await pipeline.initialize()
        session_manager = SessionManager()
        hardener = PromptHardener()
        app.state.pipeline = pipeline
        app.state.session_mgr = session_manager
        logger.info(
            "PromptWall ready — ML=%s model=promptwall-distilbert Upstream=%s Judge=%s",
            "enabled" if pipeline.ml_classifier.available else "disabled",
            config.settings.UPSTREAM_MODEL,
            config.settings.JUDGE_MODEL,
        )
    except Exception as e:
        logger.exception("Startup failed: %s", e)
        raise
    yield
    logger.info("PromptWall shutting down.")
    pipeline = None
    session_manager = None
    hardener = None


app = FastAPI(title="PromptWall", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _last_user_message(messages: list) -> str:
    """Extract last user message from OpenAI messages array."""
    for m in reversed(messages or []):
        role = (m.get("role") or "").strip().lower()
        if role == "user":
            content = m.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        return part.get("text", "") or ""
                return ""
    return ""


@app.get("/health")
async def health() -> dict:
    """Health check with service name, version, upstream model, ML status, uptime."""
    try:
        ml_loaded = (
            pipeline is not None
            and getattr(pipeline, "ml_classifier", None) is not None
            and getattr(pipeline.ml_classifier, "available", False)
        )
        return {
            "status": "ok",
            "service": "promptwall",
            "version": "1.0.0",
            "upstream_model": config.settings.UPSTREAM_MODEL,
            "ml_enabled": config.settings.ML_ENABLED,
            "ml_loaded": ml_loaded,
            "uptime_seconds": round(time.time() - START_TIME, 2),
        }
    except Exception as e:
        logger.warning("Health check error: %s", e)
        return JSONResponse(
            status_code=503,
            content={"status": "error", "message": str(e)},
        )


@app.get("/v1/models")
async def list_models() -> dict:
    """OpenAI-compatible model list; only exposes UPSTREAM_MODEL."""
    try:
        return {
            "object": "list",
            "data": [
                {
                    "id": config.settings.UPSTREAM_MODEL,
                    "object": "model",
                    "created": int(time.time()),
                }
            ],
        }
    except Exception as e:
        logger.warning("List models error: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """
    Proxy to upstream. Run detection; if blocked return 400 with details.
    If clean, harden prompt, forward, return stream or JSON. Never expose UPSTREAM_API_KEY.
    """
    if pipeline is None or session_manager is None or hardener is None:
        return JSONResponse(status_code=503, content={"error": "Service not ready"})
    try:
        tenant_id = _tenant_key(request.headers.get("X-Tenant-ID") or config.settings.DEFAULT_TENANT_ID)
        session_id = request.headers.get("X-Session-ID") or str(uuid.uuid4())
        body = await request.json()
        messages = body.get("messages", [])
        stream = body.get("stream", False)
        user_message = _last_user_message(messages)
        session = await session_manager.get_session(tenant_id, session_id)
        result = await pipeline.analyze(user_message, session)
        session["score"] = result.score
        session.setdefault("turns", []).append({
            "text": user_message,
            "score": result.score,
            "blocked": result.blocked,
            "timestamp": time.time(),
        })
        if len(session["turns"]) > 10:
            session["turns"] = session["turns"][-10:]
        session["triggered_rules"] = list(set(session.get("triggered_rules", []) + result.rules))
        await session_manager.save_session(tenant_id, session_id, session)
        event = {
            "tenant_id": tenant_id,
            "session_id": session_id,
            "blocked": result.blocked,
            "score": result.score,
            "stage": result.stage,
            "rules": result.rules,
            "technique": result.technique,
            "latency_ms": result.latency_ms,
            "timestamp": time.time(),
        }
        await session_manager.log_event(tenant_id, event)

        if result.blocked:
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": (
                            f"Request blocked by PromptWall. Detected: {result.technique}. "
                            f"Score: {result.score:.2f}"
                        ),
                        "type": "prompt_injection_detected",
                        "code": "blocked",
                        "details": {
                            "score": result.score,
                            "stage": result.stage,
                            "rules": result.rules,
                            "technique": result.technique,
                        },
                    }
                },
                headers={
                    "X-PromptWall-Blocked": "true",
                    "X-PromptWall-Score": str(result.score),
                    "X-PromptWall-Stage": result.stage,
                },
            )

        hardened = hardener.harden(user_message, result.score)
        new_messages = []
        replaced = False
        for i, m in enumerate(messages):
            role = (m.get("role") or "").strip().lower()
            if role == "user" and i == len(messages) - 1:
                new_messages.append({"role": "user", "content": hardened})
                replaced = True
            else:
                new_messages.append(dict(m))
        if not replaced and messages and (messages[-1].get("role") or "").strip().lower() == "user":
            new_messages = list(messages[:-1]) + [{"role": "user", "content": hardened}]
        elif not new_messages:
            new_messages = list(messages)
        payload = {**body, "messages": new_messages, "model": config.settings.UPSTREAM_MODEL}
        req_headers = {
            "Authorization": f"Bearer {config.settings.UPSTREAM_API_KEY}",
            "Content-Type": "application/json",
        }
        upstream_url = f"{config.settings.UPSTREAM_BASE_URL.rstrip('/')}/chat/completions"

        if stream:
            async def stream_forward():
                async with httpx.AsyncClient(timeout=60.0) as client:
                    try:
                        async with client.stream(
                            "POST", upstream_url, json=payload, headers=req_headers
                        ) as r:
                            async for chunk in r.aiter_bytes():
                                yield chunk
                    except (httpx.TimeoutException, httpx.RequestError):
                        yield b"data: {\"error\": \"Upstream unreachable\"}\n\n"
            return StreamingResponse(
                stream_forward(),
                status_code=200,
                headers={
                    "X-PromptWall-Blocked": "false",
                    "X-PromptWall-Score": str(result.score),
                    "Content-Type": "text/event-stream",
                },
            )

        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                r = await client.post(
                    upstream_url,
                    json=payload,
                    headers=req_headers,
                )
            except httpx.TimeoutException:
                return JSONResponse(
                    status_code=503,
                    content={"error": "Upstream request timeout"},
                )
            except httpx.RequestError as e:
                logger.warning("Upstream request error: %s", e)
                return JSONResponse(
                    status_code=503,
                    content={"error": "Upstream unreachable"},
                )
        # Upstream rate limit or server error — return 503 so clients can retry later
        if r.status_code in (429, 503):
            logger.warning("Upstream returned %s (rate limit or unavailable)", r.status_code)
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "message": "Upstream rate limit (429) or unavailable. Retry later.",
                        "type": "upstream_error",
                        "code": "upstream_rate_limit",
                    }
                },
                headers={
                    "X-PromptWall-Blocked": "false",
                    "X-PromptWall-Score": str(result.score),
                },
            )
        try:
            resp_json = r.json()
        except Exception:
            resp_json = {}
        return JSONResponse(
            content=resp_json,
            status_code=r.status_code,
            headers={
                "X-PromptWall-Blocked": "false",
                "X-PromptWall-Score": str(result.score),
            },
        )
    except Exception as e:
        logger.exception("chat_completions error: %s", e)
        return JSONResponse(status_code=500, content={"error": "Internal server error"})


@app.get("/dashboard")
async def dashboard():
    """Serve dashboard static index.html."""
    path = Path(__file__).parent / "dashboard" / "static" / "index.html"
    if not path.exists():
        return JSONResponse(status_code=404, content={"error": "Dashboard not found"})
    return FileResponse(path)


def _dashboard_tenant(request: Request) -> str:
    """Tenant for dashboard: query param 'tenant' or header X-Tenant-ID, else default."""
    return _tenant_key(
        request.query_params.get("tenant") or request.headers.get("X-Tenant-ID") or config.settings.DEFAULT_TENANT_ID
    )


@app.get("/dashboard/events")
async def dashboard_events(request: Request):
    """Return last 100 events for the given tenant (?tenant= or X-Tenant-ID)."""
    if session_manager is None:
        return JSONResponse(status_code=503, content={"error": "Service not ready"})
    try:
        tenant_id = _dashboard_tenant(request)
        events = await session_manager.get_events(tenant_id, limit=100)
        return {"tenant_id": tenant_id, "events": events}
    except Exception as e:
        logger.warning("dashboard_events error: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/dashboard/stats")
async def dashboard_stats(request: Request):
    """Return aggregate stats for the given tenant (?tenant= or X-Tenant-ID)."""
    if session_manager is None:
        return JSONResponse(status_code=503, content={"error": "Service not ready"})
    try:
        tenant_id = _dashboard_tenant(request)
        stats = await session_manager.get_stats(tenant_id)
        return stats
    except Exception as e:
        logger.warning("dashboard_stats error: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.delete("/dashboard/reset")
async def dashboard_reset(request: Request):
    """Reset session state and events for the given tenant (?tenant= or X-Tenant-ID)."""
    if session_manager is None:
        return JSONResponse(status_code=503, content={"error": "Service not ready"})
    try:
        tenant_id = _dashboard_tenant(request)
        await session_manager.reset(tenant_id)
        return {"status": "reset", "tenant_id": tenant_id}
    except Exception as e:
        logger.warning("dashboard_reset error: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.delete("/dashboard/reset-all")
async def dashboard_reset_all():
    """Reset all tenants' session state and events (admin)."""
    if session_manager is None:
        return JSONResponse(status_code=503, content={"error": "Service not ready"})
    try:
        await session_manager.reset_all()
        return {"status": "reset_all"}
    except Exception as e:
        logger.warning("dashboard_reset_all error: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})
