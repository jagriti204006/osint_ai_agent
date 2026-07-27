"""FastAPI application: SSE lookup endpoint plus the static frontend.

Binds to 127.0.0.1 only. API keys live in this process and never reach the
browser — the frontend talks exclusively to this server.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import aggregate, cache, config, enrich, sources
from .detect import ValidationError, build
from .models import IOC_TYPES, LookupResult
from .sanitize import defang

@asynccontextmanager
async def lifespan(app: FastAPI):
    """One HTTP client for the process.

    A client per request meant no connection reuse, which upstreams answered
    with 'Server disconnected' under the concurrent fan-out.
    """
    app.state.client = httpx.AsyncClient(
        timeout=config.HTTP_TIMEOUT,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        headers={"User-Agent": config.USER_AGENT},
        follow_redirects=False,
    )
    try:
        yield
    finally:
        await app.state.client.aclose()


app = FastAPI(
    title="IOC Reputation Lookup", docs_url=None, redoc_url=None, lifespan=lifespan
)

# No 'unsafe-inline' anywhere: the frontend keeps all CSS in a stylesheet and
# builds DOM via textContent, so nothing inline is needed.
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    return response


class LookupRequest(BaseModel):
    ioc: str = Field(min_length=1, max_length=2048)
    type: str = "auto"


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, default=str)}\n\n"


async def _stream(raw_ioc: str, forced: str, client: httpx.AsyncClient) -> AsyncIterator[str]:
    try:
        ind = build(raw_ioc, forced)
    except ValidationError as exc:
        yield _sse("error", {"message": str(exc)})
        return

    selected = sources.for_type(ind.type)
    if not selected:
        yield _sse("error", {"message": f"No sources support '{ind.type}' indicators."})
        return

    yield _sse("start", {
        "ioc": ind.display,
        "type": ind.type,
        "normalized": ind.value,
        "sources": [s.name for s in selected],
    })

    results = []
    tasks = [asyncio.create_task(s.run(ind, client)) for s in selected]
    for completed in asyncio.as_completed(tasks):
        result = await completed
        results.append(result)
        yield _sse("source", result.as_dict())

    verdict, confidence = aggregate.decide(results)
    final = LookupResult(
        ioc=ind.display,
        type=ind.type,
        verdict=verdict,
        confidence=confidence,
        sources=results,
        type_specific=enrich.type_specific(ind, results),
        attack_techniques=enrich.techniques(ind, results),
    )
    final.summary = aggregate.summarize(final)

    payload = final.as_dict()
    payload["defanged"] = defang(ind.display)
    yield _sse("done", payload)


@app.post("/api/lookup")
async def lookup(req: LookupRequest, request: Request) -> StreamingResponse:
    forced = req.type if req.type in IOC_TYPES else "auto"
    return StreamingResponse(
        _stream(req.ioc, forced, request.app.state.client),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@app.post("/api/upload")
async def upload() -> JSONResponse:
    """File submission is refused by design.

    Uploading a sample to a public sandbox exposes it to every other
    researcher and signals to the actor that they have been detected.
    """
    return JSONResponse(
        status_code=403,
        content={
            "error": "File upload is disabled.",
            "detail": "Submitting a file to a public sandbox makes it downloadable "
                      "by third parties. Look the file up by hash instead.",
        },
    )


@app.get("/api/health")
async def health() -> dict:
    configured = [s for s in sources.status() if s["enabled"]]
    return {
        "status": "ok",
        "sources_total": len(sources.status()),
        "sources_enabled": len(configured),
        "sources": sources.status(),
        "file_upload_allowed": False,
        "urlscan_active_scan": config.URLSCAN_ACTIVE_SCAN,
    }


@app.post("/api/cache/purge")
async def purge() -> dict:
    return {"purged": cache.purge_expired()}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(config.FRONTEND_DIR / "index.html")


@app.get("/app.js")
async def appjs() -> FileResponse:
    return FileResponse(config.FRONTEND_DIR / "app.js", media_type="text/javascript")


@app.get("/styles.css")
async def styles() -> FileResponse:
    return FileResponse(config.FRONTEND_DIR / "styles.css", media_type="text/css")


@app.get("/font")
async def font() -> FileResponse:
    return FileResponse(
        config.FRONTEND_DIR / "SpaceGrotesk-VariableFont_wght.ttf",
        media_type="font/ttf",
    )


def run() -> None:
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    run()
