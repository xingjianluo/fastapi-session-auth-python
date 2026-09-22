"""FastAPI 应用入口。

所有安全结论经由 AuthError -> 统一 JSON 错误体 {"error": {"code", "message"}}，
保证各入口（登录、资源、管理）的结论一致、可解释。
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.errors import AuthError, bad_request
from app.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("session_auth")

app = FastAPI(title="session-auth-python", version="0.1.0")
app.include_router(router)


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    logger.warning(
        "security-decision: path=%s method=%s code=%s status=%d detail=%s",
        request.url.path,
        request.method,
        exc.code,
        exc.status_code,
        exc.message,
    )
    return JSONResponse(status_code=exc.status_code, content=exc.to_payload())


@app.exception_handler(RequestValidationError)
async def validation_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    error = bad_request("invalid request body or parameters")
    return JSONResponse(status_code=400, content=error.to_payload())


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
