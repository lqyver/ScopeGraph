from typing import Any
from uuid import uuid4

import structlog
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from scopegraph.normalizers.assets import NormalizationError
from scopegraph.normalizers.imports import ImportParseError


class ScopeGraphError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", uuid4()))


def _error_body(
    *,
    code: str,
    message: str,
    details: dict[str, Any],
    request_id: str,
) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details,
            "request_id": request_id,
        }
    }


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(NormalizationError)
    @app.exception_handler(ImportParseError)
    async def normalization_error_handler(
        request: Request,
        exc: NormalizationError | ImportParseError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=_error_body(
                code="NORMALIZATION_ERROR",
                message=str(exc),
                details={},
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(ScopeGraphError)
    async def scopegraph_error_handler(request: Request, exc: ScopeGraphError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(
                code=exc.code,
                message=exc.message,
                details=exc.details,
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=_error_body(
                code="VALIDATION_ERROR",
                message="Request validation failed",
                details={"errors": jsonable_encoder(exc.errors())},
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = _request_id(request)
        structlog.get_logger().exception(
            "unhandled_request_error",
            request_id=request_id,
            error_type=type(exc).__name__,
        )
        return JSONResponse(
            status_code=500,
            content=_error_body(
                code="INTERNAL_ERROR",
                message="An unexpected error occurred",
                details={},
                request_id=request_id,
            ),
        )
