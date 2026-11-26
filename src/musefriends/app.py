"""Starlette HTTP daemon for muse-friends."""
from __future__ import annotations

import contextlib
import json
import os
import pathlib
from datetime import datetime, timezone
from typing import Callable

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .errors import FriendsError
from .identity import IdentityManager
from .pairing import PairingManager
from .store import Store

MAX_REQUEST_BODY_BYTES = 64 * 1024  # 64 KiB cap for pairing requests


def _error_response(exc: FriendsError) -> JSONResponse:
    return JSONResponse(
        {"error": exc.code, "message": exc.message},
        status_code=exc.status_code,
    )


def create_app(
    state_dir: str | pathlib.Path | None = None,
    *,
    rate_limit_per_min: int = 60,
    clock: Callable[[], datetime] | None = None,
) -> Starlette:
    resolved_dir = pathlib.Path(
        state_dir
        if state_dir is not None
        else os.environ.get("MUSE_FRIENDS_STATE_DIR", "data")
    )
    store = Store(resolved_dir)
    identity = IdentityManager(store)
    pairing = PairingManager(store, identity, rate_limit_per_min=rate_limit_per_min)
    now_fn = clock or (lambda: datetime.now(timezone.utc))

    async def health(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "initialized": identity.is_initialized(),
                "schema_version": store.schema_version,
            }
        )

    async def get_card(_request: Request) -> JSONResponse:
        try:
            card = identity.current_card()
        except FriendsError as exc:
            return _error_response(exc)
        return JSONResponse(card)

    async def post_pair_request(request: Request) -> JSONResponse:
        body = await request.body()
        if len(body) > MAX_REQUEST_BODY_BYTES:
            return JSONResponse(
                {"error": "payload_too_large", "message": "request body exceeds limit"},
                status_code=413,
            )
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return JSONResponse(
                {"error": "invalid_request", "message": "body must be valid JSON"},
                status_code=400,
            )
        if not isinstance(payload, dict):
            return JSONResponse(
                {"error": "invalid_request", "message": "body must be a JSON object"},
                status_code=400,
            )
        try:
            result = pairing.submit_request(
                code=payload.get("code"),
                requester_card=payload.get("card"),
                method=request.method,
                path=request.url.path,
                body=body,
                headers=dict(request.headers),
                now=now_fn(),
            )
        except FriendsError as exc:
            return _error_response(exc)
        return JSONResponse(result, status_code=202)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette):
        try:
            yield
        finally:
            store.close()

    routes = [
        Route("/health", health, methods=["GET"]),
        Route("/.well-known/muse-friend.json", get_card, methods=["GET"]),
        Route("/friends/v1/card", get_card, methods=["GET"]),
        Route("/friends/v1/request", post_pair_request, methods=["POST"]),
    ]

    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.store = store
    app.state.identity = identity
    app.state.pairing = pairing
    return app


def main() -> None:
    import uvicorn

    host = os.environ.get("MUSE_FRIENDS_HOST", "127.0.0.1")
    port = int(os.environ.get("MUSE_FRIENDS_PORT", "8321"))
    app = create_app()
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
