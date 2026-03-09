import operator
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware
import jwt

# -------------------------
# Logging
# -------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------------
# JWT configuration
# Secret is mounted from a Kubernetes Secret at /jwt/jwt.secret.
# Audience and issuer are fixed strings shared between client and server.
# -------------------------

_JWT_SECRET_PATH = os.getenv("JWT_SECRET_PATH", "/jwt/jwt.secret")
_JWT_ALGORITHM   = "HS256"
JWT_ISSUER       = "exploit-client"
JWT_AUDIENCE     = "vuln-server"
JWT_LEEWAY_SEC   = 10   # clock-skew tolerance


def _load_jwt_secret() -> str:
    try:
        secret = open(_JWT_SECRET_PATH).read().strip()
    except OSError as exc:
        raise RuntimeError(f"Cannot read JWT secret from {_JWT_SECRET_PATH}: {exc}") from exc
    if len(secret) < 32:
        raise RuntimeError("JWT secret must be at least 32 characters")
    return secret


# Load once at startup; the value never changes during the pod's lifetime.
JWT_SECRET: str = _load_jwt_secret()

# -------------------------
# Rate limiter (slowapi — drop-in for FastAPI)
# -------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=["20/minute"])

# -------------------------
# App
# -------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Server starting up")
    yield
    logger.info("Server shutting down")

app = FastAPI(
    title="Secure Compute Server",
    docs_url=None,   # disable Swagger UI in production
    redoc_url=None,
    lifespan=lifespan,
)

# Attach rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# -------------------------
# Security headers middleware
# -------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# -------------------------
# Request size limit middleware (1 KB)
# -------------------------

MAX_BODY_SIZE = 1024  # bytes

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_BODY_SIZE:
            return JSONResponse(
                status_code=413,
                content={"error": "Request body too large"},
            )
        return await call_next(request)

app.add_middleware(RequestSizeLimitMiddleware)

# -------------------------
# JWT bearer dependency
# -------------------------

_bearer = HTTPBearer(auto_error=False)

async def require_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    """
    Validates the Bearer JWT in the Authorization header.
    Raises HTTP 401 for missing/invalid tokens, 403 for wrong audience/issuer.
    Returns the decoded payload so routes can inspect claims if needed.
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[_JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            leeway=JWT_LEEWAY_SEC,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidAudienceError:
        raise HTTPException(status_code=403, detail="Invalid token audience")
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=403, detail="Invalid token issuer")
    except jwt.PyJWTError as exc:
        logger.warning("JWT validation failed: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid token")

    return payload

# -------------------------
# Allowed operations
# -------------------------

ALLOWED_OPERATIONS = {
    "add": operator.add,
    "sub": operator.sub,
    "mul": operator.mul,
    "div": operator.truediv,
}

# -------------------------
# Request schema (Pydantic v2)
# -------------------------

class ComputeRequest(BaseModel):
    operation: str
    a: float
    b: float

    @field_validator("operation")
    @classmethod
    def operation_must_be_allowed(cls, v: str) -> str:
        if v not in ALLOWED_OPERATIONS:
            raise ValueError(f"Unsupported operation '{v}'")
        return v

# -------------------------
# Error handlers
# -------------------------

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=404, content={"error": "Not found"})

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"error": "Internal server error"})

# -------------------------
# Routes
# -------------------------

@app.get("/health")
async def health():
    """Kubernetes liveness / readiness probe — no auth required."""
    return {"status": "ok"}


@app.get("/")
@limiter.limit("10/minute")
async def home(request: Request, _: dict = Depends(require_jwt)):
    return {"status": "Server running"}


@app.post("/run")
@limiter.limit("10/minute")
async def run(
    request: Request,
    body: ComputeRequest,
    token_payload: dict = Depends(require_jwt),
):
    """Perform an arithmetic operation and return the result."""
    try:
        result = ALLOWED_OPERATIONS[body.operation](body.a, body.b)
    except ZeroDivisionError:
        raise HTTPException(status_code=400, detail="Division by zero")

    logger.info(
        "Operation executed: %s %s %s (sub=%s)",
        body.a, body.operation, body.b,
        token_payload.get("sub"),
    )

    return {
        "operation": body.operation,
        "a": body.a,
        "b": body.b,
        "result": result,
    }


# -------------------------
# Entrypoint — build an ssl.SSLContext explicitly so ALPN protocols
# are advertised. uvicorn.Config accepts ssl_certfile/ssl_keyfile to
# enable TLS; we then replace the internally-created context with our
# own (which has set_alpn_protocols) before starting the server.
# -------------------------
if __name__ == "__main__":
    import ssl
    import uvicorn

    TLS_CERT = "/tls/tls.crt"
    TLS_KEY  = "/tls/tls.key"

    config = uvicorn.Config(
        "app:app",
        host="0.0.0.0",
        port=8443,
        ssl_certfile=TLS_CERT,
        ssl_keyfile=TLS_KEY,
        log_level="info",
        access_log=False,
    )

    # Load the config so uvicorn creates its internal SSL context,
    # then replace it with ours that explicitly sets ALPN and TLS 1.2+.
    config.load()
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_ctx.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
    ssl_ctx.set_alpn_protocols(["http/1.1"])
    config.ssl = ssl_ctx

    server = uvicorn.Server(config)
    server.run()
