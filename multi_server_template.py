"""
server.py - FastMCP 3.0.2 Multi-Server with Pure ASGI Auth Middleware
======================================================================

Client sends every tool call with:
  x-a3-app-id:   <app_id>
  x-a3-token:    <a3_token>
  x-oidc-token:  <oidc_id_token>

Server:
  1. Pure ASGI middleware validates A3 + decodes OIDC → sets scope["state"]["user"]
  2. combine_lifespans() manages all MCP server lifespans correctly (v3 pattern)
  3. stateless_http=True on http_app() for safe multi-worker deployment
  4. Per-server group enforcement via required_group_ids in MCPServerConfig
"""

import json
import logging
from contextlib import asynccontextmanager
from typing import Any, Callable, Dict, List, Optional, Set

from fastapi import FastAPI, Request
from starlette.types import ASGIApp, Receive, Scope, Send

from fastmcp import FastMCP
from fastmcp.utilities.lifespan import combine_lifespans

from auth import authenticate_request, AuthError, A3Config, OIDCConfig

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# SERVER CONFIGURATION
# ---------------------------------------------------------------------------

class MCPServerConfig:
    def __init__(
        self,
        name: str,
        mount_path: str,
        tools: Optional[List[Callable]] = None,
        resources: Optional[List[Callable]] = None,
        prompts: Optional[List[Callable]] = None,
        required_group_ids: Optional[Set[str]] = None,
        enabled: bool = True,
    ) -> None:
        self.name = name
        self.mount_path = mount_path.rstrip("/")
        self.tools = tools or []
        self.resources = resources or []
        self.prompts = prompts or []
        self.required_group_ids = required_group_ids or set()
        self.enabled = enabled


# ---------------------------------------------------------------------------
# DEFINE YOUR MCP SERVERS (matches Jira ticket group IDs)
# ---------------------------------------------------------------------------

from example_functions import search_for_titles, get_user_profile, create_record

MCP_SERVERS: List[MCPServerConfig] = [
    MCPServerConfig(
        name="one-service",
        mount_path="/one-service",
        tools=[search_for_titles],
        required_group_ids={"1234"},    # from ticket: one-service → group 1234
        enabled=True,
    ),
    MCPServerConfig(
        name="two-service",
        mount_path="/two",
        tools=[get_user_profile, create_record],
        required_group_ids={"4568"},    # from ticket: two → group 4568
        enabled=True,
    ),
]


# ---------------------------------------------------------------------------
# PURE ASGI MIDDLEWARE (NOT BaseHTTPMiddleware — no memory leak)
# ---------------------------------------------------------------------------

# Path prefix → required group IDs (populated at app build time)
_PATH_GROUP_MAP: Dict[str, Set[str]] = {}

SKIP_PATHS: Set[str] = {"/health", "/metrics", "/favicon.ico"}


class A3OIDCMiddleware:
    """
    Pure ASGI middleware.

    On every tool call request:
      - Reads x-a3-app-id, x-a3-token, x-oidc-token headers
      - Validates A3 + decodes OIDC (see auth.py)
      - Checks group membership for the target path
      - Injects UserInfo into scope["state"]["user"]
      - Returns JSON error responses that MCP clients/AI can parse
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        if path in SKIP_PATHS:
            await self.app(scope, receive, send)
            return

        # Parse headers (ASGI headers are list of (bytes, bytes))
        headers: Dict[bytes, str] = {
            k: v.decode("utf-8", errors="ignore")
            for k, v in scope.get("headers", [])
        }

        app_id   = headers.get(A3Config.HEADER_APP_ID.encode(), "")
        a3_token = headers.get(A3Config.HEADER_TOKEN.encode(), "")
        oidc_tok = headers.get(OIDCConfig.HEADER_NAME.encode(), "")

        # Per-path group requirement
        required_groups: Set[str] = set()
        for prefix, groups in _PATH_GROUP_MAP.items():
            if path.startswith(prefix):
                required_groups = groups
                break

        try:
            user = await authenticate_request(
                app_id=app_id,
                a3_token=a3_token,
                oidc_token=oidc_tok,
                required_groups=required_groups,
            )
        except AuthError as e:
            await _send_json_error(scope, receive, send, e.message, e.status_code)
            return
        except Exception:
            logger.exception("Unexpected error in auth middleware")
            await _send_json_error(
                scope, receive, send,
                "Internal authentication error. Please retry or contact platform-support.",
                500,
            )
            return

        # Inject user into scope state
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["user"] = user

        await self.app(scope, receive, send)


async def _send_json_error(
    scope: Scope, receive: Receive, send: Send, message: str, status_code: int
) -> None:
    """Send a JSON response without going through FastAPI routing."""
    body = json.dumps({
        "error": "AuthenticationError",
        "message": message,
        "status_code": status_code,
        "detail": (
            "The AI agent cannot call this tool on behalf of the user. "
            "Ensure A3 token, app_id, and OIDC identity token are all valid "
            "and the user has the required AD group access."
        ),
    }).encode("utf-8")

    await send({
        "type": "http.response.start",
        "status": status_code,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body, "more_body": False})


# ---------------------------------------------------------------------------
# MCP SERVER FACTORY
# ---------------------------------------------------------------------------

def _build_mcp(cfg: MCPServerConfig) -> FastMCP:
    import inspect
    mcp = FastMCP(name=cfg.name)

    for fn in cfg.tools:
        mcp.tool()(fn)

    for fn in cfg.resources:
        params = [
            p for p in inspect.signature(fn).parameters
            if p not in ("ctx", "context", "self")
        ]
        uri = (
            f"{cfg.name}://{'/'.join('{' + p + '}' for p in params)}"
            if params else f"{cfg.name}://static"
        )
        mcp.resource(uri)(fn)

    for fn in cfg.prompts:
        mcp.prompt()(fn)

    return mcp


# ---------------------------------------------------------------------------
# APP FACTORY
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    mcp_infos: List[Dict[str, Any]] = []
    lifespan_fns = []

    for cfg in MCP_SERVERS:
        if not cfg.enabled:
            logger.info(f"⊗ Skipped (disabled): {cfg.name}")
            continue

        mcp_server = _build_mcp(cfg)
        mcp_app = mcp_server.http_app(path="/", stateless_http=True)

        mcp_infos.append({
            "name": cfg.name,
            "mount_path": cfg.mount_path,
            "app": mcp_app,
            "required_groups": cfg.required_group_ids,
        })
        _PATH_GROUP_MAP[cfg.mount_path] = cfg.required_group_ids
        lifespan_fns.append(mcp_app.lifespan)

        logger.info(
            f"✓ Prepared '{cfg.name}' at '{cfg.mount_path}' "
            f"(groups={cfg.required_group_ids})"
        )

    @asynccontextmanager
    async def app_lifespan(application: FastAPI):
        logger.info("🚀 App starting")
        application.state.mcp_infos = mcp_infos
        yield
        logger.info("🛑 App stopping")

    # -----------------------------------------------------------------------
    # V3 LIFESPAN: combine_lifespans — NOT manual __aenter__/__aexit__ loop
    # Enters in order, exits LIFO (last in, first out)
    # -----------------------------------------------------------------------
    lifespan = combine_lifespans(app_lifespan, *lifespan_fns)
    app = FastAPI(title="MCP Server", lifespan=lifespan)

    # Mount MCP servers
    for info in mcp_infos:
        app.mount(info["mount_path"], info["app"])
        logger.info(f"✓ Mounted '{info['name']}' at {info['mount_path']}")

    # -----------------------------------------------------------------------
    # PURE ASGI MIDDLEWARE — wraps entire app, runs before FastAPI routing
    # NOT BaseHTTPMiddleware (memory leak, slower)
    # -----------------------------------------------------------------------
    app.add_middleware(A3OIDCMiddleware)

    # REST endpoints
    @app.get("/health")
    async def health(request: Request):
        return {
            "status": "healthy",
            "servers": [
                {
                    "name": i["name"],
                    "mcp_endpoint": f"{i['mount_path']}/mcp",
                    "required_groups": list(i["required_groups"]),
                }
                for i in request.app.state.mcp_infos
            ],
        }

    @app.get("/me")
    async def whoami(request: Request):
        user = request.state.user
        return {
            "subject": user.subject,
            "email": user.email,
            "name": user.name,
            "groups": list(user.groups),
        }

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, workers=4, reload=False)




















"""
auth.py - Auth pipeline: A3 (app-to-app) + OIDC user identity
===============================================================

Flow:
  1. Client sends every tool call with two headers:
       X-A3-App-ID: <app_id>
       X-A3-Token:  <a3_token>
       X-OIDC-Token: <oidc_id_token>   ← user identity, already obtained by client

  2. Server validates A3 (app-to-app) against your internal A3 service
  3. Server decodes OIDC token (NO signature verify — A3 already proves app trust)
     → extracts user email, name, groups
  4. Returns UserInfo for downstream use in tools

  NO: JWKS, PyJWKClient, issuer/audience validation, RS256 check
      (Those live on the identity provider / client side already)
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

import httpx
import jwt as pyjwt  # PyJWT

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CONFIG (load from env in production)
# ---------------------------------------------------------------------------

class A3Config:
    """A3 app-to-app token validation config."""
    VALIDATION_ENDPOINT: str = "https://a3-internal.your-org.com/validate"
    HEADER_APP_ID: str = "x-a3-app-id"       # Header name (lowercase for ASGI)
    HEADER_TOKEN: str = "x-a3-token"          # Header name (lowercase for ASGI)


class OIDCConfig:
    """OIDC token decoding config — decode only, no signature check."""
    HEADER_NAME: str = "x-oidc-token"         # Header name (lowercase for ASGI)
    GROUPS_CLAIM: str = "groups"              # JWT claim containing user group IDs
    EMAIL_CLAIM: str = "email"
    NAME_CLAIM: str = "name"
    SUBJECT_CLAIM: str = "sub"


# ---------------------------------------------------------------------------
# DATA MODELS
# ---------------------------------------------------------------------------

@dataclass
class UserInfo:
    """User identity decoded from OIDC token."""
    subject: str
    email: str
    name: str
    groups: Set[str]
    raw_claims: Dict[str, Any]


class AuthError(Exception):
    """
    Raised on any auth failure.
    message: safe to surface directly to LLM clients / AI response.
    """
    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


# ---------------------------------------------------------------------------
# STEP 1: A3 VALIDATION (app-to-app)
# ---------------------------------------------------------------------------

async def validate_a3(app_id: str, token: str) -> None:
    """
    Validate A3 app-to-app token against your internal A3 service.
    Raises AuthError with actionable messages on failure.
    """
    if not app_id:
        raise AuthError(
            f"Missing A3 app ID. Expected header: {A3Config.HEADER_APP_ID}.",
            status_code=401,
        )
    if not token:
        raise AuthError(
            f"Missing A3 token. Expected header: {A3Config.HEADER_TOKEN}.",
            status_code=401,
        )

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                A3Config.VALIDATION_ENDPOINT,
                json={"app_id": app_id, "token": token},
                headers={"Content-Type": "application/json"},
            )
    except httpx.TimeoutException:
        raise AuthError(
            "A3 validation service timed out. Please retry. "
            "If this persists, contact platform-support.",
            status_code=503,
        )
    except httpx.RequestError as e:
        raise AuthError(
            f"Could not reach A3 validation service: {e}",
            status_code=503,
        )

    if resp.status_code == 401:
        raise AuthError(
            "A3 token is invalid or expired. "
            "Please re-generate your A3 token via your SSO provider.",
            status_code=401,
        )
    if resp.status_code == 403:
        raise AuthError(
            f"A3 token is not authorized for app_id={app_id}. "
            "Ensure you are using the correct application credentials.",
            status_code=403,
        )
    if not resp.is_success:
        raise AuthError(
            f"A3 service returned unexpected status {resp.status_code}.",
            status_code=502,
        )

    # A3 valid — continue


# ---------------------------------------------------------------------------
# STEP 2: OIDC DECODE (user identity — no signature verify)
# ---------------------------------------------------------------------------

def decode_oidc_token(token: str, required_groups: Optional[Set[str]] = None) -> UserInfo:
    """
    Decode OIDC JWT to extract user identity and groups.
    NO signature verification — A3 already proves the caller is a trusted app.
    Raises AuthError with actionable messages on failure.
    """
    if not token:
        raise AuthError(
            f"Missing OIDC identity token. "
            f"Client must send the user's OIDC ID token in header: {OIDCConfig.HEADER_NAME}.",
            status_code=401,
        )

    try:
        # options: disable all verification — just decode claims
        claims: Dict[str, Any] = pyjwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": True,    # Still check expiry to catch stale tokens
                "verify_aud": False,
                "verify_iss": False,
            },
            algorithms=["RS256", "HS256", "ES256"],
        )
    except pyjwt.ExpiredSignatureError:
        raise AuthError(
            "OIDC identity token has expired. "
            "The client should refresh the token before making tool calls. "
            "Token auto-refresh should handle this automatically.",
            status_code=401,
        )
    except pyjwt.DecodeError as e:
        raise AuthError(
            f"Could not decode OIDC token: {e}. "
            "Ensure the correct OIDC ID token is being sent.",
            status_code=401,
        )

    # Extract user info
    user_groups: Set[str] = set(str(g) for g in claims.get(OIDCConfig.GROUPS_CLAIM, []))

    # Group membership check (per-server)
    if required_groups:
        missing = required_groups - user_groups
        if missing:
            raise AuthError(
                f"Access denied: your account does not have access to this MCP server. "
                f"Required group(s): {', '.join(missing)}. "
                f"Contact the owner of the AD group to request access. "
                f"(You can look up the group owner Directory MCP if enabled.)",
                status_code=403,
            )

    return UserInfo(
        subject=claims.get(OIDCConfig.SUBJECT_CLAIM, ""),
        email=claims.get(OIDCConfig.EMAIL_CLAIM, ""),
        name=claims.get(OIDCConfig.NAME_CLAIM, ""),
        groups=user_groups,
        raw_claims=claims,
    )


# ---------------------------------------------------------------------------
# COMBINED AUTHENTICATOR
# ---------------------------------------------------------------------------

async def authenticate_request(
    app_id: str,
    a3_token: str,
    oidc_token: str,
    required_groups: Optional[Set[str]] = None,
) -> UserInfo:
    """
    Full auth pipeline:
      1. Validate A3 token (app-to-app trust)
      2. Decode OIDC token + check group membership
      3. Return UserInfo

    Raises AuthError with client-safe messages on any failure.
    """
    await validate_a3(app_id, a3_token)
    return decode_oidc_token(oidc_token, required_groups)
















"""
example_functions.py - Tool implementations
=============================================
Shows how to read UserInfo (injected by ASGI middleware) inside tools.

Pattern:
  scope["state"]["user"] is set by A3OIDCMiddleware
  FastMCP exposes the raw ASGI scope via ctx.asgi_scope
"""

import logging
from typing import List, Optional
from fastmcp import Context
from auth import UserInfo

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HELPER - use in any tool that needs user context
# ---------------------------------------------------------------------------

def get_user(ctx: Context) -> Optional[UserInfo]:
    """
    Read UserInfo from ASGI scope state.
    Set by A3OIDCMiddleware before the tool runs.
    Always present when middleware is active.
    """
    return ctx.asgi_scope.get("state", {}).get("user")


# ---------------------------------------------------------------------------
# TOOLS
# ---------------------------------------------------------------------------

async def search_for_titles(query: str, ctx: Context) -> List[str]:
    """Search for titles. Requires group 1234 (enforced by middleware)."""
    user = get_user(ctx)
    logger.info(f"search_for_titles called by {user.email} | query={query!r}")

    # Use user identity for auditing, personalization, or downstream API calls
    # e.g., call your real titles API with user context
    return [
        f"Title result 1 for '{query}'",
        f"Title result 2 for '{query}'",
    ]


async def get_user_profile(user_id: str, ctx: Context) -> dict:
    """Get a user profile. Requires group 4568 (enforced by middleware)."""
    caller = get_user(ctx)
    logger.info(f"get_user_profile called by {caller.email} | user_id={user_id}")

    return {
        "id": user_id,
        "name": "Example User",
        "fetched_by": caller.email,
    }


async def create_record(name: str, data: str, ctx: Context) -> dict:
    """Create a record. Requires group 4568 (enforced by middleware)."""
    caller = get_user(ctx)
    logger.info(f"create_record called by {caller.email}")

    return {
        "id": "rec_001",
        "name": name,
        "data": data,
        "created_by": caller.email,  # Audit trail from OIDC user
    }
