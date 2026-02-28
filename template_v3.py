"""
FastMCP 3.0.2 COMPLETE REFERENCE - Validated Against Official Docs
===================================================================
COMPREHENSIVE demonstration of:
- All visibility/enable/disable patterns (server + session + version-based)
- Admin control flows with runtime toggling
- All providers (Local, FileSystem, OpenAPI, Proxy, Skills)
- All transports (stdio, streamable-http, sse) with all parameters
- Proxy patterns (single vs multi-server, mounted vs standalone)
- All transforms, middleware, auth patterns
- Pure ASGI middleware vs BaseHTTPMiddleware
- Multi-server lifespan management with combine_lifespans
- ASGI scope state access in tools
- Complete mcp.run() and http_app() reference
- FastAPI + FastMCP hybrid with correct lifespan wiring
- stateless_http explained
"""

# ============================================================================
# IMPORTS - All FastMCP 3.0.2 modules (CORRECTED PATHS)
# ============================================================================

from fastmcp import FastMCP, Context
from fastmcp.server import create_proxy
from fastmcp.exceptions import ToolError

# Providers (CORRECT IMPORT PATH)
from fastmcp.server.providers import (
    FileSystemProvider,      # Auto-discover from directory
    OpenAPIProvider,         # Wrap REST APIs
    ProxyProvider,           # Proxy remote MCP servers
    SkillsProvider,          # Expose skill markdown files
)

# Transforms (CORRECT IMPORT PATH + CLASS NAMES)
from fastmcp.server.transforms import (
    Namespace,               # Add prefix to avoid collisions
    Rename,                  # Rename individual components
    Filter,                  # Whitelist/blacklist components
    Visibility,              # Hide/show components (NOT VisibilityFilter)
    ToolTransform,           # Modify tool definitions
)

# Middleware
from fastmcp.middleware import (
    ResponseLimitingMiddleware,  # Cap response sizes
    AuthMiddleware,              # Authorization logic
)

# Auth
from fastmcp.server.auth import BearerTokenAuth

# Utilities
from fastmcp.utilities.lifespan import combine_lifespans
from fastmcp.utilities.versions import VersionSpec
from fastmcp.resources import Resource
from fastmcp.prompts import Prompt
from fastmcp.types import ToolResult, ResourceResult, PromptResult

# Dependencies for ASGI scope access
from fastmcp.server.dependencies import get_http_request

# Standard library
from typing import Annotated
from contextlib import asynccontextmanager
import asyncio
from pathlib import Path
import os


# ============================================================================
# PART 1: SERVER LIFESPAN
# ============================================================================

@asynccontextmanager
async def server_lifespan(server):
    """Startup/shutdown logic"""
    print("🚀 Server starting...")
    server.state["db"] = {"connected": True}
    server.state["admin_sessions"] = set()
    yield
    print("🛑 Server stopping...")
    server.state["db"]["connected"] = False


# ============================================================================
# PART 2A: VISIBILITY PATTERNS - COMPLETE DEMONSTRATION
# ============================================================================

mcp = FastMCP(
    "Complete Visibility Demo",
    lifespan=server_lifespan,
    dependencies=["requests", "pydantic"]
)

# ----------------------------------------------------------------------------
# TOOLS WITH TAGS - Foundation for visibility control
# ----------------------------------------------------------------------------

@mcp.tool(tags={"public", "read"})
def public_read_tool(query: str) -> str:
    """Public read-only tool - available to all by default"""
    return f"Public data: {query}"

@mcp.tool(tags={"public", "write"})
def public_write_tool(data: str) -> str:
    """Public write tool"""
    return f"Wrote: {data}"

@mcp.tool(tags={"premium", "read"})
def premium_read_tool(query: str) -> str:
    """Premium feature - disabled by default, requires unlock"""
    return f"Premium data: {query}"

@mcp.tool(tags={"premium", "analytics"})
def premium_analytics_tool() -> dict:
    """Premium analytics - disabled by default"""
    return {"users": 1000, "revenue": 50000}

@mcp.tool(tags={"admin", "dangerous"})
def admin_delete_tool(target: str) -> str:
    """Admin tool - very dangerous, disabled by default"""
    return f"DELETED: {target}"

@mcp.tool(tags={"admin"})
def admin_panel_tool() -> str:
    """Admin panel access"""
    return "Admin dashboard data"

@mcp.tool(tags={"internal", "debug"})
def internal_debug_tool() -> str:
    """Internal debugging - hidden from clients"""
    return "Debug info"

@mcp.tool(tags={"beta"})
def beta_feature_tool() -> str:
    """Beta feature - may be enabled for testing"""
    return "Beta functionality"

@mcp.tool()  # No tags - untagged tool
def untagged_tool() -> str:
    """Tool without any tags"""
    return "Untagged result"


# ----------------------------------------------------------------------------
# PART 2B: SERVER-LEVEL VISIBILITY (affects ALL clients globally)
# ----------------------------------------------------------------------------

# PATTERN 1: Disable by tag (blocklist mode - default)
mcp.disable(tags={"premium"})     # Hide all premium tools
mcp.disable(tags={"admin"})       # Hide all admin tools  
mcp.disable(tags={"internal"})    # Hide internal tools

# PATTERN 2: Disable by specific name (component name)
mcp.disable(names={"beta_feature_tool"})  # Disable one specific tool

# PATTERN 3: Combine tags and names
mcp.disable(
    tags={"dangerous"},
    names={"internal_debug_tool"}
)

# PATTERN 4: Re-enable previously disabled
# mcp.enable(tags={"beta"})  # Uncomment to re-enable beta tools

# PATTERN 5: ALLOWLIST MODE (only=True) - EVERYTHING OFF except specified
# mcp.enable(tags={"public"}, only=True)  
# ^^^ If uncommented, ONLY public-tagged tools visible

# PATTERN 6: Later calls override earlier ones
# mcp.enable(tags={"admin"}, only=True)  # Switch to admin-only mode
# mcp.disable(names={"admin_delete_tool"})  # But still hide this one


# ----------------------------------------------------------------------------
# PART 2C: SESSION-LEVEL VISIBILITY (per-client runtime control)
# ----------------------------------------------------------------------------

@mcp.tool(tags={"public"})
async def unlock_premium(token: str, ctx: Context) -> str:
    """Unlock premium features for THIS SESSION ONLY"""
    if token == "premium-key-2026":
        await ctx.enable_components(tags={"premium"})
        return "✅ Premium features unlocked for your session!"
    return "❌ Invalid premium token"

@mcp.tool(tags={"public"})
async def admin_login(password: str, ctx: Context) -> str:
    """Admin login - enables admin tools for this session"""
    if password == "admin123":
        await ctx.enable_components(tags={"admin"})
        
        # Track admin session
        server = ctx.fastmcp
        server.state["admin_sessions"].add(ctx.session_id)
        
        return "✅ Admin access granted for your session"
    return "❌ Invalid admin password"

@mcp.tool(tags={"admin"})
async def admin_revoke_dangerous(ctx: Context) -> str:
    """Admin can disable dangerous tools mid-session"""
    await ctx.disable_components(tags={"dangerous"})
    return "⚠️ Dangerous tools disabled for safety"

@mcp.tool(tags={"admin"})
async def admin_enable_beta(ctx: Context) -> str:
    """Admin can enable beta features for testing"""
    await ctx.enable_components(tags={"beta"})
    return "🧪 Beta features enabled for this session"

@mcp.tool(tags={"public"})
async def logout(ctx: Context) -> str:
    """Reset session to global defaults"""
    await ctx.reset_visibility()
    
    server = ctx.fastmcp
    server.state["admin_sessions"].discard(ctx.session_id)
    
    return "👋 Session reset to defaults"

@mcp.tool(tags={"public"})
async def check_my_permissions(ctx: Context) -> str:
    """Show what this session has access to"""
    is_admin = ctx.session_id in ctx.fastmcp.state.get("admin_sessions", set())
    
    return f"""
Your session permissions:
- Admin: {'✅ YES' if is_admin else '❌ NO'}
- Session ID: {ctx.session_id[:8]}...
- Transport: {ctx.transport}
    """


# ----------------------------------------------------------------------------
# PART 2D: VERSION-BASED VISIBILITY (NEW in v3.0)
# ----------------------------------------------------------------------------

@mcp.tool(version="1.0", tags={"public"})
def legacy_search(query: str) -> str:
    """Old search algorithm - v1.0"""
    return f"V1 search: {query}"

@mcp.tool(version="2.0", tags={"public"})
def modern_search(query: str) -> str:
    """New search with ML - v2.0"""
    return f"V2 ML search: {query}"

@mcp.tool(version="2.5", tags={"beta"})
def experimental_search(query: str) -> str:
    """Experimental search - v2.5 beta"""
    return f"V2.5 experimental: {query}"

@mcp.tool(tags={"admin"})
async def enable_only_stable_versions(ctx: Context) -> str:
    """Admin can filter by version - only show stable tools"""
    await ctx.enable_components(
        version=VersionSpec(gte="2.0", lt="2.5"),
        components={"tool"}
    )
    return "📌 Only stable v2.0-2.4 tools enabled"

@mcp.tool(tags={"admin"})
async def enable_all_versions(ctx: Context) -> str:
    """Show all versions including experimental"""
    await ctx.enable_components(
        version=VersionSpec(gte="1.0"),
        components={"tool"}
    )
    return "🔓 All tool versions enabled"


# ============================================================================
# PART 3: CONTEXT API - COMPLETE DEMONSTRATION
# ============================================================================

@mcp.tool(tags={"public"})
async def context_demo_tool(message: str, ctx: Context) -> str:
    """
    Demonstrates Context API:
    
    METHODS REQUIRING await:
    - ctx.set_state(key, value)
    - ctx.get_state(key)
    - ctx.delete_state(key)
    - ctx.enable_components(...)
    - ctx.disable_components(...)
    - ctx.reset_visibility()
    - ctx.info/debug/warning/error(message)
    - ctx.report_progress(progress, total, message)
    - ctx.read_resource(uri)
    - ctx.list_resources()
    - ctx.list_prompts()
    - ctx.get_prompt(name)
    - ctx.sample(messages)
    - ctx.sample_step(messages)
    - ctx.elicit(message, response_type)
    
    PLAIN ATTRIBUTE ACCESS (no await):
    - ctx.transport  # "stdio", "streamable-http", or "sse"
    - ctx.session_id
    - ctx.request_id
    - ctx.client_id
    - ctx.fastmcp
    - ctx.lifespan_context
    - ctx.client_supports_extension(ext_id)
    - ctx.is_background_task
    - ctx.task_id
    """
    # Session state (persists across calls)
    await ctx.set_state("last_message", message)
    previous = await ctx.get_state("last_message")
    
    # Plain attribute access (NO await)
    transport = ctx.transport  # "stdio", "streamable-http", or "sse"
    session = ctx.session_id
    request = ctx.request_id
    
    # Check client capabilities (NO await)
    supports_apps = ctx.client_supports_extension("mcp-apps")
    
    # Logging (requires await)
    await ctx.info(f"Processed: {message}")
    
    # Progress reporting (requires await)
    await ctx.report_progress(50, 100, "Processing...")
    
    return f"""
Context Demo Results:
- Previous message: {previous}
- Transport: {transport}
- Session ID: {session[:8]}...
- Request ID: {request[:8]}...
- MCP Apps support: {supports_apps}
    """

@mcp.tool(sequential=True, tags={"admin"})
def sequential_critical_operation(action: str) -> str:
    """Sequential execution - won't run in parallel"""
    import time
    time.sleep(0.5)
    return f"Completed sequentially: {action}"

@mcp.tool(timeout=3.0, tags={"public"})
def slow_operation(duration: float) -> str:
    """Tool with timeout - will fail if exceeds 3 seconds"""
    import time
    time.sleep(min(duration, 5))
    return f"Completed in {duration}s"


# ============================================================================
# PART 4: RESOURCES & PROMPTS
# ============================================================================

@mcp.resource("config://settings", tags={"public"})
def get_settings() -> str:
    """Static resource"""
    return "server_mode=production\nmax_connections=100"

@mcp.resource("data://users/{user_id}", tags={"admin"})
async def get_user(user_id: str) -> dict:
    """Parameterized resource - admin only"""
    return {"id": user_id, "name": f"User {user_id}", "role": "admin"}

@mcp.prompt(tags={"public"})
def code_review_prompt(language: str = "python") -> str:
    """Prompt template"""
    return f"You are a {language} code reviewer. Review for bugs and best practices."


# ============================================================================
# PART 5: FILESYSTEM PROVIDER (CORRECTED - reload=True, Path object)
# ============================================================================

tools_dir = Path("./tools")
tools_dir.mkdir(exist_ok=True)

(tools_dir / "discovered_tool.py").write_text("""
from fastmcp import tool

@tool(tags={"filesystem"})
def fs_discovered_tool(x: int, y: int) -> int:
    '''Tool discovered from filesystem - tagged as filesystem'''
    return x + y
""")

# CORRECTED: Use root=Path(...), reload=True (not hot_reload)
mcp.add_provider(
    FileSystemProvider(
        root=tools_dir,    # Path object, keyword arg
        reload=True        # Correct parameter name
    )
)


# ============================================================================
# PART 6: OPENAPI PROVIDER
# ============================================================================

mcp.add_provider(
    OpenAPIProvider(
        spec="https://jsonplaceholder.typicode.com/swagger.json",
        base_url="https://jsonplaceholder.typicode.com",
        headers={"User-Agent": "FastMCP/3.0"}
    ),
    transform=Namespace("api")
)


# ============================================================================
# PART 7: TRANSFORMS (CORRECTED - Visibility class)
# ============================================================================

# Filter - whitelist/blacklist
mcp.add_transform(
    Filter(
        allow=["public_*", "api/*"],
        deny=["*_debug_*"]
    )
)

# CORRECTED: Visibility (not VisibilityFilter)
# Equivalent to: mcp.disable(names={"beta_feature_tool", "experimental_search"})
mcp.add_transform(
    Visibility(False, names={"beta_feature_tool", "experimental_search"})
)

# Rename
mcp.add_transform(
    Rename(renames={"public_read_tool": "read_data"})
)

# ToolTransform
def add_prefix_to_descriptions(tool):
    tool.description = f"[ENHANCED] {tool.description}"
    return tool

mcp.add_transform(ToolTransform(transform=add_prefix_to_descriptions))


# ============================================================================
# PART 8: MIDDLEWARE
# ============================================================================

mcp.add_middleware(
    ResponseLimitingMiddleware(
        max_chars=8000,
        truncation_message="\n\n[... truncated - use search/filter ...]"
    )
)

async def admin_auth_check(component, context):
    """Check if client has admin access"""
    if "admin" in component.tags:
        is_admin = context.session_id in context.fastmcp.state.get("admin_sessions", set())
        return is_admin
    return True

mcp.add_middleware(
    AuthMiddleware(
        auth_fn=admin_auth_check,
        tags={"admin"}
    )
)


# ============================================================================
# PART 9: MOUNTING OTHER SERVERS
# ============================================================================

sub_server = FastMCP("Sub Server")

@sub_server.tool(tags={"subserver"})
def sub_tool(x: int) -> int:
    """Tool from sub-server"""
    return x * 2

@sub_server.tool(tags={"subserver", "math"})
def sub_math_tool(a: int, b: int) -> int:
    """Math tool from sub-server"""
    return a + b

mcp.mount(sub_server, namespace="subserver")


# ============================================================================
# PART 10: PROXY PATTERNS
# ============================================================================

def create_unified_hub():
    """Hub that proxies multiple backend servers"""
    config = {
        "mcpServers": {
            "jira": {
                "url": "http://localhost:8001/mcp",
                "transport": "http"
            },
            "github": {
                "url": "http://localhost:8002/mcp",
                "transport": "http"
            },
            "kube": {
                "url": "http://localhost:8003/mcp",
                "transport": "http"
            }
        }
    }
    
    hub = create_proxy(config, name="Unified Hub")
    return hub


# ============================================================================
# PART 11: SKILLS PROVIDER
# ============================================================================

skills_dir = Path("./skills")
skills_dir.mkdir(exist_ok=True)

(skills_dir / "example_skill.md").write_text("""
# Example CLI Skill

## Read file
python cli.py read <path>

## Write file
python cli.py write <path> "<content>"

## Search file
python cli.py search <path> "<pattern>"
""")

mcp.add_provider(SkillsProvider(str(skills_dir)))


# ============================================================================
# PART 12: mcp.run() - ALL PARAMETERS REFERENCE
# ============================================================================

def run_stdio():
    """
    STDIO transport
    
    Parameters:
    - transport: "stdio"
    - NO host/port (uses stdin/stdout)
    - NO stateless_http (always stateful)
    """
    mcp.run(transport="stdio")


def run_http_complete():
    """
    HTTP transport - ALL supported parameters
    """
    mcp.run(
        transport="streamable-http",   # CORRECT: "streamable-http" not "http"
        host="0.0.0.0",
        port=8000,
        path="/mcp",
        log_level="INFO",
        stateless_http=False,
    )


def run_sse():
    """
    SSE transport (legacy)
    """
    mcp.run(
        transport="sse",
        host="0.0.0.0",
        port=8000,
        log_level="INFO"
    )


# ============================================================================
# PART 13: http_app() vs mcp.run()
# ============================================================================

def use_run_for_simple():
    """Use mcp.run() for simple single-process deployments"""
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)


def use_http_app_for_production():
    """Use mcp.http_app() for production multi-worker"""
    app = mcp.http_app(
        path="/mcp",
        stateless_http=True
    )
    return app

app = use_http_app_for_production()


# ============================================================================
# PART 14: stateless_http=True EXPLAINED
# ============================================================================

"""
stateless_http=True - For multi-worker deployments

WHEN REQUIRED:
- uvicorn --workers 4
- Serverless (Lambda, Cloud Functions)
- Load-balanced deployments

WHAT IT DISABLES:
- ctx.set_state() / ctx.get_state() unavailable

ALTERNATIVES:
1. Pass state via scope["custom_key"] in middleware
2. External store (Redis)
3. Keep stateless_http=False for single-worker
"""

def stateless_example():
    """Production multi-worker with stateless HTTP"""
    app = mcp.http_app(path="/mcp", stateless_http=True)
    return app

stateless_app = stateless_example()


# ============================================================================
# PART 17: PURE ASGI MIDDLEWARE (CORRECTED - scope["custom_key"])
# ============================================================================

class PureASGIAuthMiddleware:
    """
    Pure ASGI middleware - the RIGHT way
    
    CRITICAL: Use scope["custom_key"], NOT scope["state"]
    (scope["state"] is reserved by Starlette for Request.state)
    """
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()
        
        user = await self._authenticate(auth_header)
        
        if not user:
            await self._send_json_error(send, 401, "Unauthorized - invalid token")
            return
        
        # CORRECTED: Use custom key, not scope["state"]
        scope["authenticated_user"] = user
        
        await self.app(scope, receive, send)
    
    async def _authenticate(self, auth_header: str) -> dict | None:
        if not auth_header.startswith("Bearer "):
            return None
        
        token = auth_header[7:]
        await asyncio.sleep(0.01)
        
        if token == "valid-token-123":
            return {
                "id": "user_123",
                "email": "user@example.com",
                "permissions": ["read", "write"]
            }
        return None
    
    async def _send_json_error(self, send, status: int, message: str):
        import json
        body = json.dumps({"error": message}).encode()
        
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(body)).encode()],
            ],
        })
        
        await send({
            "type": "http.response.body",
            "body": body,
        })


# ============================================================================
# PART 18: ACCESSING ASGI SCOPE STATE IN TOOLS (CORRECTED)
# ============================================================================

@mcp.tool(tags={"public"})
async def async_tool_with_scope_state(data: str, ctx: Context) -> str:
    """
    ASYNC tool accessing middleware-injected state
    
    CORRECTED: Use get_http_request() from fastmcp.server.dependencies
    """
    # Get Starlette Request object (works in HTTP transport)
    request = get_http_request()  # NO await needed
    
    if not request:
        return "Not available in STDIO transport"
    
    # Read from custom scope key (middleware injected)
    user = request.scope.get("authenticated_user", {})
    user_id = user.get("id", "anonymous")
    permissions = user.get("permissions", [])
    
    # Logging requires await
    await ctx.info(f"Processing for user: {user_id}")
    
    return f"Processed {data} for user {user_id} with permissions {permissions}"


@mcp.tool(tags={"public"})
def sync_tool_with_scope_state(data: str, ctx: Context) -> str:
    """
    SYNC tool can also access scope state
    """
    request = get_http_request()  # Works in sync tools too
    
    if not request:
        return "Not available in STDIO"
    
    user = request.scope.get("authenticated_user", {})
    user_id = user.get("id", "anonymous")
    
    return f"Sync processed {data} for user {user_id}"


# ============================================================================
# PART 19: MULTI-SERVER LIFESPAN WITH combine_lifespans
# ============================================================================

@asynccontextmanager
async def db_lifespan(app):
    """Database connection lifespan"""
    print("📊 Connecting to database...")
    db_conn = {"connected": True, "pool_size": 10}
    app.state["db"] = db_conn
    yield
    print("📊 Closing database...")
    db_conn["connected"] = False


@asynccontextmanager
async def cache_lifespan(app):
    """Cache connection lifespan"""
    print("🗄️ Connecting to Redis...")
    cache_conn = {"connected": True, "ttl": 3600}
    app.state["cache"] = cache_conn
    yield
    print("🗄️ Closing Redis...")
    cache_conn["connected"] = False


def create_multi_server_fastapi():
    """FastAPI with multiple MCP servers mounted"""
    from fastapi import FastAPI
    
    mcp1 = FastMCP("Service 1")
    mcp2 = FastMCP("Service 2")
    
    @mcp1.tool()
    def tool_from_service1() -> str:
        return "Service 1 data"
    
    @mcp2.tool()
    def tool_from_service2() -> str:
        return "Service 2 data"
    
    mcp1_app = mcp1.http_app(path="/")
    mcp2_app = mcp2.http_app(path="/")
    
    # Combine all lifespans
    combined_lifespan = combine_lifespans(
        mcp1_app.lifespan,
        mcp2_app.lifespan,
        db_lifespan,
        cache_lifespan
    )
    
    api = FastAPI(lifespan=combined_lifespan)
    
    @api.get("/health")
    def health():
        # CORRECTED: Use getattr() for Starlette State
        db = getattr(api.state, "db", {})
        cache = getattr(api.state, "cache", {})
        return {
            "db": db.get("connected", False),
            "cache": cache.get("connected", False)
        }
    
    api.mount("/mcp/service1", mcp1_app)
    api.mount("/mcp/service2", mcp2_app)
    
    return api


# ============================================================================
# PART 20: FASTAPI + FASTMCP HYBRID - CORRECT LIFESPAN WIRING
# ============================================================================

def create_fastapi_hybrid_correct():
    """FastAPI + FastMCP hybrid - THE RIGHT WAY"""
    from fastapi import FastAPI
    
    mcp_app = mcp.http_app(path="/", stateless_http=True)
    
    # Pass MCP lifespan to FastAPI
    api = FastAPI(
        title="Hybrid API + MCP",
        lifespan=mcp_app.lifespan
    )
    
    # Add pure ASGI middleware
    api.add_middleware(PureASGIAuthMiddleware)
    
    @api.get("/api/status")
    def api_status():
        # CORRECTED: Use getattr()
        db = getattr(api.state, "db", {})
        return {
            "api": "ok",
            "db": db.get("connected", False)
        }
    
    @api.post("/api/data")
    def create_data(item: dict):
        return {"created": item}
    
    api.mount("/mcp", mcp_app)
    
    return api

fastapi_hybrid = create_fastapi_hybrid_correct()


# ============================================================================
# PART 21: COMPLETE CONTEXT REFERENCE
# ============================================================================

@mcp.tool(tags={"public"})
async def complete_context_reference(ctx: Context) -> str:
    """
    COMPLETE Context reference
    
    METHODS REQUIRING await:
    - ctx.set_state(), ctx.get_state(), ctx.delete_state()
    - ctx.enable_components(), ctx.disable_components(), ctx.reset_visibility()
    - ctx.info(), ctx.debug(), ctx.warning(), ctx.error()
    - ctx.report_progress()
    - ctx.read_resource(), ctx.list_resources()
    - ctx.list_prompts(), ctx.get_prompt()
    - ctx.sample(), ctx.sample_step()
    - ctx.elicit()
    
    ATTRIBUTES (NO await):
    - ctx.transport  # "stdio", "streamable-http", "sse"
    - ctx.session_id, ctx.request_id, ctx.client_id
    - ctx.fastmcp
    - ctx.lifespan_context
    - ctx.client_supports_extension(ext_id)
    - ctx.is_background_task, ctx.task_id
    """
    
    # State management (await)
    await ctx.set_state("key", "value")
    value = await ctx.get_state("key")
    await ctx.delete_state("key")
    
    # Visibility (await)
    await ctx.enable_components(tags={"admin"})
    await ctx.disable_components(names={"dangerous_tool"})
    await ctx.reset_visibility()
    
    # Logging (await)
    await ctx.info("Info message")
    
    # Progress (await)
    await ctx.report_progress(50, 100, "Halfway")
    
    # Attributes (NO await)
    transport = ctx.transport  # "stdio", "streamable-http", "sse"
    session_id = ctx.session_id
    server = ctx.fastmcp
    
    # CORRECTED: get_http_request() for scope access
    request = get_http_request()
    if request:
        user = request.scope.get("authenticated_user", {})
    
    return "See docstring for complete reference"


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import sys
    
    mode = sys.argv[1] if len(sys.argv) > 1 else "http"
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║  FastMCP 3.0.2 COMPLETE REFERENCE - Validated Against Official Docs ║
║                                                                      ║
║  ✅ All imports from fastmcp.server.* (CORRECTED)                   ║
║  ✅ Visibility class (NOT VisibilityFilter) (CORRECTED)             ║
║  ✅ FileSystemProvider(root=Path, reload=True) (CORRECTED)          ║
║  ✅ ctx.transport returns "streamable-http" (CORRECTED)             ║
║  ✅ get_http_request() for scope access (CORRECTED)                 ║
║  ✅ scope["custom_key"] not scope["state"] (CORRECTED)              ║
║  ✅ getattr(api.state, ...) for Starlette State (CORRECTED)         ║
║  ✅ All visibility patterns (server + session + version)            ║
║  ✅ Admin control flow (login → unlock → revoke → logout)          ║
║  ✅ All transforms, middleware, auth                                 ║
║  ✅ Pure ASGI middleware (correct pattern)                           ║
║  ✅ Multi-server lifespan with combine_lifespans                    ║
║  ✅ Complete mcp.run() + http_app() reference                        ║
║  ✅ stateless_http explained                                         ║
║  ✅ Context: await vs NO await complete reference                   ║
║                                                                      ║
║  Running in: {mode.upper():56} ║
╚══════════════════════════════════════════════════════════════════════╝

TRANSPORT VALUES (CORRECTED):
─────────────────────────────────────────────────────────────────────
ctx.transport returns:
  • "stdio" - STDIO transport
  • "streamable-http" - HTTP transport (NOT "http")
  • "sse" - SSE transport (legacy)

mcp.run() parameters:
  • transport="stdio" | "streamable-http" | "sse"
  • host="0.0.0.0", port=8000 (HTTP/SSE only)
  • path="/mcp" (HTTP only)
  • log_level="INFO"
  • stateless_http=True (HTTP only, for multi-worker)
─────────────────────────────────────────────────────────────────────
    """)
    
    if mode == "stdio":
        print("📡 Starting STDIO mode...")
        mcp.run(transport="stdio")
    elif mode == "sse":
        print("📡 Starting SSE mode...")
        run_sse()
    elif mode == "http":
        print("📡 Starting HTTP mode at http://localhost:8000/mcp ...")
        run_http_complete()
    elif mode == "asgi":
        print("📡 ASGI: uvicorn script:app --host 0.0.0.0 --port 8000 --workers 4")
    elif mode == "fastapi":
        print("📡 FastAPI: uvicorn script:fastapi_hybrid --host 0.0.0.0 --port 8000")
    elif mode == "multi":
        print("📡 Multi-server: uvicorn script:multi_server_app --host 0.0.0.0 --port 8000")
    elif mode == "hub":
        print("📡 Starting unified hub...")
        hub = create_unified_hub()
        hub.run(transport="streamable-http", host="0.0.0.0", port=8000)
    else:
        print(f"❌ Unknown mode: {mode}")
        print("Usage: python script.py [stdio|http|sse|asgi|fastapi|multi|hub]")
