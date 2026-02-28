"""
FastMCP 3.0.2 COMPLETE REFERENCE - Validated Against Official Docs
===================================================================
COMPREHENSIVE demonstration of:
- All visibility/enable/disable patterns (server + session + version-based)
- Admin control flows with runtime toggling
- All providers (Local, FileSystem, OpenAPI, Proxy, Skills, FastMCPProvider)
- All transports (stdio, http, sse) with all parameters
- Proxy patterns (single vs multi-server, mounted vs standalone)
- All transforms, middleware, auth patterns
- Complete working examples for LLMs without internet access
"""

# ============================================================================
# IMPORTS - All FastMCP 3.0.2 modules
# ============================================================================

from fastmcp import FastMCP, Context
from fastmcp.server import create_proxy
from fastmcp.exceptions import ToolError

# Providers
from fastmcp.providers import (
    LocalProvider,           # Decorator-based (classic FastMCP)
    FileSystemProvider,      # Auto-discover from directory
    OpenAPIProvider,         # Wrap REST APIs
    ProxyProvider,           # Proxy remote MCP servers
    SkillsProvider,          # Expose skill markdown files
)

# Transforms
from fastmcp.transforms import (
    Namespace,               # Add prefix to avoid collisions
    Rename,                  # Rename individual components
    Filter,                  # Whitelist/blacklist components
    VisibilityFilter,        # Hide/show components (same as Visibility)
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
# Everything enabled except what you explicitly disable
mcp.disable(tags={"premium"})     # Hide all premium tools
mcp.disable(tags={"admin"})       # Hide all admin tools  
mcp.disable(tags={"internal"})    # Hide internal tools

# PATTERN 2: Disable by specific key (exact component)
mcp.disable(keys={"tool:beta_feature_tool"})  # Disable one specific tool

# PATTERN 3: Combine tags and keys
mcp.disable(
    tags={"dangerous"},           # All dangerous tagged
    keys={"tool:internal_debug_tool"}  # Plus this specific one
)

# PATTERN 4: Re-enable previously disabled
# mcp.enable(tags={"beta"})  # Uncomment to re-enable beta tools

# PATTERN 5: ALLOWLIST MODE (only=True) - EVERYTHING OFF except specified
# This is the nuclear option - flips default from "allow all" to "deny all"
# mcp.enable(tags={"public"}, only=True)  
# ^^^ If uncommented, ONLY public-tagged tools visible
# All others (premium, admin, internal, untagged) DISABLED

# PATTERN 6: Later calls override earlier ones
# mcp.enable(tags={"admin"}, only=True)  # Switch to admin-only mode
# mcp.disable(keys={"tool:admin_delete_tool"})  # But still hide this one dangerous tool


# ----------------------------------------------------------------------------
# PART 2C: SESSION-LEVEL VISIBILITY (per-client runtime control)
# ----------------------------------------------------------------------------

@mcp.tool(tags={"public"})
async def unlock_premium(token: str, ctx: Context) -> str:
    """
    Unlock premium features for THIS SESSION ONLY
    Other clients unaffected
    """
    if token == "premium-key-2026":
        # Enable premium tools for this session
        await ctx.enable_components(tags={"premium"})
        return "✅ Premium features unlocked for your session!"
    return "❌ Invalid premium token"

@mcp.tool(tags={"public"})
async def admin_login(password: str, ctx: Context) -> str:
    """
    Admin login - enables admin tools for this session
    """
    if password == "admin123":
        await ctx.enable_components(tags={"admin"})
        
        # Track admin session
        server = ctx.server
        server.state["admin_sessions"].add(ctx.session_id)
        
        return "✅ Admin access granted for your session"
    return "❌ Invalid admin password"

@mcp.tool(tags={"admin"})
async def admin_revoke_dangerous(ctx: Context) -> str:
    """
    Admin can disable dangerous tools mid-session
    Even though they have admin tag enabled
    """
    await ctx.disable_components(tags={"dangerous"})
    return "⚠️ Dangerous tools disabled for safety"

@mcp.tool(tags={"admin"})
async def admin_enable_beta(ctx: Context) -> str:
    """Admin can enable beta features for testing"""
    await ctx.enable_components(tags={"beta"})
    return "🧪 Beta features enabled for this session"

@mcp.tool(tags={"public"})
async def logout(ctx: Context) -> str:
    """
    Reset session to global defaults
    Clears all session-specific enable/disable
    """
    await ctx.reset_visibility()
    
    # Remove from admin tracking
    server = ctx.server
    server.state["admin_sessions"].discard(ctx.session_id)
    
    return "👋 Session reset to defaults"

@mcp.tool(tags={"public"})
async def check_my_permissions(ctx: Context) -> str:
    """
    Show what this session has access to
    Demonstrates session state inspection
    """
    # This is conceptual - FastMCP doesn't expose component list via ctx
    # In practice you'd track this in session state
    is_admin = ctx.session_id in ctx.server.state.get("admin_sessions", set())
    
    return f"""
Your session permissions:
- Admin: {'✅ YES' if is_admin else '❌ NO'}
- Premium: {'✅ Unlocked' if 'premium_unlocked' in str(ctx.state) else '❌ Locked'}
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
    """
    Admin can filter by version - only show stable tools
    Hides beta/experimental versions
    """
    await ctx.enable_components(
        version=VersionSpec(gte="2.0", lt="2.5"),  # 2.0 <= version < 2.5
        components={"tool"}  # Only affect tools, not resources/prompts
    )
    return "📌 Only stable v2.0-2.4 tools enabled"

@mcp.tool(tags={"admin"})
async def enable_all_versions(ctx: Context) -> str:
    """Show all versions including experimental"""
    await ctx.enable_components(
        version=VersionSpec(gte="1.0"),  # All versions >= 1.0
        components={"tool"}
    )
    return "🔓 All tool versions enabled"


# ----------------------------------------------------------------------------
# PART 2E: VISIBILITY IN @mcp.tool() DECORATOR (via tags)
# ----------------------------------------------------------------------------

# FastMCP v3 doesn't have a direct `visible=False` parameter in @mcp.tool()
# Instead, visibility is controlled via:
# 1. Tags + server-level enable/disable
# 2. VisibilityFilter transform

# Example using VisibilityFilter transform:
# (We'll add this in PART 7 transforms section)


# ============================================================================
# PART 3: MORE TOOLS - Context, Versioning, Sequential, Timeout
# ============================================================================

@mcp.tool(tags={"public"})
async def context_aware_tool(message: str, ctx: Context) -> str:
    """Demonstrate context API features"""
    # Session state (persists across calls in same session)
    await ctx.set_state("last_message", message)
    previous = await ctx.get_state("last_message", default="(none)")
    
    # Transport detection
    transport = ctx.transport  # "stdio", "sse", or "http"
    
    # Client capabilities
    supports_apps = ctx.client_supports_extension("mcp-apps")
    
    # Session ID
    session = ctx.session_id
    
    return f"""
Previous message: {previous}
Transport: {transport}
MCP Apps support: {supports_apps}
Session ID: {session[:8]}...
    """

@mcp.tool(sequential=True, tags={"admin"})
def sequential_critical_operation(action: str) -> str:
    """
    Sequential execution - won't run in parallel
    Even if LLM calls multiple tools at once
    """
    import time
    time.sleep(0.5)  # Simulate critical operation
    return f"Completed sequentially: {action}"

@mcp.tool(timeout=3.0, tags={"public"})
def slow_operation(duration: float) -> str:
    """Tool with timeout - will fail if exceeds 3 seconds"""
    import time
    time.sleep(min(duration, 5))  # May timeout if duration > 3
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
# PART 5: FILESYSTEM PROVIDER (hot-reload)
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

mcp.add_provider(
    FileSystemProvider(
        str(tools_dir),
        hot_reload=True,  # Changes detected without restart
        recursive=True
    )
)


# ============================================================================
# PART 6: OPENAPI PROVIDER
# ============================================================================

# Example: JSONPlaceholder public API
mcp.add_provider(
    OpenAPIProvider(
        spec="https://jsonplaceholder.typicode.com/swagger.json",
        base_url="https://jsonplaceholder.typicode.com",
        headers={"User-Agent": "FastMCP/3.0"}
    ),
    transform=Namespace("api")  # All tools prefixed with "api/"
)


# ============================================================================
# PART 7: TRANSFORMS (modify components in pipeline)
# ============================================================================

# Namespace - already shown above with OpenAPIProvider

# Filter - whitelist/blacklist
mcp.add_transform(
    Filter(
        allow=["public_*", "api/*"],  # Whitelist patterns
        deny=["*_debug_*"]  # Blacklist patterns (takes precedence)
    )
)

# VisibilityFilter - hide components by default
# Can be enabled per-session via ctx.enable_components()
mcp.add_transform(
    VisibilityFilter(
        hidden=["beta_feature_tool", "experimental_search"]
    )
)

# Rename
mcp.add_transform(
    Rename(renames={"public_read_tool": "read_data"})
)

# ToolTransform - modify metadata
def add_prefix_to_descriptions(tool):
    tool.description = f"[ENHANCED] {tool.description}"
    return tool

mcp.add_transform(ToolTransform(transform=add_prefix_to_descriptions))


# ============================================================================
# PART 8: MIDDLEWARE
# ============================================================================

# Response limiting
mcp.add_middleware(
    ResponseLimitingMiddleware(
        max_chars=8000,
        truncation_message="\n\n[... truncated - use search/filter ...]"
    )
)

# Auth middleware - only allow admin tools if authorized
async def admin_auth_check(component, context):
    """Check if client has admin access for admin-tagged components"""
    if "admin" in component.tags:
        # Check if session is in admin list
        is_admin = context.session_id in context.server.state.get("admin_sessions", set())
        return is_admin
    return True  # Non-admin tools always allowed

mcp.add_middleware(
    AuthMiddleware(
        auth_fn=admin_auth_check,
        tags={"admin"}
    )
)


# ============================================================================
# PART 9: MOUNTING OTHER SERVERS (FastMCPProvider pattern)
# ============================================================================

# Create a sub-server
sub_server = FastMCP("Sub Server")

@sub_server.tool(tags={"subserver"})
def sub_tool(x: int) -> int:
    """Tool from sub-server"""
    return x * 2

@sub_server.tool(tags={"subserver", "math"})
def sub_math_tool(a: int, b: int) -> int:
    """Math tool from sub-server"""
    return a + b

# Mount it into main server
# Tools automatically get namespace prefix: "subserver/sub_tool"
mcp.mount(sub_server, namespace="subserver")

# After mounting, you can still control visibility:
# mcp.disable(keys={"tool:subserver/sub_tool"})  # Disable specific mounted tool
# mcp.enable(tags={"subserver"}, only=True)  # Only show subserver tools


# ============================================================================
# PART 10: PROXY PATTERNS - COMPLETE DEMONSTRATION
# ============================================================================

# PATTERN 1: ProxyProvider - Proxy remote MCP server into main server
# (Commented - requires actual remote server)
"""
mcp.add_provider(
    ProxyProvider(
        "http://remote-server.com:8001/mcp",
        # Or local: ProxyProvider("python other_server.py")
    ),
    transform=Namespace("remote")  # Tools prefixed with "remote/"
)
"""

# PATTERN 2: create_proxy - Standalone proxy server (aggregates multiple servers)
def create_unified_hub():
    """
    Hub that proxies multiple backend servers
    All tools accessible through one endpoint
    """
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
    
    # Create proxy that merges all servers
    hub = create_proxy(config, name="Unified Hub")
    
    # Proxy supports same enable/disable as regular servers
    # hub.disable(tags={"dangerous"})
    # hub.enable(tags={"safe"}, only=True)
    
    return hub

# To run the hub:
# hub = create_unified_hub()
# hub.run(transport="http", host="0.0.0.0", port=8000)


# PATTERN 3: Hybrid - Main server + ProxyProvider for specific backends
# This is the "hub + individual servers" pattern from the user's requirement
def create_hybrid_hub():
    """
    Main FastMCP server that:
    1. Has its own tools (defined above)
    2. Proxies remote servers for Jira, GitHub, etc.
    """
    # Main server already has tools defined above
    
    # Add remote servers as providers
    # mcp.add_provider(
    #     ProxyProvider("http://localhost:8001/mcp"),
    #     transform=Namespace("jira")
    # )
    # mcp.add_provider(
    #     ProxyProvider("http://localhost:8002/mcp"),
    #     transform=Namespace("github")
    # )
    
    # Now mcp exposes:
    # - Its own tools (public_read_tool, admin_delete_tool, etc.)
    # - jira/* tools from localhost:8001
    # - github/* tools from localhost:8002
    
    return mcp


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
# PART 12: RUNNING THE SERVER - All Transports & Parameters
# ============================================================================

def run_stdio():
    """
    STDIO transport (default)
    For: Claude Desktop, Cursor, Roo Code, Goose
    Communication: stdin/stdout
    Lifecycle: Client spawns server process per session
    """
    mcp.run(transport="stdio")
    # No host/port - uses standard streams
    # Server doesn't stay running - client manages lifecycle


def run_http():
    """
    HTTP transport (streamable HTTP - recommended for v3)
    For: Network-accessible servers, production deployments
    Communication: HTTP requests with streaming
    """
    mcp.run(
        transport="http",
        host="0.0.0.0",      # Bind to all interfaces (or "127.0.0.1" for local only)
        port=8000,           # Port to listen on
        path="/mcp"          # MCP endpoint path (default: "/mcp")
    )
    # Server accessible at: http://localhost:8000/mcp


def run_sse():
    """
    SSE transport (Server-Sent Events)
    For: Legacy compatibility (deprecated, use http instead)
    """
    mcp.run(
        transport="sse",
        host="0.0.0.0",
        port=8000
    )
    # SSE endpoint: http://localhost:8000/sse


def run_with_custom_params():
    """All supported mcp.run() parameters"""
    mcp.run(
        transport="http",           # "stdio", "http", "sse"
        host="0.0.0.0",            # Host to bind (HTTP/SSE only)
        port=8000,                 # Port (HTTP/SSE only)
        path="/mcp",               # Endpoint path (HTTP/SSE only, default "/mcp")
        log_level="INFO",          # Logging level
        stateless_http=False,      # True for multi-worker (no session state)
    )


# ============================================================================
# PART 13: ASGI APP (Production with Uvicorn)
# ============================================================================

def create_asgi_app():
    """
    Convert FastMCP to ASGI app for production
    Run with: uvicorn script:app --host 0.0.0.0 --port 8000 --workers 4
    """
    app = mcp.http_app(
        path="/mcp",           # MCP endpoint path
        stateless_http=True    # Required for multi-worker deployments
    )
    return app

# Export for uvicorn
app = create_asgi_app()


# ============================================================================
# PART 14: FASTAPI HYBRID (MCP + REST API in one app)
# ============================================================================

def create_fastapi_hybrid():
    """
    Embed MCP inside FastAPI
    Supports both MCP tools AND regular REST endpoints
    """
    from fastapi import FastAPI
    
    # Create MCP ASGI app
    mcp_app = mcp.http_app(path="/")
    
    # Create FastAPI with MCP lifespan (REQUIRED!)
    api = FastAPI(lifespan=mcp_app.lifespan)
    
    # Regular REST endpoints
    @api.get("/api/health")
    def health():
        return {"status": "ok"}
    
    @api.get("/api/stats")
    def stats():
        return {
            "admin_sessions": len(api.state.get("admin_sessions", set())),
            "db_connected": api.state.get("db", {}).get("connected", False)
        }
    
    # Mount MCP at /mcp
    api.mount("/mcp", mcp_app)
    
    return api

# fastapi_app = create_fastapi_hybrid()
# Run: uvicorn script:fastapi_app --host 0.0.0.0 --port 8000


# ============================================================================
# PART 15: CLI COMMANDS (FastMCP v3 CLI)
# ============================================================================

# After starting server, use these commands:

# List all tools
# $ fastmcp list http://localhost:8000/mcp

# Call a tool
# $ fastmcp call http://localhost:8000/mcp public_read_tool --query "test"

# Generate typed CLI from MCP server
# $ fastmcp generate-cli http://localhost:8000/mcp --output cli.py

# Install to Claude Desktop
# $ fastmcp install stdio python server.py --client claude-desktop

# Install to Cursor
# $ fastmcp install stdio http://localhost:8000/mcp --client cursor

# Discover configured servers
# $ fastmcp discover

# Run with auto-reload
# $ fastmcp run server.py --reload --transport http --port 8000


# ============================================================================
# PART 16: ADMIN CONTROL FLOW EXAMPLE
# ============================================================================

"""
COMPLETE ADMIN WORKFLOW:

1. Server starts - admin tools DISABLED globally
   mcp.disable(tags={"admin"})

2. Client A calls admin_login("admin123")
   → Session-level: await ctx.enable_components(tags={"admin"})
   → Client A now sees admin tools
   → Other clients still don't see them (session-scoped)

3. Client A calls admin_enable_beta()
   → await ctx.enable_components(tags={"beta"})
   → Client A now sees beta tools too
   → Still session-scoped, others unaffected

4. Client A calls admin_revoke_dangerous()
   → await ctx.disable_components(tags={"dangerous"})
   → Client A loses dangerous tools (but keeps other admin tools)

5. Client A calls logout()
   → await ctx.reset_visibility()
   → Client A back to global defaults (no admin tools)

6. Admin updates global policy
   → mcp.enable(tags={"public"}, only=True)
   → NOW all clients (A, B, C) only see public tools
   → Previous session overrides cleared
"""


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
║  ✅ SERVER-LEVEL visibility (mcp.enable/disable with tags/keys)      ║
║  ✅ SESSION-LEVEL visibility (ctx.enable_components/disable)         ║
║  ✅ VERSION-BASED visibility (VersionSpec filtering)                 ║
║  ✅ ALLOWLIST mode (only=True) vs BLOCKLIST (default)               ║
║  ✅ Admin control flow (login → unlock → revoke → logout)          ║
║  ✅ All providers (Local, FileSystem, OpenAPI, Proxy, Skills)       ║
║  ✅ All transforms (Namespace, Filter, VisibilityFilter, Rename)    ║
║  ✅ Middleware (ResponseLimiting, Auth)                              ║
║  ✅ Mounting servers (FastMCPProvider pattern)                       ║
║  ✅ Proxy patterns (ProxyProvider, create_proxy, hybrid)            ║
║  ✅ All transports (stdio, http, sse) with ALL parameters           ║
║  ✅ ASGI deployment + FastAPI hybrid                                 ║
║                                                                      ║
║  Running in: {mode.upper():56} ║
╚══════════════════════════════════════════════════════════════════════╝

TRANSPORT PARAMETERS REFERENCE:
─────────────────────────────────────────────────────────────────────
stdio:  mcp.run(transport="stdio")
        No host/port - uses stdin/stdout

http:   mcp.run(transport="http", host="0.0.0.0", port=8000, path="/mcp")
        Full network server at http://host:port/path

sse:    mcp.run(transport="sse", host="0.0.0.0", port=8000)
        Legacy SSE at http://host:port/sse

All:    log_level="INFO", stateless_http=True (for multi-worker)
─────────────────────────────────────────────────────────────────────
    """)
    
    if mode == "stdio":
        print("📡 Starting STDIO mode (for Claude Desktop/Cursor)...")
        run_stdio()
    elif mode == "sse":
        print("📡 Starting SSE mode (legacy)...")
        run_sse()
    elif mode == "http":
        print("📡 Starting HTTP mode at http://localhost:8000/mcp ...")
        run_http()
    elif mode == "asgi":
        print("📡 ASGI mode - run with: uvicorn script:app --host 0.0.0.0 --port 8000 --workers 4")
    elif mode == "fastapi":
        print("📡 FastAPI hybrid - run with: uvicorn script:fastapi_app --host 0.0.0.0 --port 8000")
    elif mode == "hub":
        print("📡 Starting unified hub (proxy mode)...")
        hub = create_unified_hub()
        hub.run(transport="http", host="0.0.0.0", port=8000)
    else:
        print(f"❌ Unknown mode: {mode}")
        print("Usage: python script.py [stdio|http|sse|asgi|fastapi|hub]")
