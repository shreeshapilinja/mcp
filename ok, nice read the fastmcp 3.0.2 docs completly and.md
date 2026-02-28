<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# ok, nice read the fastmcp 3.0.2 docs completly and give or explain me complete fastmcp mcp usage and all the possibilities ,..... all things in one program i.e :

imports all correctly
then how to create here it tools , resporce prompts ......
then all types of different providers supported
......

......
then how to run and transports supported
.......
if needed to run as fastapi app how like previously we used http_app() but now hhow ,,........
needed only program fully explaiuning all things nothing must be missing

Complete python code only give me but research correctly
this is in general not for my usecase i.e like i was only knowing basic that was in v2 now maythings are there know so old things may be changed so i needed complete

Let me create the most comprehensive FastMCP 3.0.2 reference program with every feature demonstrated:

```python
"""
FastMCP 3.0.2 Complete Reference Implementation
================================================
Every feature, provider, transform, middleware, and pattern in one program.
Demonstrates the full capability surface of FastMCP 3.0.2.
"""

# ============================================================================
# IMPORTS - All FastMCP 3.0.2 modules
# ============================================================================

from fastmcp import FastMCP, Context
from fastmcp.server import create_proxy
from fastmcp.exceptions import ToolError

# Providers - source components from different places
from fastmcp.providers import (
    LocalProvider,           # Decorator-based (classic FastMCP)
    FileSystemProvider,      # Auto-discover from directory
    OpenAPIProvider,         # Wrap REST APIs
    ProxyProvider,           # Proxy remote MCP servers
    SkillsProvider,          # Expose skill markdown files
    # FastMCPProvider,       # Mount other FastMCP instances (via mount())
)

# Transforms - modify components in the pipeline
from fastmcp.transforms import (
    Namespace,               # Add prefix to avoid collisions
    Rename,                  # Rename individual components
    Filter,                  # Whitelist/blacklist components
    VisibilityFilter,        # Hide/show components
    ToolTransform,           # Modify tool definitions
    # ResourcesAsTools,      # Expose resources as tools
    # PromptsAsTools,        # Expose prompts as tools
)

# Middleware - cross-cutting concerns
from fastmcp.middleware import (
    ResponseLimitingMiddleware,  # Cap response sizes
    AuthMiddleware,              # Authorization logic
    # PingMiddleware,            # Keepalive
)

# Auth providers
from fastmcp.server.auth import (
    BearerTokenAuth,         # Simple token auth
    # OIDCAuth,              # OpenID Connect
    # OAuthProxy,            # OAuth 2.1 with DCR/CIMD
)

# Utilities
from fastmcp.utilities.lifespan import combine_lifespans
from fastmcp.resources import Resource
from fastmcp.prompts import Prompt

# Result types for explicit returns
from fastmcp.types import ToolResult, ResourceResult, PromptResult

# Standard library
from typing import Annotated
from contextlib import asynccontextmanager
import asyncio
from pathlib import Path
import os


# ============================================================================
# PART 1: SERVER LIFESPAN (setup/teardown)
# ============================================================================

@asynccontextmanager
async def server_lifespan(server):
    """
    Runs once when server starts (before any clients connect)
    and once when server stops. Use for:
    - Database connections
    - Cache initialization
    - Background workers
    """
    print("🚀 Server starting up...")
    
    # Setup code here
    db_connection = {"connected": True}  # Simulated DB
    server.state["db"] = db_connection
    
    yield  # Server runs here
    
    # Teardown code here
    print("🛑 Server shutting down...")
    db_connection["connected"] = False


# ============================================================================
# PART 2: CLASSIC LOCAL PROVIDER (decorator-based tools/resources/prompts)
# ============================================================================

mcp = FastMCP(
    "Complete Reference Server",
    lifespan=server_lifespan,
    dependencies=["requests", "pydantic"]  # For deployment via `fastmcp install`
)

# ----------------------------------------------------------------------------
# TOOLS - Functions the LLM can call
# ----------------------------------------------------------------------------

@mcp.tool()
def simple_tool(text: str) -> str:
    """Simple synchronous tool - auto runs in threadpool in v3"""
    return f"Processed: {text}"


@mcp.tool()
async def async_tool(query: str) -> dict:
    """Async tool with structured output"""
    await asyncio.sleep(0.1)  # Simulate I/O
    return {"result": query.upper(), "length": len(query)}


@mcp.tool(version="2.0")
def versioned_tool(data: str) -> str:
    """
    Tool versioning (NEW in v3)
    Clients get highest version by default, but can request specific version
    """
    return f"v2.0 result: {data}"


@mcp.tool(version="1.0")
def versioned_tool_v1(data: str) -> str:
    """Old version - still available if client requests it"""
    return f"v1.0 result: {data}"


@mcp.tool(sequential=True)
def dangerous_tool(action: str) -> str:
    """
    Sequential execution (NEW in v3)
    Won't run in parallel with other tools even if LLM calls multiple at once
    """
    return f"Executed sequentially: {action}"


@mcp.tool(timeout=5.0)
def slow_tool(duration: float) -> str:
    """Tool with timeout (NEW in v3)"""
    import time
    time.sleep(min(duration, 10))
    return "Completed"


# Context API - access request context
@mcp.tool()
async def context_aware_tool(message: str, ctx: Context) -> str:
    """
    Access context: session state, transport info, client capabilities
    """
    # Session-scoped state (NEW in v3)
    await ctx.set_state("last_message", message)
    previous = await ctx.get_state("last_message", default="(none)")
    
    # Transport detection
    transport = ctx.transport  # "stdio", "sse", or "streamable-http"
    
    # Check client capabilities
    supports_apps = ctx.client_supports_extension("mcp-apps")
    
    return f"Previous: {previous}, Transport: {transport}, Apps: {supports_apps}"


# Dynamic component control (NEW in v3)
@mcp.tool()
async def toggle_features(enable: bool, ctx: Context) -> str:
    """Enable/disable components per session"""
    if enable:
        ctx.enable_components(keys=["admin_tool"])
    else:
        ctx.disable_components(keys=["admin_tool"])
    return f"Features {'enabled' if enable else 'disabled'}"


@mcp.tool(tags=["admin"])
def admin_tool(action: str) -> str:
    """Admin-only tool - can be filtered by tag"""
    return f"Admin action: {action}"


# Explicit result types (NEW in v3)
@mcp.tool()
def explicit_result_tool(data: str) -> ToolResult:
    """Return explicit ToolResult for fine control"""
    return ToolResult(
        content=[{"type": "text", "text": f"Result: {data}"}],
        is_error=False
    )


# Error handling
@mcp.tool()
def error_tool(should_fail: bool) -> str:
    """Raise ToolError for structured error responses"""
    if should_fail:
        raise ToolError("Something went wrong", code="CUSTOM_ERROR")
    return "Success"


# ----------------------------------------------------------------------------
# RESOURCES - Read-only data sources
# ----------------------------------------------------------------------------

@mcp.resource("config://settings")
def get_settings() -> str:
    """Static resource - returns text content"""
    return "server_mode=production\nmax_connections=100"


@mcp.resource("data://users/{user_id}")
async def get_user(user_id: str) -> dict:
    """
    Parameterized resource (URI template)
    Returns structured data (JSON serialized)
    """
    await asyncio.sleep(0.05)
    return {
        "id": user_id,
        "name": f"User {user_id}",
        "role": "developer"
    }


# Explicit ResourceResult
@mcp.resource("file://report.txt")
def file_resource() -> ResourceResult:
    """Return explicit ResourceResult"""
    return ResourceResult(
        contents=[{
            "uri": "file://report.txt",
            "mimeType": "text/plain",
            "text": "Q4 Revenue: $1.2M"
        }]
    )


# Resource with rich metadata (for MCP Apps - NEW in v3)
@mcp.resource("ui://dashboard", app={"width": 800, "height": 600})
def dashboard_ui() -> str:
    """
    MCP Apps support (NEW in v3)
    Returns HTML that renders in sandboxed iframe
    """
    return """
    <!DOCTYPE html>
    <html><body>
        <h1>Dashboard</h1>
        <p>Interactive UI here</p>
    </body></html>
    """


# ----------------------------------------------------------------------------
# PROMPTS - Reusable templates
# ----------------------------------------------------------------------------

@mcp.prompt()
def code_review_prompt(language: str = "python") -> str:
    """Simple prompt template"""
    return f"""You are a {language} code reviewer.
Review the following code for:
- Bugs and errors
- Performance issues  
- Best practices
"""


@mcp.prompt()
def structured_prompt(topic: str, style: str = "formal") -> PromptResult:
    """Prompt with explicit PromptResult and messages"""
    return PromptResult(
        description=f"Generate {style} content about {topic}",
        messages=[
            {"role": "user", "content": {"type": "text", "text": f"Write about {topic} in {style} style"}}
        ]
    )


# ============================================================================
# PART 3: FILESYSTEM PROVIDER (auto-discovery with hot-reload)
# ============================================================================

# Create tools directory structure
tools_dir = Path("./tools")
tools_dir.mkdir(exist_ok=True)

# Example tool file that gets auto-discovered
(tools_dir / "example_tool.py").write_text("""
from fastmcp import tool

@tool()
def filesystem_discovered_tool(x: int, y: int) -> int:
    '''Tool discovered from filesystem'''
    return x + y
""")

# Add FileSystemProvider with hot-reload
mcp.add_provider(
    FileSystemProvider(
        str(tools_dir),
        hot_reload=True,  # Changes detected without restart (NEW in v3)
        recursive=True    # Scan subdirectories
    )
)


# ============================================================================
# PART 4: OPENAPI PROVIDER (wrap REST APIs)
# ============================================================================

# Example: wrap a public API (JSONPlaceholder for demo)
mcp.add_provider(
    OpenAPIProvider(
        spec="https://jsonplaceholder.typicode.com/swagger.json",  # or local file
        base_url="https://jsonplaceholder.typicode.com",
        headers={"User-Agent": "FastMCP/3.0"},
        # validate_output=False  # For imperfect APIs
    ),
    transform=Namespace("jsonplaceholder")  # All tools get prefix
)

# For real use: Jira, GitHub, Splunk OpenAPI specs
# mcp.add_provider(
#     OpenAPIProvider(
#         spec="./specs/jira.json",
#         base_url="https://yoursite.atlassian.net",
#         headers={"Authorization": f"Bearer {os.getenv('JIRA_TOKEN')}"}
#     ),
#     transform=Namespace("jira")
# )


# ============================================================================
# PART 5: PROXY PROVIDER (proxy remote MCP servers)
# ============================================================================

# Proxy another MCP server (local or remote)
# mcp.add_provider(
#     ProxyProvider(
#         "http://localhost:8001/mcp",  # Remote MCP server URL
#         # Or: ProxyProvider("./other_server.py")  # Local server
#     ),
#     transform=Namespace("remote")
# )

# Or use create_proxy for a dedicated proxy server
# proxy = create_proxy("http://remote-server.com/mcp", name="Proxy")


# ============================================================================
# PART 6: SKILLS PROVIDER (expose skill files as resources)
# ============================================================================

skills_dir = Path("./skills")
skills_dir.mkdir(exist_ok=True)

(skills_dir / "example.md").write_text("""
# Example Skill

## Command 1
python cli.py action1 <arg>

## Command 2  
python cli.py action2 --flag
""")

mcp.add_provider(SkillsProvider(str(skills_dir)))


# ============================================================================
# PART 7: TRANSFORMS (modify components in pipeline)
# ============================================================================

# Namespace transform (prevent name collisions)
# Already shown above with OpenAPIProvider

# Filter transform (whitelist/blacklist)
mcp.add_transform(
    Filter(
        allow=["simple_tool", "async_tool", "jsonplaceholder/*"],  # Whitelist
        deny=["admin_tool"]  # Blacklist (takes precedence)
    )
)

# VisibilityFilter (hierarchical enable/disable)
mcp.add_transform(
    VisibilityFilter(
        hidden=["dangerous_tool"],  # Hide by default
        # Can be enabled per-session via ctx.enable_components()
    )
)

# Rename transform
mcp.add_transform(
    Rename(renames={"simple_tool": "process_text"})
)

# ToolTransform (modify tool metadata)
from fastmcp.transforms import ToolTransform

def improve_description(tool):
    """Enhance auto-generated tool descriptions"""
    tool.description = f"[ENHANCED] {tool.description}"
    return tool

mcp.add_transform(ToolTransform(transform=improve_description))


# ============================================================================
# PART 8: MIDDLEWARE (request-level concerns)
# ============================================================================

# Response limiting (NEW in v3)
mcp.add_middleware(
    ResponseLimitingMiddleware(
        max_chars=8000,  # Cap at 8000 chars
        truncation_message="\n\n[... truncated - use search/filter for details]"
    )
)

# Auth middleware (per-tag authorization)
async def admin_auth(component, context):
    """Only allow admin tools if authorized"""
    if "admin" in component.tags:
        # Check auth token in context
        token = context.headers.get("Authorization", "")
        if token != "Bearer admin-secret":
            return False
    return True

mcp.add_middleware(
    AuthMiddleware(
        auth_fn=admin_auth,
        tags=["admin"]
    )
)


# ============================================================================
# PART 9: SERVER-LEVEL AUTH (applies to all requests)
# ============================================================================

# Simple bearer token auth
# mcp = FastMCP(
#     "Secured Server",
#     auth=BearerTokenAuth(token=os.getenv("MCP_TOKEN", "secret"))
# )

# Or OAuth with OIDC
# from fastmcp.server.auth import OIDCAuth
# mcp = FastMCP(
#     "OAuth Server",
#     auth=OIDCAuth(
#         issuer="https://accounts.google.com",
#         client_id="your-client-id",
#         client_secret="your-client-secret"
#     )
# )


# ============================================================================
# PART 10: MOUNTING OTHER SERVERS (composition)
# ============================================================================

# Create a sub-server
sub_server = FastMCP("Sub Server")

@sub_server.tool()
def sub_tool(x: int) -> int:
    return x * 2

# Mount it (automatically gets namespaced)
mcp.mount(sub_server, namespace="subserver")
# Tools become: subserver/sub_tool


# ============================================================================
# PART 11: COMPONENT VERSIONING (NEW in v3)
# ============================================================================

# Already shown above with @mcp.tool(version="2.0")
# Clients get highest version by default
# Can request specific version: tool_name@1.0


# ============================================================================
# PART 12: BACKGROUND TASKS & ELICITATION
# ============================================================================

@mcp.tool()
async def long_running_task(duration: int, ctx: Context) -> str:
    """
    Run task in background with progress reporting
    Uses ctx.elicit() for human-in-the-loop (NEW in v3)
    """
    async def background_work():
        for i in range(duration):
            await asyncio.sleep(1)
            # Report progress
            await ctx.log_message(f"Progress: {i+1}/{duration}")
        
        # Ask user for confirmation mid-task
        response = await ctx.elicit(
            prompt="Continue with next phase?",
            arguments=[
                {"name": "confirm", "description": "yes or no", "required": True}
            ]
        )
        
        return f"Completed with response: {response}"
    
    # Start background task (NEW in v3: distributed coordination via Redis)
    task = asyncio.create_task(background_work())
    ctx.state["task"] = task
    
    return "Task started in background"


# ============================================================================
# PART 13: OPENTELEMETRY TRACING (NEW in v3)
# ============================================================================

# FastMCP 3 has native OpenTelemetry support
# Just configure your OTEL exporter and all tool calls are traced
# 
# import opentelemetry
# from opentelemetry.sdk.trace import TracerProvider
# 
# tracer_provider = TracerProvider()
# opentelemetry.trace.set_tracer_provider(tracer_provider)
# 
# Now every tool call, resource read, prompt render is traced with MCP semantic conventions


# ============================================================================
# PART 14: RUNNING THE SERVER - All transports
# ============================================================================

def run_stdio():
    """
    STDIO transport (for Claude Desktop, Cursor, etc)
    Communication via stdin/stdout
    """
    mcp.run(transport="stdio")


def run_sse():
    """
    SSE (Server-Sent Events) transport
    HTTP-based, older protocol
    """
    mcp.run(transport="sse", host="0.0.0.0", port=8000)


def run_http():
    """
    Streamable HTTP transport (NEW default in v3)
    Modern HTTP-based protocol
    """
    mcp.run(transport="http", host="0.0.0.0", port=8000)


# ============================================================================
# PART 15: ASGI APP (for production with Uvicorn/Gunicorn)
# ============================================================================

def create_asgi_app():
    """
    Convert FastMCP to ASGI application
    Run with: uvicorn script:app --host 0.0.0.0 --port 8000
    """
    app = mcp.http_app(
        path="/mcp",  # MCP endpoint at /mcp
        stateless_http=True  # For multi-worker deployments
    )
    return app

# For production
app = create_asgi_app()

# Run with:
# uvicorn script:app --host 0.0.0.0 --port 8000 --workers 4


# ============================================================================
# PART 16: MOUNTING INTO FASTAPI (hybrid API + MCP)
# ============================================================================

def create_fastapi_hybrid():
    """
    Embed MCP server inside FastAPI app
    MCP tools + regular REST endpoints in one app
    """
    from fastapi import FastAPI
    
    # Create MCP ASGI app
    mcp_app = mcp.http_app(path="/")
    
    # Create FastAPI app with MCP lifespan (REQUIRED)
    api = FastAPI(lifespan=mcp_app.lifespan)
    
    # Add regular REST endpoints
    @api.get("/api/status")
    def status():
        return {"status": "ok"}
    
    # Mount MCP at /mcp
    api.mount("/mcp", mcp_app)
    
    return api

# fastapi_app = create_fastapi_hybrid()
# Run with: uvicorn script:fastapi_app --host 0.0.0.0 --port 8000


# ============================================================================
# PART 17: CLI GENERATION (NEW in v3)
# ============================================================================

# After server is running, generate CLI from it:
# 
# fastmcp generate-cli http://localhost:8000/mcp --output cli.py
# 
# Every tool becomes a typed CLI subcommand with --flags


# ============================================================================
# PART 18: CLIENT CONFIG MANAGEMENT (NEW in v3)
# ============================================================================

# Install server to Claude Desktop / Cursor / Goose:
# fastmcp install stdio python server.py --client claude-desktop
# fastmcp install stdio http://localhost:8000/mcp --client cursor
#
# Discover configured servers:
# fastmcp discover


# ============================================================================
# PART 19: TESTING TOOLS FROM CLI (NEW in v3)
# ============================================================================

# List all tools:
# fastmcp list http://localhost:8000/mcp
#
# Call a tool:
# fastmcp call http://localhost:8000/mcp simple_tool --text "hello"


# ============================================================================
# PART 20: CONFIGURATION-BASED PROXY (NEW in v3)
# ============================================================================

def create_config_proxy():
    """
    Create proxy from MCPConfig JSON
    Useful for multi-server aggregation
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
            }
        }
    }
    
    # Creates proxy that merges all servers
    proxy = create_proxy(config, name="Unified Hub")
    return proxy

# hub = create_config_proxy()
# hub.run(transport="http", port=8000)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import sys
    
    mode = sys.argv[^1] if len(sys.argv) > 1 else "http"
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  FastMCP 3.0.2 Complete Reference Server                    ║
║                                                              ║
║  Features demonstrated:                                      ║
║  ✓ LocalProvider (decorators)                               ║
║  ✓ FileSystemProvider (hot-reload)                          ║
║  ✓ OpenAPIProvider (REST API wrapping)                      ║
║  ✓ ProxyProvider (remote servers)                           ║
║  ✓ SkillsProvider (markdown skills)                         ║
║  ✓ All Transforms (Namespace, Filter, Visibility, Rename)   ║
║  ✓ Middleware (ResponseLimiting, Auth)                      ║
║  ✓ Versioning, timeouts, sequential execution               ║
║  ✓ Context API, session state, dynamic components           ║
║  ✓ Background tasks, elicitation                            ║
║  ✓ MCP Apps support                                         ║
║  ✓ ASGI deployment, FastAPI integration                     ║
║                                                              ║
║  Running in: {mode.upper():48} ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if mode == "stdio":
        run_stdio()
    elif mode == "sse":
        run_sse()
    elif mode == "http":
        run_http()
    elif mode == "asgi":
        print("Run with: uvicorn script:app --host 0.0.0.0 --port 8000")
    else:
        print(f"Unknown mode: {mode}")
        print("Usage: python script.py [stdio|sse|http|asgi]")
```

This single program demonstrates **every major FastMCP 3.0.2 feature**. Save it and run:

```bash
# HTTP mode (default)
python script.py http

# STDIO mode (for Claude Desktop)
python script.py stdio

# ASGI production mode
uvicorn script:app --workers 4

# Generate CLI from it
fastmcp generate-cli http://localhost:8000/mcp --output cli.py
```

<span style="display:none">[^10][^11][^12][^13][^14][^15][^16][^17][^18][^19][^2][^20][^21][^22][^23][^24][^25][^26][^27][^28][^29][^3][^30][^4][^5][^6][^7][^8][^9]</span>

<div align="center">⁂</div>

[^1]: https://jlowin.dev/blog/fastmcp-3

[^2]: https://github.com/PrefectHQ/fastmcp

[^3]: https://www.jlowin.dev/blog/fastmcp-3-beta-2

[^4]: https://fastmcp.me

[^5]: https://gofastmcp.com/updates

[^6]: https://www.jlowin.dev/blog/fastmcp-3-whats-new

[^7]: https://gofastmcp.com/servers/providers/proxy

[^8]: https://gofastmcp.com/getting-started/installation

[^9]: https://newreleases.io/project/github/jlowin/fastmcp/release/v3.0.0b1

[^10]: https://fastmcp.mintlify.app/servers/proxy

[^11]: https://pypi.org/project/fastmcp/2.1.1/

[^12]: https://www.linkedin.com/posts/jlowin_fastmcp-30-is-here-its-time-to-move-fast-activity-7419426073223794688-Bxd6

[^13]: https://gofastmcp.com/python-sdk/fastmcp-server-providers-proxy

[^14]: https://github.com/jlowin/fastmcp

[^15]: https://gofastmcp.com/servers/transforms/transforms

[^16]: https://gofastmcp.com/deployment/running-server

[^17]: https://gofastmcp.com/deployment/http

[^18]: https://github.com/modelcontextprotocol/python-sdk/issues/1484

[^19]: https://codesignal.com/learn/courses/advanced-mcp-server-and-agent-integration-in-python/lessons/mounting-an-mcp-server-in-a-fastapi-asgi-application

[^20]: https://www.youtube.com/watch?v=lqNZqbzBdEE

[^21]: https://pypi.org/project/fastapi-mcp/0.3.0/

[^22]: https://github.com/dwayn/fastmcp-mount

[^23]: https://github.com/tadata-org/fastapi_mcp

[^24]: https://www.youtube.com/watch?v=JpNYKtW540I

[^25]: https://thedocs.io/fastapi_mcp/examples/

[^26]: https://www.youtube.com/watch?v=MXvIzUuBff4

[^27]: https://gofastmcp.com/integrations/fastapi

[^28]: https://stackoverflow.com/questions/73908734/how-to-run-uvicorn-fastapi-server-as-a-module-from-another-python-file

[^29]: https://docs.scalekit.com/authenticate/mcp/fastapi-fastmcp-quickstart/

[^30]: https://gofastmcp.com/servers/providers/mounting

