<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# oh now i resently say there is 3.0.2 that has many features and for my usecanse can be helpfull i.e instead of 2.14.5 i.e Here is a complete breakdown of every upgrade, feature, and major fix from FastMCP v2.14.5 → v3.0.2, organized by release milestone across the full transition path.

v2.14.5 — "Sealed Docket" (Feb 3, 2026)
This was the final stable 2.x release before the v3 line. It was a targeted patch:​
Fixed a memory leak in the memory:// docket broker where cancelled background tasks accumulated without being garbage collected
Served as the clean baseline before the 3.0 architectural overhaul
v3.0.0 — "Three at Last" (Feb 18, 2026)
This is FastMCP's largest-ever release, rebuilding the framework around three core primitives: components, providers, and transforms. The surface API (@mcp.tool()) is unchanged, but everything underneath was redesigned. FastMCP also officially moved from jlowin/fastmcp to PrefectHQ/fastmcp at this milestone.​
Provider/Transform Architecture
ProviderWhat It Does
FileSystemProvider
Discovers tools from directories with hot-reload
OpenAPIProvider
Wraps REST APIs as MCP components
ProxyProvider
Proxies remote MCP servers
SkillsProvider
Exposes agent skill files as MCP resources
LocalProvider
Default for decorator-registered components
Providers are fully composable — multiple providers can feed one server, and one provider can serve many servers. Transforms (Namespace, Rename, Filter, Visibility, Version) modify components as they flow to clients without touching source code.​
Two special transforms, ResourcesAsTools and PromptsAsTools, expose non-tool components to tool-only clients.​
New Features 🎉
Component Versioning — register @tool(version="2.0") alongside older versions from one codebase; clients get the highest version by default but can request specific versions​
Session-Scoped State — await ctx.set_state() / await ctx.get_state() persist across the full session; ctx.enable_components() / ctx.disable_components() adapt dynamically per client​
Granular Authorization — per-component auth= checks (now async-capable), server-wide AuthMiddleware, and scope-based access control​
CIMD (Client ID Metadata Document) — the successor to Dynamic Client Registration; clients host a static JSON document at an HTTPS URL as their client_id, with SSRF-hardened fetching and private_key_jwt validation​
Static Client Registration — clients can provide a pre-registered client_id/client_secret directly, bypassing DCR entirely​
Azure OBO via Dependency Injection — declarative On-Behalf-Of token exchange; EntraOBOToken in a function parameter triggers the token exchange automatically​
JWT Audience Validation — with RFC 8707 warnings to auth providers, and confused-deputy protections​
OpenTelemetry Tracing — full tracing support with MCP semantic conventions using standard traceparent/tracestate keys​
ResponseLimitingMiddleware — caps tool response sizes with UTF-8-safe truncation for text and schema-aware error handling for structured outputs​
Concurrent Tool Execution — when an LLM returns multiple tool calls in one response, they now execute in parallel; tools that aren't safe can declare sequential=True​
--reload Flag — auto-restarts the server on file changes (frontend file types included); fastmcp dev includes it by default​
Automatic Threadpool — sync tools, resources, and prompts now automatically run in a threadpool, enabling parallel execution instead of sequential blocking​
Tool Timeouts — timeout parameter for foreground tool execution​
MCP-Compliant Pagination — for large component lists​
PingMiddleware — for keepalive connections​
Composable Lifespans — combine lifespans with | for modular setup/teardown; contexts are merged, exit is LIFO ​
Rich Result Classes — explicit ToolResult, ResourceResult, and PromptResult return types for controlled responses​
Context.transport Property — tools can detect active transport ("stdio", "sse", or "streamable-http")​
Background Task Elicitation Relay — ctx.elicit() in background tasks routes through Redis-based coordination; distributed Redis notification queue replaces polling (7,200 round-trips/hour → 1 blocking call)​
Standalone Decorators — decorators return the original function, so decorated tools remain callable in tests and non-MCP contexts​
MCP Apps Phase 1 — ui:// resource scheme, typed AppConfig metadata, extension negotiation, ctx.client_supports_extension()​
CLI Expansion 🖥️
fastmcp list — list all tools on any MCP server from the terminal​
fastmcp call — invoke tools on any server from the terminal​
fastmcp discover — scans Claude Desktop, Cursor, Goose, and Gemini CLI configs for configured servers by name​
fastmcp generate-cli — writes a standalone typed CLI script where every tool is a subcommand with flags and help text​
fastmcp install stdio — registers servers with Claude Desktop, Cursor, or Goose in one command​
fastmcp dev renamed to fastmcp dev inspector​
Goose integration via deeplink URL generation​
Major Bugs Fixed 🐞
Fixed rate limit detection during teardown phase​
Fixed OAuth Proxy resource parameter validation​
Fixed openapi_version check to include OpenAPI 3.1​
Fixed base_url fallback when URL is not set​
Fixed OAuth token storage TTL calculation​
Fixed client hanging on HTTP 4xx/5xx errors​
Fixed HTTP transport timeout incorrectly defaulting to 5 seconds (should be 30s)​
Fixed ContextVar propagation for ASGI-mounted servers with background tasks​
Fixed \$ref dereferencing in tool schemas for MCP client compatibility​
Fixed timeout not propagating to proxy clients in multi-server MCPConfig​
Fixed redirect URI validation bypass when allowed_client_redirect_uris is supplied​
Fixed --reload port conflict when using an explicit port​
Fixed compress_schema to preserve additionalProperties: false for MCP compatibility​
Fixed CIMD redirect allowlist bypass and cache revalidation​
Fixed session visibility marks leaking across sessions​
Fixed unhandled exceptions in OpenAPI POST tool calls​
Fixed stale request context in StatefulProxyClient handlers​
Fixed confused deputy attack via consent binding cookie​
Used correct MCP spec error code -32002 for resource not found​
Security Fixes 🔐
Dropped diskcache dependency (CVE-2025-69872)​
Upgraded python-multipart to 0.0.22 (CVE-2026-24486)​
Upgraded protobuf to 6.33.5 (CVE-2026-0994)​
Breaking Changes 🛫
VisibilityFilter for hierarchical enable/disable replaces the old enabled parameter on components​
Auth providers no longer auto-load from environment variables — explicit configuration required​
pydocket made optional; DI systems unified​
ui= parameter renamed to app= with unified AppConfig class​
16 deprecated FastMCP() constructor kwargs finally removed (throws TypeError with migration instructions)​
FastMCP.as_proxy() replaced by create_proxy() function​
tool_serializer parameter deprecated​
Removed deprecated WSTransport​
v3.0.1 — "Three-covery Mode" (Feb 20, 2026)
The first patch after 3.0, focused on smoothing out issues discovered in the wild.​
Fixes 🐞
Fixed non-serializable state lost between middleware and tools​
Fixed Tool.from_tool() to accept callables again (regression from 3.0)​
Fixed circular reference crash in OpenAPI schema discovery​
Fixed NameError with future annotations and Context/Depends parameters​
Fixed decorator overload return types for function mode​
Switched to max_completion_tokens instead of the deprecated max_tokens in OpenAI handler​
Fixed skill metadata not being preserved through provider wrapping​
Fixed type compatibility issues with upgraded dependencies​
Enhancement 🔧
Added verify_id_token to OIDCProxy to support Azure AD configurations that issue opaque access tokens but standard JWT id_tokens​
v3.0.2 — "Three-covery Mode II" (Feb 22, 2026)
A second round of community-contributed fixes:​
Auth headers from MCP transport no longer leak through to downstream OpenAPI APIs — a security-relevant isolation fix​
Background task workers no longer retain stale session/transport state between task invocations​
Quick Summary Table
VersionDateTypeTheme
2.14.5
Feb 3, 2026
Patch
Memory leak fix in docket broker
3.0.0b1
Jan 20, 2026
Beta
Provider/Transform architecture introduced
3.0.0b2
Feb 7, 2026
Beta
CLI tools, CIMD, MCP Apps, background task context
3.0.0rc1
Feb 12, 2026
RC
Async auth, Static Client Registration, Azure OBO, concurrent sampling
3.0.0
Feb 18, 2026
Stable
Full release + security CVE drops, 3 CVE fixes
3.0.1
Feb 20, 2026
Patch
State/middleware fixes, circular ref crash, future annotations
3.0.2
Feb 22, 2026
Patch
Auth header leakage fix, background task worker isolation

So now tell me how can this all updates help me

No search needed — the user provided the full changelog. Let me map every relevant v3 feature directly to their exact setup.

***

## The features that directly change your architecture

### 1. `FileSystemProvider` + `--reload` → No more manual server registration

Before (v2): you had to explicitly import and register every `apis/*.py` file.

After (v3):

```python
from fastmcp import FastMCP
from fastmcp.providers import FileSystemProvider

mcp = FastMCP("hub")

# Drop any .py file into apis/ → tools auto-discovered, hot-reloaded
mcp.add_provider(FileSystemProvider("./apis/", hot_reload=True))

if __name__ == "__main__":
    mcp.run(transport="http", port=8000)
```

This is **exactly** what you described: *"will keep on building such functions in a folder"* — just drop `chorus_api.py`, it shows up as tools automatically, no restart needed.

***

### 2. `OpenAPIProvider` → Jira, GitHub, Splunk, Quip from their OpenAPI specs directly

Before: write full `jira_api.py` manually, wrap each endpoint.

After (v3):

```python
from fastmcp.providers import OpenAPIProvider

# Jira has an official OpenAPI spec
mcp.add_provider(OpenAPIProvider(
    spec="https://dac-static.atlassian.com/cloud/jira/platform/swagger-v3.v3.json",
    base_url="https://yoursite.atlassian.net",
    headers={"Authorization": f"Bearer {JIRA_TOKEN}"}
))

# GitHub has an official OpenAPI spec
mcp.add_provider(OpenAPIProvider(
    spec="https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json",
    base_url="https://api.github.com",
    headers={"Authorization": f"token {GH_TOKEN}"}
))

# Splunk has one too
mcp.add_provider(OpenAPIProvider(
    spec="./specs/splunk.json",
    base_url="https://localhost:8089"
))
```

You skip writing `*_api.py` entirely for APIs that publish OpenAPI specs. The provider wraps every endpoint as an MCP tool automatically.

***

### 3. `Filter` + `VisibilityFilter` Transforms → Your enable/disable UI is now native

Before: you needed a custom FastAPI UI + `config.json` to toggle servers.

After (v3) — this is built in:

```python
from fastmcp.transforms import Filter, VisibilityFilter

# Disable entire Jira server
mcp.add_transform(VisibilityFilter(hidden=["jira/*"]))

# Disable specific tools across all servers
mcp.add_transform(VisibilityFilter(hidden=[
    "splunk/delete_index",
    "kube/delete_cluster",
    "github/delete_repo"
]))

# Or use Filter to whitelist only what LLMs should see
mcp.add_transform(Filter(allow=["jira/*", "github/create_*", "kube/get_*"]))
```

Plus, **per-session dynamic control** via `ctx.enable_components()` / `ctx.disable_components()` — you can toggle tools per client/session without restarting the server.

***

### 4. `Namespace` Transform → No tool name collisions across providers

When Jira and GitHub both have a `create_issue` tool:

```python
from fastmcp.transforms import Namespace

mcp.add_provider(jira_provider,   transform=Namespace("jira"))
mcp.add_provider(github_provider, transform=Namespace("github"))
mcp.add_provider(kube_provider,   transform=Namespace("kube"))

# Tools become: jira/create_issue, github/create_issue, kube/get_pods
```


***

### 5. `create_proxy()` → Your hub becomes 3 lines

The old `FastMCP.as_proxy()` is replaced by `create_proxy()`:

```python
from fastmcp import create_proxy

hub = create_proxy({
    "mcpServers": {
        "jira":   {"url": "http://localhost:8001/mcp"},
        "github": {"url": "http://localhost:8002/mcp"},
        "kube":   {"url": "http://localhost:8003/mcp"},
        "splunk": {"url": "http://localhost:8004/mcp"},
    }
})
hub.run(port=8000)
```


***

### 6. `fastmcp generate-cli` → Your CLI layer is auto-generated

Before: you had to write `cli/jira_cli.py`, `cli/github_cli.py` etc. manually.

After (v3):

```bash
# Point at your MCP server, get a full typed CLI script instantly
fastmcp generate-cli http://localhost:8001/mcp --output cli/jira_cli.py
fastmcp generate-cli http://localhost:8002/mcp --output cli/github_cli.py
```

Every tool becomes a subcommand with `--flags` and `--help` text, fully typed. **The CLI you planned to write by hand is now auto-generated from the MCP server.**

***

### 7. `fastmcp install stdio` → One command replaces all client config

Before: manually edit JSON config for Roo Code, Claude Desktop, Cursor, Goose.

After:

```bash
# Register your hub with every client in one shot
fastmcp install stdio http://localhost:8000/mcp --client claude-desktop
fastmcp install stdio http://localhost:8000/mcp --client cursor
fastmcp install stdio http://localhost:8000/mcp --client goose

# Or discover what's already configured across clients
fastmcp discover
```


***

### 8. `ResponseLimitingMiddleware` → Large content problem solved at server level

Before: you had to manually handle `--head/--tail` in every CLI command.

After (v3) — global cap at the MCP layer:

```python
from fastmcp.middleware import ResponseLimitingMiddleware

mcp.add_middleware(ResponseLimitingMiddleware(
    max_chars=8000,           # UTF-8-safe truncation
    truncation_message="[truncated — use --head or search for details]"
))
```

Applies to every tool response automatically. Large file reads, Splunk log dumps, Kubernetes pod lists — all auto-capped.

***

### 9. `SkillsProvider` → SKILL.md files become MCP resources

```python
from fastmcp.providers import SkillsProvider

mcp.add_provider(SkillsProvider("./skills/"))
# skills/jira.md, skills/github.md etc. exposed as MCP resources
# Coding agents (Roo Code, Claude Code) can read them on demand
```


***

### 10. `Concurrent Tool Execution` → Multi-step tasks run in parallel

When an agent calls `jira_search` + `github_list_prs` + `splunk_search` in one response, v3 runs them in parallel by default. Mark dangerous ones:

```python
@mcp.tool(sequential=True)
def kube_delete_deployment(name: str): ...  # forced sequential, won't run in parallel
```


***

## Your revised architecture with v3

```python
# hub/hub.py  — entire hub in ~25 lines
from fastmcp import FastMCP, create_proxy
from fastmcp.providers import FileSystemProvider, OpenAPIProvider, SkillsProvider
from fastmcp.transforms import Namespace, VisibilityFilter
from fastmcp.middleware import ResponseLimitingMiddleware

mcp = FastMCP("hub")

# Auto-discover all your apis/*.py tools, hot-reload on change
mcp.add_provider(FileSystemProvider("./apis/", hot_reload=True))

# Auto-wrap Jira + GitHub from their OpenAPI specs directly
mcp.add_provider(OpenAPIProvider("./specs/jira.json",   ...), transform=Namespace("jira"))
mcp.add_provider(OpenAPIProvider("./specs/github.json", ...), transform=Namespace("github"))

# Expose skills/ markdown files as resources for coding agents
mcp.add_provider(SkillsProvider("./skills/"))

# Safety: cap all responses, hide destructive tools
mcp.add_middleware(ResponseLimitingMiddleware(max_chars=8000))
mcp.add_transform(VisibilityFilter(hidden=["kube/delete_*", "github/delete_*"]))

if __name__ == "__main__":
    mcp.run(transport="http", port=8000)  # --reload included in fastmcp dev inspector
```

```bash
# One-time setup: point all clients to hub
fastmcp install stdio http://localhost:8000/mcp --client claude-desktop
fastmcp install stdio http://localhost:8000/mcp --client cursor

# Generate CLI wrappers for all servers
fastmcp generate-cli http://localhost:8000/mcp --output cli/all_cli.py

# Dev: run with auto-reload
fastmcp dev inspector hub/hub.py
```


***

## What v3 eliminates from your previous plan

| You planned to build | v3 replaces it with |
| :-- | :-- |
| Custom FastAPI UI for enable/disable | `VisibilityFilter` + `ctx.enable_components()` |
| Manual `cli/jira_cli.py` etc. | `fastmcp generate-cli` |
| Manual client JSON config editing | `fastmcp install stdio` |
| `config.json` for server toggling | `Filter` / `VisibilityFilter` transforms |
| `ResponseLimitingMiddleware` DIY | Built-in `ResponseLimitingMiddleware` |
| Import each `apis/*.py` manually | `FileSystemProvider` auto-discovery |
| Write `jira_api.py` from scratch | `OpenAPIProvider` from Jira's OpenAPI spec |
| `FastMCP.as_proxy()` hub | `create_proxy()` |

