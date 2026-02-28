<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# Can you completely research the upgrades or features added and major issues fixed in fastmcp i.e (from version 2.14.5  -> to 3.0.2

Here is a complete breakdown of every upgrade, feature, and major fix from FastMCP **v2.14.5 → v3.0.2**, organized by release milestone across the full transition path.

***

## v2.14.5 — "Sealed Docket" *(Feb 3, 2026)*

This was the final stable 2.x release before the v3 line. It was a targeted patch:[^1]

- Fixed a **memory leak** in the `memory://` docket broker where cancelled background tasks accumulated without being garbage collected
- Served as the clean baseline before the 3.0 architectural overhaul

***

## v3.0.0 — "Three at Last" *(Feb 18, 2026)*

This is FastMCP's largest-ever release, rebuilding the framework around three core primitives: **components**, **providers**, and **transforms**. The surface API (`@mcp.tool()`) is unchanged, but everything underneath was redesigned. FastMCP also officially moved from `jlowin/fastmcp` to `PrefectHQ/fastmcp` at this milestone.[^2]

### Provider/Transform Architecture

| Provider | What It Does |
| :-- | :-- |
| `FileSystemProvider` | Discovers tools from directories with hot-reload |
| `OpenAPIProvider` | Wraps REST APIs as MCP components |
| `ProxyProvider` | Proxies remote MCP servers |
| `SkillsProvider` | Exposes agent skill files as MCP resources |
| `LocalProvider` | Default for decorator-registered components |

Providers are fully composable — multiple providers can feed one server, and one provider can serve many servers. **Transforms** (Namespace, Rename, Filter, Visibility, Version) modify components as they flow to clients without touching source code.[^2]

Two special transforms, `ResourcesAsTools` and `PromptsAsTools`, expose non-tool components to tool-only clients.[^2]

### New Features 🎉

- **Component Versioning** — register `@tool(version="2.0")` alongside older versions from one codebase; clients get the highest version by default but can request specific versions[^2]
- **Session-Scoped State** — `await ctx.set_state()` / `await ctx.get_state()` persist across the full session; `ctx.enable_components()` / `ctx.disable_components()` adapt dynamically per client[^2]
- **Granular Authorization** — per-component `auth=` checks (now async-capable), server-wide `AuthMiddleware`, and scope-based access control[^2]
- **CIMD (Client ID Metadata Document)** — the successor to Dynamic Client Registration; clients host a static JSON document at an HTTPS URL as their `client_id`, with SSRF-hardened fetching and `private_key_jwt` validation[^2]
- **Static Client Registration** — clients can provide a pre-registered `client_id`/`client_secret` directly, bypassing DCR entirely[^2]
- **Azure OBO via Dependency Injection** — declarative On-Behalf-Of token exchange; `EntraOBOToken` in a function parameter triggers the token exchange automatically[^2]
- **JWT Audience Validation** — with RFC 8707 warnings to auth providers, and confused-deputy protections[^2]
- **OpenTelemetry Tracing** — full tracing support with MCP semantic conventions using standard `traceparent`/`tracestate` keys[^2]
- **ResponseLimitingMiddleware** — caps tool response sizes with UTF-8-safe truncation for text and schema-aware error handling for structured outputs[^2]
- **Concurrent Tool Execution** — when an LLM returns multiple tool calls in one response, they now execute in parallel; tools that aren't safe can declare `sequential=True`[^2]
- **`--reload` Flag** — auto-restarts the server on file changes (frontend file types included); `fastmcp dev` includes it by default[^2]
- **Automatic Threadpool** — sync tools, resources, and prompts now automatically run in a threadpool, enabling parallel execution instead of sequential blocking[^3]
- **Tool Timeouts** — `timeout` parameter for foreground tool execution[^2]
- **MCP-Compliant Pagination** — for large component lists[^2]
- **PingMiddleware** — for keepalive connections[^2]
- **Composable Lifespans** — combine lifespans with `|` for modular setup/teardown; contexts are merged, exit is LIFO [^3]
- **Rich Result Classes** — explicit `ToolResult`, `ResourceResult`, and `PromptResult` return types for controlled responses[^3]
- **`Context.transport` Property** — tools can detect active transport (`"stdio"`, `"sse"`, or `"streamable-http"`)[^3]
- **Background Task Elicitation Relay** — `ctx.elicit()` in background tasks routes through Redis-based coordination; distributed Redis notification queue replaces polling (7,200 round-trips/hour → 1 blocking call)[^2]
- **Standalone Decorators** — decorators return the original function, so decorated tools remain callable in tests and non-MCP contexts[^2]
- **MCP Apps Phase 1** — `ui://` resource scheme, typed `AppConfig` metadata, extension negotiation, `ctx.client_supports_extension()`[^2]


### CLI Expansion 🖥️

- `fastmcp list` — list all tools on any MCP server from the terminal[^2]
- `fastmcp call` — invoke tools on any server from the terminal[^2]
- `fastmcp discover` — scans Claude Desktop, Cursor, Goose, and Gemini CLI configs for configured servers by name[^2]
- `fastmcp generate-cli` — writes a standalone typed CLI script where every tool is a subcommand with flags and help text[^2]
- `fastmcp install stdio` — registers servers with Claude Desktop, Cursor, or Goose in one command[^2]
- `fastmcp dev` renamed to `fastmcp dev inspector`[^2]
- Goose integration via deeplink URL generation[^2]


### Major Bugs Fixed 🐞

- Fixed rate limit detection during teardown phase[^2]
- Fixed OAuth Proxy resource parameter validation[^2]
- Fixed `openapi_version` check to include OpenAPI 3.1[^2]
- Fixed `base_url` fallback when URL is not set[^2]
- Fixed OAuth token storage TTL calculation[^2]
- Fixed client hanging on HTTP 4xx/5xx errors[^2]
- Fixed HTTP transport timeout incorrectly defaulting to 5 seconds (should be 30s)[^2]
- Fixed ContextVar propagation for ASGI-mounted servers with background tasks[^2]
- Fixed `$ref` dereferencing in tool schemas for MCP client compatibility[^2]
- Fixed timeout not propagating to proxy clients in multi-server `MCPConfig`[^2]
- Fixed redirect URI validation bypass when `allowed_client_redirect_uris` is supplied[^2]
- Fixed `--reload` port conflict when using an explicit port[^2]
- Fixed `compress_schema` to preserve `additionalProperties: false` for MCP compatibility[^2]
- Fixed CIMD redirect allowlist bypass and cache revalidation[^2]
- Fixed session visibility marks leaking across sessions[^2]
- Fixed unhandled exceptions in OpenAPI POST tool calls[^2]
- Fixed stale request context in `StatefulProxyClient` handlers[^2]
- Fixed confused deputy attack via consent binding cookie[^2]
- Used correct MCP spec error code `-32002` for resource not found[^2]


### Security Fixes 🔐

- **Dropped `diskcache` dependency** (CVE-2025-69872)[^2]
- **Upgraded `python-multipart` to 0.0.22** (CVE-2026-24486)[^2]
- **Upgraded `protobuf` to 6.33.5** (CVE-2026-0994)[^2]


### Breaking Changes 🛫

- `VisibilityFilter` for hierarchical enable/disable replaces the old `enabled` parameter on components[^2]
- Auth providers **no longer auto-load from environment variables** — explicit configuration required[^2]
- `pydocket` made optional; DI systems unified[^2]
- `ui=` parameter renamed to `app=` with unified `AppConfig` class[^2]
- 16 deprecated `FastMCP()` constructor kwargs finally removed (throws `TypeError` with migration instructions)[^2]
- `FastMCP.as_proxy()` replaced by `create_proxy()` function[^2]
- `tool_serializer` parameter deprecated[^2]
- Removed deprecated `WSTransport`[^2]

***

## v3.0.1 — "Three-covery Mode" *(Feb 20, 2026)*

The first patch after 3.0, focused on smoothing out issues discovered in the wild.[^2]

### Fixes 🐞

- Fixed **non-serializable state** lost between middleware and tools[^2]
- Fixed `Tool.from_tool()` to **accept callables** again (regression from 3.0)[^2]
- Fixed **circular reference crash** in OpenAPI schema discovery[^2]
- Fixed `NameError` with **future annotations** and `Context`/`Depends` parameters[^2]
- Fixed **decorator overload return types** for function mode[^2]
- Switched to `max_completion_tokens` instead of the **deprecated `max_tokens`** in OpenAI handler[^2]
- Fixed **skill metadata** not being preserved through provider wrapping[^2]
- Fixed type compatibility issues with upgraded dependencies[^2]


### Enhancement 🔧

- Added `verify_id_token` to `OIDCProxy` to support Azure AD configurations that issue **opaque access tokens** but standard JWT id_tokens[^2]

***

## v3.0.2 — "Three-covery Mode II" *(Feb 22, 2026)*

A second round of community-contributed fixes:[^4]

- **Auth headers from MCP transport no longer leak** through to downstream OpenAPI APIs — a security-relevant isolation fix[^4]
- **Background task workers** no longer retain stale session/transport state between task invocations[^4]

***

## Quick Summary Table

| Version | Date | Type | Theme |
| :-- | :-- | :-- | :-- |
| 2.14.5 | Feb 3, 2026 | Patch | Memory leak fix in docket broker |
| 3.0.0b1 | Jan 20, 2026 | Beta | Provider/Transform architecture introduced |
| 3.0.0b2 | Feb 7, 2026 | Beta | CLI tools, CIMD, MCP Apps, background task context |
| 3.0.0rc1 | Feb 12, 2026 | RC | Async auth, Static Client Registration, Azure OBO, concurrent sampling |
| 3.0.0 | Feb 18, 2026 | Stable | Full release + security CVE drops, 3 CVE fixes |
| 3.0.1 | Feb 20, 2026 | Patch | State/middleware fixes, circular ref crash, future annotations |
| 3.0.2 | Feb 22, 2026 | Patch | Auth header leakage fix, background task worker isolation |

<span style="display:none">[^10][^11][^12][^13][^14][^15][^16][^17][^18][^19][^5][^6][^7][^8][^9]</span>

<div align="center">⁂</div>

[^1]: https://gofastmcp.com/v2/updates

[^2]: https://gofastmcp.com/changelog

[^3]: https://www.jlowin.dev/blog/fastmcp-3-whats-new

[^4]: https://github.com/PrefectHQ/fastmcp/releases

[^5]: https://www.jlowin.dev/blog/fastmcp-3-beta-2

[^6]: https://gofastmcp.com/development/releases

[^7]: https://github.com/PrefectHQ/fastmcp/issues

[^8]: https://www.reddit.com/r/mcp/comments/1m885ua/mcp_server_upgrade_fastmcp_edition/

[^9]: https://gofastmcp.com/updates

[^10]: https://github.com/PrefectHQ/fastmcp

[^11]: https://gofastmcp.com/v2/getting-started/installation

[^12]: https://gofastmcp.com

[^13]: https://github.com/jlowin/fastmcp/issues/899

[^14]: https://github.com/punkpeye/fastmcp/issues

[^15]: https://pypi.org/project/fastmcp/

[^16]: https://www.linkedin.com/posts/nortonjr_release-v300b1-this-beta-work-jlowin-activity-7419730885232488448-pGw-

[^17]: https://pypi.org/project/fastmcp/0.3.0/

[^18]: https://pypi.org/project/fastmcp/2.2.0/

[^19]: https://github.com/jlowin/fastmcp/issues/3174

