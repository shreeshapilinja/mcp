<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# Now I have 2.1.79 (Claude Code) Till that time there are many environment variables they support and i.e in experimental also they support some flags that can be used like for creating the team , ... like those all they support flags can you give me list of all those reseearch in depth and give me

Here is a comprehensive, categorized list of all environment variables and CLI flags supported by Claude Code (as of v2.1.79), pulled directly from the official docs.

***

## 🔑 Authentication \& API

| Variable | Purpose |
| :-- | :-- |
| `ANTHROPIC_API_KEY` | Primary API key; overrides subscription login [^1] |
| `ANTHROPIC_AUTH_TOKEN` | Custom `Authorization` header value (prefixed with `Bearer`) [^1] |
| `ANTHROPIC_BASE_URL` | Route requests via a proxy or gateway [^1] |
| `ANTHROPIC_CUSTOM_HEADERS` | Newline-separated custom headers (`Name: Value` format) [^1] |
| `ANTHROPIC_FOUNDRY_API_KEY` | API key for Microsoft Azure Foundry [^1] |
| `ANTHROPIC_FOUNDRY_BASE_URL` | Full base URL for the Foundry resource [^1] |
| `ANTHROPIC_FOUNDRY_RESOURCE` | Foundry resource name (e.g., `my-resource`) [^1] |
| `CLAUDE_CODE_CLIENT_CERT` | Path to client certificate for mTLS [^1] |
| `CLAUDE_CODE_CLIENT_KEY` | Path to private key for mTLS [^1] |
| `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE` | Passphrase for encrypted client key [^1] |
| `AWS_BEARER_TOKEN_BEDROCK` | Bedrock API key for authentication [^1] |


***

## ☁️ Cloud Provider (Bedrock / Vertex / Foundry)

| Variable | Purpose |
| :-- | :-- |
| `CLAUDE_CODE_USE_BEDROCK` | Use AWS Bedrock as backend [^1] |
| `CLAUDE_CODE_USE_VERTEX` | Use Google Vertex AI as backend [^1] |
| `CLAUDE_CODE_USE_FOUNDRY` | Use Microsoft Azure Foundry as backend [^1] |
| `CLAUDE_CODE_SKIP_BEDROCK_AUTH` | Skip AWS auth (e.g., when using an LLM gateway) [^1] |
| `CLAUDE_CODE_SKIP_VERTEX_AUTH` | Skip Google auth [^1] |
| `CLAUDE_CODE_SKIP_FOUNDRY_AUTH` | Skip Azure auth [^1] |
| `ANTHROPIC_SMALL_FAST_MODEL_AWS_REGION` | Override AWS region for Haiku-class model on Bedrock [^1] |
| `VERTEX_REGION_CLAUDE_3_5_HAIKU` | Override Vertex AI region per model (similar vars exist for Sonnet 4.0/4.1 and Opus 4.0/4.1) [^1] |


***

## 🤖 Model Configuration

| Variable | Purpose |
| :-- | :-- |
| `ANTHROPIC_MODEL` | Model to use [^1] |
| `ANTHROPIC_DEFAULT_SONNET_MODEL` | Override default Sonnet model [^1] |
| `ANTHROPIC_DEFAULT_HAIKU_MODEL` | Override default Haiku model [^1] |
| `ANTHROPIC_DEFAULT_OPUS_MODEL` | Override default Opus model [^1] |
| `ANTHROPIC_SMALL_FAST_MODEL` | *(Deprecated)* Haiku-class model for background tasks [^1] |
| `CLAUDE_CODE_SUBAGENT_MODEL` | Model used for subagents [^1] |
| `CLAUDE_CODE_EFFORT_LEVEL` | Effort level: `low`, `medium`, `high`, `max` (Opus 4.6 only), or `auto` [^1] |
| `CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING` | Set to `1` to disable adaptive reasoning on Opus 4.6 / Sonnet 4.6 [^1] |
| `MAX_THINKING_TOKENS` | Override extended thinking token budget; `0` disables thinking entirely [^1] |
| `CLAUDE_CODE_MAX_OUTPUT_TOKENS` | Max output tokens per request [^1] |
| `CLAUDE_CODE_DISABLE_1M_CONTEXT` | Set to `1` to disable 1M context window variants [^1] |
| `ANTHROPIC_CUSTOM_MODEL_OPTION` | Adds a custom model entry in `/model` picker [^1] |
| `ANTHROPIC_CUSTOM_MODEL_OPTION_NAME` | Display name for custom model picker entry [^1] |
| `ANTHROPIC_CUSTOM_MODEL_OPTION_DESCRIPTION` | Display description for custom model picker entry [^1] |


***

## 🧑‍🤝‍🧑 Agent Teams (Experimental)

These are key flags for the experimental **agent teams** feature you mentioned:[^1]


| Variable | Purpose |
| :-- | :-- |
| `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` | Set to `1` to **enable agent teams** (disabled by default) [^1] |
| `CLAUDE_CODE_TEAM_NAME` | Name of the agent team a teammate belongs to (auto-set by Claude Code) [^1] |
| `CLAUDE_CODE_PLAN_MODE_REQUIRED` | Auto-set to `true` on teammates requiring plan approval (read-only) [^1] |

In the CLI, the `--teammate-mode` flag controls how team members display — `auto` (default), `in-process`, or `tmux` .

***

## 🔧 Bash \& Shell Behavior

| Variable | Purpose |
| :-- | :-- |
| `BASH_DEFAULT_TIMEOUT_MS` | Default timeout for long-running bash commands [^1] |
| `BASH_MAX_TIMEOUT_MS` | Max timeout the model can set for bash commands [^1] |
| `BASH_MAX_OUTPUT_LENGTH` | Max characters in bash output before middle-truncation [^1] |
| `CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR` | Return to original working dir after each Bash command [^1] |
| `CLAUDE_CODE_SHELL` | Override automatic shell detection (e.g., force `bash` vs `zsh`) [^1] |
| `CLAUDE_CODE_SHELL_PREFIX` | Command prefix wrapping all bash commands (useful for logging/auditing) [^1] |
| `CLAUDE_ENV_FILE` | Shell script sourced before each Bash command (e.g., to activate virtualenv) [^1] |
| `CLAUDECODE` | Set to `1` inside Claude Code-spawned shell environments — use to detect context [^1] |


***

## 🧠 Memory, Context \& Compaction

| Variable | Purpose |
| :-- | :-- |
| `CLAUDE_CODE_DISABLE_AUTO_MEMORY` | Set to `1` to disable auto memory creation/loading [^1] |
| `CLAUDE_AUTOCOMPACT_PCT_OVERRIDE` | % of context at which auto-compaction triggers (default ~95%) [^1] |
| `CLAUDE_CODE_AUTO_COMPACT_WINDOW` | Token capacity used for auto-compaction calculations [^1] |
| `CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD` | Set to `1` to load CLAUDE.md from `--add-dir` directories [^1] |
| `CLAUDE_CODE_FILE_READ_MAX_OUTPUT_TOKENS` | Override default token limit for file reads [^1] |


***

## 🔌 MCP (Model Context Protocol)

| Variable | Purpose |
| :-- | :-- |
| `MCP_TIMEOUT` | Timeout (ms) for MCP server startup [^1] |
| `MCP_TOOL_TIMEOUT` | Timeout (ms) for MCP tool execution [^1] |
| `MAX_MCP_OUTPUT_TOKENS` | Max tokens in MCP tool responses (default: 25000) [^1] |
| `ENABLE_CLAUDEAI_MCP_SERVERS` | Set to `false` to disable claude.ai MCP servers [^1] |
| `ENABLE_TOOL_SEARCH` | Controls MCP tool search; values: `true`, `auto`, `auto:N`, `false` [^1] |
| `MCP_CLIENT_SECRET` | OAuth client secret for MCP servers [^1] |
| `MCP_OAUTH_CALLBACK_PORT` | Fixed port for OAuth redirect callback [^1] |


***

## 📋 Tasks, Sessions \& Scheduling

| Variable | Purpose |
| :-- | :-- |
| `CLAUDE_CODE_ENABLE_TASKS` | Set to `true` to enable task tracking in non-interactive (`-p`) mode [^1] |
| `CLAUDE_CODE_TASK_LIST_ID` | Share a task list across multiple Claude Code instances [^1] |
| `CLAUDE_CODE_DISABLE_CRON` | Set to `1` to disable scheduled tasks and the `/loop` skill [^1] |
| `CLAUDE_CODE_DISABLE_BACKGROUND_TASKS` | Set to `1` to disable background tasks and `Ctrl+B` shortcut [^1] |
| `CLAUDE_CODE_EXIT_AFTER_STOP_DELAY` | Auto-exit after (ms) of idle in SDK mode [^1] |
| `CLAUDE_CODE_SESSIONEND_HOOKS_TIMEOUT_MS` | Max time (ms) for SessionEnd hooks to complete (default: 1500) [^1] |


***

## 📦 Plugins \& Updates

| Variable | Purpose |
| :-- | :-- |
| `DISABLE_AUTOUPDATER` | Set to `1` to disable automatic updates [^1] |
| `FORCE_AUTOUPDATE_PLUGINS` | Force plugin auto-updates even when autoupdater is disabled [^1] |
| `CLAUDE_CODE_PLUGIN_GIT_TIMEOUT_MS` | Timeout (ms) for git operations during plugin install/update (default: 120000) [^1] |
| `CLAUDE_CODE_PLUGIN_SEED_DIR` | Path(s) to read-only plugin seed directories for container images [^1] |


***

## 🚫 Disabling Features

| Variable | Purpose |
| :-- | :-- |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` | Disables autoupdater, feedback command, error reporting, and telemetry at once [^1] |
| `DISABLE_TELEMETRY` | Opt out of Statsig telemetry [^1] |
| `DISABLE_ERROR_REPORTING` | Opt out of Sentry error reporting [^1] |
| `DISABLE_FEEDBACK_COMMAND` | Disable the `/feedback` command (`DISABLE_BUG_COMMAND` also accepted) [^1] |
| `DISABLE_COST_WARNINGS` | Disable cost warning messages [^1] |
| `DISABLE_INSTALLATION_CHECKS` | Disable installation warnings [^1] |
| `DISABLE_PROMPT_CACHING` | Disable prompt caching globally [^1] |
| `DISABLE_PROMPT_CACHING_HAIKU` / `_SONNET` / `_OPUS` | Disable prompt caching per model tier [^1] |
| `CLAUDE_CODE_DISABLE_FAST_MODE` | Set to `1` to disable fast mode [^1] |
| `CLAUDE_CODE_DISABLE_TERMINAL_TITLE` | Disable automatic terminal title updates [^1] |
| `CLAUDE_CODE_DISABLE_GIT_INSTRUCTIONS` | Remove built-in git/commit workflow instructions from system prompt [^1] |
| `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS` | Strip `anthropic-beta` headers from API requests (use when a proxy rejects them) [^1] |
| `CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY` | Disable "How is Claude doing?" session surveys [^1] |


***

## 🌐 Network \& Proxy

| Variable | Purpose |
| :-- | :-- |
| `HTTP_PROXY` / `HTTPS_PROXY` | HTTP/HTTPS proxy server URL [^1] |
| `NO_PROXY` | Domains/IPs to bypass proxy [^1] |
| `CLAUDE_CODE_PROXY_RESOLVES_HOSTS` | Let proxy handle DNS resolution [^1] |
| `CLAUDE_CODE_SKIP_FAST_MODE_NETWORK_ERRORS` | Allow fast mode even when org status check fails due to network [^1] |


***

## ⚙️ Miscellaneous / Advanced

| Variable | Purpose |
| :-- | :-- |
| `CLAUDE_CONFIG_DIR` | Custom config/data storage directory [^1] |
| `CLAUDE_CODE_TMPDIR` | Override internal temp directory (Claude Code appends `/claude/`) [^1] |
| `CLAUDE_CODE_SIMPLE` | Set to `1` for minimal mode: only Bash + file tools, no MCP/hooks/CLAUDE.md [^1] |
| `CLAUDE_CODE_NEW_INIT` | Set to `true` for interactive `/init` flow [^1] |
| `CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION` | Set to `false` to disable grayed-out prompt predictions [^1] |
| `CLAUDE_CODE_ENABLE_TELEMETRY` | Set to `1` to enable OpenTelemetry data collection [^1] |
| `CLAUDE_CODE_OTEL_HEADERS_HELPER_DEBOUNCE_MS` | Interval for refreshing dynamic OTel headers (default: 29 min) [^1] |
| `CLAUDE_CODE_API_KEY_HELPER_TTL_MS` | Credentials refresh interval for `apiKeyHelper` [^1] |
| `SLASH_COMMAND_TOOL_CHAR_BUDGET` | Override character budget for skill metadata shown to Skill tool [^1] |
| `USE_BUILTIN_RIPGREP` | Set to `0` to use system `rg` instead of Claude's bundled version [^1] |
| `IS_DEMO` | Demo mode: hides email/org, skips onboarding, hides internal commands [^1] |
| `MAX_MCP_OUTPUT_TOKENS` | Max tokens allowed in MCP tool responses [^1] |
| `CLAUDE_CODE_ACCOUNT_UUID` / `CLAUDE_CODE_USER_EMAIL` / `CLAUDE_CODE_ORGANIZATION_UUID` | SDK callers provide account info synchronously to avoid telemetry race conditions [^1] |


***

## 🚩 Key CLI Flags (launch-time)

These are passed directly when launching `claude` :

- **`--teammate-mode`** — `auto` / `in-process` / `tmux` for agent team display
- **`--agents`** — Define custom subagents dynamically via JSON
- **`--agent`** — Specify an agent for the current session
- **`--permission-mode`** — Start in a specific mode (`plan`, etc.)
- **`--effort`** — `low` / `medium` / `high` / `max`
- **`--betas`** — Pass beta headers like `interleaved-thinking` (API key users only)
- **`--dangerously-skip-permissions`** — Skip all permission prompts
- **`--worktree` / `-w`** — Launch in an isolated git worktree
- **`--remote`** — Create a new web session on claude.ai
- **`--remote-control` / `--rc`** — Enable remote control from claude.ai
- **`--plugin-dir`** — Load plugins from a directory for this session
- **`--fork-session`** — Create a new session ID when resuming
- **`--json-schema`** — Get validated JSON output matching a schema (print mode)
- **`--max-budget-usd`** — Spending cap for API calls (print mode)
- **`--mcp-config`** — Load MCP servers from JSON files
- **`--strict-mcp-config`** — Only use MCP servers from `--mcp-config`, ignoring all others
- **`--system-prompt` / `--append-system-prompt`** — Replace or extend the system prompt
- **`--disable-slash-commands`** — Disable all skills/commands for a session
- **`--chrome`** / **`--no-chrome`** — Toggle browser integration
- **`--teleport`** — Resume a web session in local terminal
<span style="display:none">[^10][^11][^12][^13][^14][^15][^2][^3][^4][^5][^6][^7][^8][^9]</span>

<div align="center">⁂</div>

[^1]: https://code.claude.com/docs/en/env-vars

[^2]: https://code.claude.com/docs/en/settings

[^3]: https://code.claude.com/docs/en/changelog

[^4]: https://gist.github.com/unkn0wncode/f87295d055dd0f0e8082358a0b5cc467

[^5]: https://www.reddit.com/r/ClaudeAI/comments/1lp8g4w/how_to_find_claude_code_environment_variables_and/

[^6]: https://code.claude.com/docs/en/cli-reference

[^7]: https://aws.plainenglish.io/configuring-claude-code-extension-with-aws-bedrock-and-how-you-can-avoid-my-mistakes-090dbed5215b

[^8]: https://blakecrosley.com/guides/claude-code

[^9]: https://shipyard.build/blog/claude-code-cheat-sheet/

[^10]: https://dev.to/youngluo/claude-code-env-simplify-your-anthropic-api-environment-management-3mkk

[^11]: https://help.apiyi.com/en/claude-code-environment-variables-complete-guide-en.html

[^12]: https://paddo.dev/blog/claude-code-hidden-mcp-flag/

[^13]: https://support.claude.com/en/articles/12304248-managing-api-key-environment-variables-in-claude-code

[^14]: https://code.claude.com/docs/en/model-config

[^15]: https://www.datacamp.com/tutorial/claude-code-2-1-guide

