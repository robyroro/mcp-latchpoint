# mcp-latchpoint

<!-- mcp-name: io.github.robyroro/mcp-latchpoint -->

`mcp-latchpoint` audits MCP client configuration files without running the configured servers. It works offline, reads only local files you select, and produces text, JSON, or SARIF results.

This is an early defensive tool. Review findings in context before changing a working configuration.

## What it checks

The v0.1 rules cover:

- plain HTTP for non-loopback remote endpoints
- shell wrappers and inline shell control syntax
- identifiable `npx` and `uvx` packages without exact versions
- literal credentials in environment values, headers, arguments, or URLs
- filesystem roots and home roots passed as recognizable access scopes
- wildcard hosts and recognizable wildcard scopes
- conflicting, missing, invalid, or unsupported transport settings

Every finding has a stable rule ID, severity, location, remediation, redacted evidence, and a confidence note when interpretation depends on the launched server.

## Install

Python 3.11 or newer is required.

```console
python -m pip install mcp-latchpoint
```

To install from a local checkout:

```console
python -m venv .venv
# Linux or macOS
. .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1
python -m pip install .
```

For development:

```console
python -m pip install -e ".[dev]"
pytest
ruff check .
mypy
```

The MCP server uses the official Python SDK v2 and the dependency is constrained to `mcp>=2.3,<3`.

## CLI

Scan one or more explicit files:

```console
mcp-latchpoint scan ~/.config/Code/User/mcp.json
mcp-latchpoint scan examples/risky.json --format json
mcp-latchpoint scan examples/risky.json --format sarif --fail-on high > results.sarif
```

Restrict every explicit path to an approved directory:

```console
mcp-latchpoint scan ./configs --allowed-root ./configs
```

Directories are searched only for recognized MCP config filenames, up to 256 files. A file is limited to 1 MiB by default. Change these bounds with `--max-files` and `--max-bytes`.

Exit codes are `0` for a completed scan below the chosen threshold, `1` when a finding meets `--fail-on`, and `2` for input, containment, or parse errors. The default `--fail-on none` reports findings without failing a build.

List and explain rules:

```console
mcp-latchpoint rules
mcp-latchpoint explain MCP004
```

### Recognized layouts

Explicit files may use these structures:

| Client layout | Container | Accepted file syntax |
| --- | --- | --- |
| Claude Desktop, Cursor, portable `.mcp.json`, generic MCP JSON | top-level `mcpServers` object | JSON |
| Claude Code user/local settings | top-level `mcpServers`, plus `projects.<path>.mcpServers` in `~/.claude.json` | JSON |
| VS Code | top-level `servers` object | JSONC for `.vscode/mcp.json` |
| Codex | `[mcp_servers.<name>]` tables | TOML |

Files ending in `.jsonc` are also parsed as JSONC. Other `.json` files remain strict JSON so malformed input is not silently accepted.

`--discover` checks only the following paths when they exist. It does not search the rest of the home directory.

- All systems: `~/.claude.json`, `~/.cursor/mcp.json`, `~/.codex/config.toml`, `$COPILOT_HOME/mcp-config.json` with `~/.copilot/mcp-config.json` as the fallback
- Current project: `.mcp.json`, `.codex/config.toml`, `.cursor/mcp.json`, `.vscode/mcp.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`, `%APPDATA%\Code\User\mcp.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`, `~/Library/Application Support/Code/User/mcp.json`
- Linux: `$XDG_CONFIG_HOME/Code/User/mcp.json`, falling back to `~/.config/Code/User/mcp.json`

## Read-only MCP server

The stdio server exposes two tools: `list_rules` and `scan`. It requires an allowed root at startup. Relative scan paths are resolved below that root; absolute paths, `..` traversal, and symlinks cannot escape it.

```console
mcp-latchpoint-server --root /absolute/path/to/reviewed-configs
mcp-latchpoint serve --root /absolute/path/to/reviewed-configs
```

Example client entry:

```json
{
  "mcpServers": {
    "latchpoint": {
      "command": "/absolute/path/to/mcp-latchpoint-server",
      "args": ["--root", "/absolute/path/to/reviewed-configs"]
    }
  }
}
```

The server returns findings and scan metadata, never raw configuration content. Stdio is the only server transport exposed by the entry point, and stdout is reserved for MCP protocol messages.

The `serve` command is also the entry point advertised in the MCP Registry. Set `--root` to a directory you explicitly trust before connecting a client.

### Glama build

The [Glama listing](https://glama.ai/mcp/servers/robyroro/mcp-latchpoint) builds a container from the repository. In its Dockerfile configuration, use Python 3.13, these build steps and command arguments:

```json
["uv sync --no-dev"]
```

```json
["mcp-proxy", "--", "/app/.venv/bin/mcp-latchpoint-server", "--root", "/app/examples"]
```

The root is an existing directory with synthetic sample configurations. It lets Glama start and inspect the tools without giving the server access to a user's files. The command uses the executable inside the virtual environment created by `uv sync`. For this demo, the environment-variable schema can be `{"type":"object","properties":{}}` and placeholder parameters can be `{}`.

To scan your own configurations, run the server locally with `--root` pointing to a directory you explicitly trust. Glama's demo root is only for the sample files in `examples/`.

## Safety and limitations

The scanner never executes commands, installs packages, resolves referenced environment variables, or connects to endpoints. It does not follow configuration includes or inspect an MCP server's code or runtime behavior. Argument-based rules are intentionally limited to recognizable patterns, so custom flags can be missed. A clean report is not proof that a server is safe.

Secret detection is designed to emit field names and `<redacted>` markers rather than values. If you find a leak or a path-containment problem, follow [SECURITY.md](SECURITY.md) and do not attach a real configuration to a public issue.

## License

MIT. See [LICENSE](LICENSE).
