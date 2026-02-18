# mcp-fs

Rust-based MCP server for filesystem access.

## Build

```bash
cargo build
```

## Build the browser UI

```bash
cd frontend
npm install
npm run build
```

## Run

```bash
cargo run -- --root "/path/to/project"
```

## Startup options

- `--root <path>`: configure the server root (default: CWD)
- `--allow-escape`: allow paths outside the configured root
- `--find-limit <n>`: default limit for `find_files` (default: 200). Use `0` to disable the default limit
- `--search-max-bytes <n>`: maximum output size for `search_files` responses (default: 51200). Use `0` for unlimited
- `--search-summary-top <n>`: when summary output is still too large, return top N files by match count (default: 20). Use `0` for unlimited
- `--read-max-bytes <n>`: maximum total output bytes for `read_file` (default: 51200). Use `0` for unlimited
- `--read-max-line-bytes <n>`: maximum bytes per line for `read_file` before truncation (default: 25600). Use `0` for unlimited
- `--allow-root <path>`: allow access to additional roots (repeatable). Relative paths are resolved from the configured root
- `--preview-cache-size <n>`: maximum number of preview diffs to keep (default: 100). Use `0` for unlimited
- `--otel-enabled <bool>`: enable OpenTelemetry tracing (default: true)
- `--otel-endpoint <url>`: OTLP endpoint (default: http://127.0.0.1:4317)
- `--otel-service-name <name>`: OTEL service.name (default: mcp-fs)

Environment variables:

- `MCP_ROOT`: same as `--root`
- `MCP_ALLOW_ESCAPE`: `1|true|yes` to allow escape
- `MCP_FIND_LIMIT`: same as `--find-limit`
- `MCP_SEARCH_MAX_BYTES`: same as `--search-max-bytes`
- `MCP_SEARCH_SUMMARY_TOP`: same as `--search-summary-top`
- `MCP_READ_MAX_BYTES`: same as `--read-max-bytes`
- `MCP_READ_MAX_LINE_BYTES`: same as `--read-max-line-bytes`
- `MCP_ALLOWED_ROOTS`: comma-separated list of additional allowed roots
- `MCP_PREVIEW_CACHE_SIZE`: same as `--preview-cache-size`
- `MCP_OTEL_ENABLED`: same as `--otel-enabled`
- `MCP_OTEL_ENDPOINT`: same as `--otel-endpoint`
- `MCP_OTEL_SERVICE_NAME`: same as `--otel-service-name`

## Tools

The server exposes tools via `tools/list` and `tools/call`:

- `find_files`: fd-compatible file finder
- `search_files`: ripgrep-based text search
- `read_file`: read file contents with start_line/limit
- `read_multiple_files`: read multiple files with per-file caps
- `write_file`: write changes (mode: `overwrite|append|prepend`)
- `edit_file`: replace exact matches in a file
- `list_roots`: list configured roots and per-call read grants
- `move_file`: move/rename a file or directory (fails if destination exists)
- `delete_file`: delete a file or directory recursively

Use `tools/list` to get full input/output schemas.

Notes:

- Preview mode for `edit_file` is enabled via `_meta.preview` inside `tools/call` params.
- Tools accept `_meta.granted_scopes` to allow per-call access to additional roots (string or array).

## MCP Extensions

### Preview Resources

Some tools expose preview artifacts through MCP resources.

- `edit_file` and `write_file` preview via `_meta.preview: true`.
- Preview results include two `content` links with types:
  - `review`: `ui://edit_file/<id>` or `ui://write_file/<id>` (HTML)
  - `diff`: `ui://edit_file/<id>.diff` or `ui://write_file/<id>.diff` (unified diff)
- The resources are available via `resources/list` and `resources/read`.
- `ui://` resources can be rendered using `mcp-view`, which injects them into an iframe.

### Tool Annotations

Tools include an `annotations` object to help clients choose the right tool.

- `scopes`: `read:file` or `write:file`
- `priority`: `edit_file` is `1` and `write_file` is `0` (prefer edit_file)
- `group`: `filesystem`

### Requested/Granted Scopes

When a request is outside the configured root or allowed roots (and `allow_escape` is off), the error response includes:

- `_meta.requested_scopes`: array of scope strings, e.g. `read:file:/abs/root` or `write:file:/abs/root`

Clients can retry the call with user-approved scopes by adding:

- `_meta.granted_scopes`: string or array of scope strings

Scopes are structured as `read:file` / `write:file` so clients can grant broader scopes (e.g. `write:*`) if desired.

### Default Root

Unless an absolute path is provided, tools resolve paths relative to the default root.
Use `list_roots` to discover the default root (marked with `default: true`).

Preview resources are exposed via:

- `resources/list`: lists available preview and static UI resources
- `resources/read`: reads a resource by URI (e.g., `ui://edit_file/<id>`)
