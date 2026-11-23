# Architecture

```
phantom (Ruby)  --argv, JSON stdin/stdout-->  python3 -m phantom_engine run <tool>   (100 tools)
      |
      +--JSON stdin/stdout-->  phantom-core (Rust, optional): normalize_url, validate_hostname
```

## Components
- **engine/phantom_engine** (Python, stdlib): `registry.py` (tool IDs, schemas, permissions), `runner.py`
  (validation, authorization gate, result envelope), `tools_*.py` (one module per category).
- **lib/phantom** (Ruby): `cli.rb` routing, `workflows.rb` (ordered tool lists), `engine.rb` and `core.rb`
  (protocol clients), `exec.rb` (process runner, argv only, timeouts), `banner.rb` (ASCII moon).
- **core** (Rust): memory-safe URL/hostname primitives with unit tests.

## Protocol
Request: one JSON object of parameters on stdin. Response envelope:
`{"ok":true,"tool_id":"URL-014","tool":"url.phishing_score","result":{...},"risk":{"score":..,"label":..}}`
or `{"ok":false,"error":{"code":"bad_params","message":"..."}}`. Errors never include tracebacks.

## Safety model
- Permissions: `none`, `file-read`, `file-write`, `network`. Network tools are refused without `authorized=true`.
- Limits: 8 MiB string params, 64 MiB file reads (1 GiB streaming for hashes), 20 ports, 1-15 s timeouts, 0.2 s
  network rate limit, bounded redirects.
- Findings carry `kind`: `fact`, `heuristic`, `intel`. Only imported feeds produce `intel`.
- Reports: JSON on disk under `$PHANTOM_HOME/reports`, ID `RPT-YYYYMMDD-HHMMSS-xxxxxxxx`, IDs validated before
  any path is built.

## Adding a tool
Register with `@tool("CAT-NNN", "name", "description", "param:type=default, ...", "output_keys", perm)`, add a test
case, run `tools/gen_docs.py` and `tools/release_verify.py`.
