# D-MOON PHANTOM

Defensive cybersecurity intelligence suite for Android (Termux, ARM64) and Linux.
100 implemented tools in 10 categories, one CLI: `phantom`.

- **Python engine**: detection, heuristics, file/domain/URL/email analysis (standard library only)
- **Ruby orchestrator**: CLI, command routing, workflows, reports
- **Rust core**: optional fast URL normalization / hostname validation

## Quick start (Termux)

```sh
pkg install -y python ruby git
./install.sh              # add --with-core to build the Rust core (pkg install rust)
phantom --help
phantom scan phishing "http://paypal.com.secure-login.xyz/verify"
phantom analyze domain secure-paypal.xyz
phantom file analyze ./sample.bin
phantom analyze dns example.com --authorized      # live, only for domains you may test
phantom inspect ssl example.com --authorized
phantom inspect headers https://example.com --authorized
phantom report list
phantom doctor
```

## Principles
- Defensive only. Network commands need `--authorized`; `--offline` blocks them completely.
- Suspicious URLs are **never visited**.
- Every finding says what it is: `fact`, `heuristic` or `intel` (a match in a feed you imported).
- Counts come from the registry and the test run, not from this README. Check with
  `phantom system status` and `python3 tools/release_verify.py`.

## Commands
See `phantom --help`. Any single tool: `phantom tools list`, `phantom tools info url.normalize`,
`phantom run url.normalize url="HTTP://Example.com:80/a/../b"`. Use `key=@file.txt` to pass file content.
Reports are stored under `~/.d-moon/reports` (`PHANTOM_HOME` overrides) as JSON; export with
`phantom report show <ID> --format html --html report.html`.

## Documentation
`docs/INSTALL.md`, `docs/ARCHITECTURE.md`, `docs/TOOLS.md` (generated catalog), `docs/RELEASE_NOTES.md`,
`SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.

## License
MIT (see `LICENSE`).
