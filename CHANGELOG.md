# Changelog

All notable changes are documented here. Format: Keep a Changelog; versioning: SemVer.

## [1.0.0] - 2026-11-23

First release of D-MOON PHANTOM.

### Added
- Registry of 100 tools in 10 categories (URL & phishing 15, domain 12, DNS 10, TLS 10, HTTP 12,
  IP & network 12, file 10, email 8, threat intelligence 6, reporting 5), each with ID, schemas,
  permission level, tests and generated documentation.
- Python detection/intelligence engine (standard library only) with a JSON-over-stdio protocol.
- Ruby orchestrator: `phantom` CLI, command routing, workflows, report management, `doctor`, `update`.
- Rust core: URL normalization and hostname validation over JSON stdio (optional, Python fallback).
- ASCII crescent-moon branding, JSON/TXT/HTML reports, offline analysis mode.
- `tools/release_verify.py` release gates; counts are computed, never typed in.
- Installer/uninstaller for Termux (ARM64) and Linux.

### Known limits
- The Public Suffix List is not bundled; a small multi-part suffix subset is used.
- No bundled threat-intelligence data: "verified" intelligence exists only for feeds you import.
- Stable status requires `tools/release_verify.py` to pass every gate on the target device.
