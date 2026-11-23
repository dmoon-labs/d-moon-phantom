# Release notes - D-MOON PHANTOM 1.0.0

## What is in the box
100 tools (URL & phishing 15, domain 12, DNS 10, TLS 10, HTTP 12, IP & network 12, file 10, email 8,
threat intelligence 6, reporting 5), Python engine, Ruby CLI, optional Rust core, installer, docs.

## Verification status at packaging time
Verified in the build environment (Linux x86_64, Python 3.12): all engine tests, per-tool cases, input
validation, CLI protocol and static security checks. Live network tools were tested against loopback
servers (UDP DNS, TLS, HTTP, TCP) only.

NOT executed in the build environment (no toolchain / wrong CPU): `ruby -c` and the Ruby CLI, `cargo test`
for the Rust core, and any ARM64 run. Those gates are reported as **NOT RUN**, and the release is therefore
**not declared stable yet**. On your Termux device run:

```sh
./install.sh --with-core
python3 tools/release_verify.py
```
When every gate prints PASS, 1.0.0 may be marked stable. If a Ruby or Rust gate fails, fix it before tagging.

## Honest limitations
- Heuristics can be wrong; no tool replaces threat-intelligence services.
- No bundled Public Suffix List or reputation data.
- Rust core covers URL normalization and hostname validation only.
