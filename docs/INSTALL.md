# Installation

## Requirements
Python 3.8+, Ruby 2.7+. Optional: Rust (core), git (updates). No Docker, no root.

## Termux (Android ARM64)
```sh
pkg update && pkg install -y python ruby git
git clone <repository-url> d-moon-phantom && cd d-moon-phantom     # or extract the release archive
./install.sh                # installs launcher into $PREFIX/bin and runs phantom doctor
./install.sh --with-core    # additionally: pkg install rust, cargo build --release in core/
```

## Linux
Install python3 and ruby with your package manager, then `./install.sh` (launcher goes to `~/.local/bin`).

## Dependency check
`phantom doctor` checks Python, Ruby, the engine (100 tools), the optional Rust core, the data directory,
platform and git.

## Offline mode
Everything except `analyze dns`, `inspect ssl`, `inspect headers`, `dns.query`, `tls.live_handshake`,
`http.fetch` and `net.tcp_probe` works with no network. Add `--offline` to guarantee that.

## Verify the installation
```sh
python3 tools/release_verify.py
```
Writes `registry_status.json` (read by `phantom system status`) and `registry.json` (per-tool test and
documentation status).

## Upgrade
Git install: `phantom update` (fast-forward only), then rebuild the core if used, then `phantom doctor`.
Archive install: extract the new release over the folder, run `./install.sh`.

## Uninstall
`./uninstall.sh` removes the launcher. `./uninstall.sh --purge` also offers to delete `~/.d-moon`.
Delete the project folder to remove the program files.
