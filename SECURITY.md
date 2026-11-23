# Security policy

D-MOON PHANTOM is a defensive toolkit. Use it only on systems you own or are explicitly authorized to assess.

## Reporting a vulnerability
Open a private security advisory on the project's repository, or email the maintainers listed there.
Include the version (`phantom --version`), steps to reproduce and impact. Please allow 90 days for a fix
before public disclosure.

## Design guarantees
- No tool exploits, brute-forces, floods, evades monitoring or steals credentials.
- Suspicious URLs are never visited. URL tools have permission `none`.
- Network tools (`dns.query`, `tls.live_handshake`, `http.fetch`, `net.tcp_probe`) refuse to run unless
  `authorized=true` / `--authorized` is given, clamp timeouts to 1-15 s, rate-limit requests, cap ports to 20
  and send no exploit payloads.
- Child processes are started from argument arrays, never through a shell.
- Files are read-only inspected; archives are listed, never extracted; HTML reports escape every value
  and carry a restrictive Content-Security-Policy.
- Findings are labelled `fact`, `heuristic` or `intel`. Heuristics are not threat-intelligence verdicts.

## Out of scope
Results depend on the data you supply. A low score is not proof of safety.
