# Contributing

1. Every tool lives in `engine/phantom_engine/tools_*.py` and is registered with `@tool(...)`
   (ID, name, description, input spec, output keys, permission).
2. Add at least one case in `tests/cases.py` that checks real behaviour (not just "returns ok").
   A tool counts as tested only if a case passes.
3. Run `python3 tools/gen_docs.py` to regenerate `docs/TOOLS.md`.
4. Run `python3 tools/release_verify.py`. Do not edit counts by hand and never mark a gate as passed
   if it was NOT RUN.
5. Rules: defensive scope only; standard library only in the engine; no shell, `eval` or `pickle`;
   network behaviour needs `perm="network"`; label findings honestly (`fact` / `heuristic` / `intel`).
6. Never commit personal data or developer identities.

Code style: short functions, explicit errors via `PhantomError(code, message)`, no tracebacks across the protocol.
