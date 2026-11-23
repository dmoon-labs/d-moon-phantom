"""JSON-over-stdio protocol used by the Ruby orchestrator.

  python3 -m phantom_engine run <tool>      stdin: {"param": ...}   stdout: envelope
  python3 -m phantom_engine list            stdout: all tool schemas
  python3 -m phantom_engine counts          stdout: implemented counts
"""
import json
import sys

from . import registry
from .runner import VERSION, load_all, run


def main(argv):
    load_all()
    if len(argv) < 2:
        sys.stderr.write("usage: phantom_engine run <tool> | list | counts | version\n")
        return 2
    cmd = argv[1]
    if cmd == "version":
        print(VERSION)
        return 0
    if cmd == "counts":
        print(json.dumps(registry.counts()))
        return 0
    if cmd == "list":
        print(json.dumps([t.schema() for t in sorted(registry.REGISTRY.values(), key=lambda t: t.id)]))
        return 0
    if cmd == "run" and len(argv) >= 3:
        raw = sys.stdin.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            env = {"ok": False, "error": {"code": "too_large", "message": "stdin exceeds 16 MiB"}}
        else:
            try:
                params = json.loads(raw) if raw.strip() else {}
                env = run(argv[2], params)
            except json.JSONDecodeError as e:
                env = {"ok": False, "tool": argv[2], "error": {"code": "bad_json", "message": str(e)[:120]}}
        sys.stdout.write(json.dumps(env, ensure_ascii=False))
        sys.stdout.write("\n")
        return 0 if env.get("ok") else 1
    sys.stderr.write("unknown engine command: %s\n" % cmd[:40])
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
