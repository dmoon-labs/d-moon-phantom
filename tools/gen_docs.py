#!/usr/bin/env python3
"""Generates docs/TOOLS.md from the live registry."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "engine"))

from phantom_engine import registry  # noqa: E402
from phantom_engine.runner import load_all  # noqa: E402


def render():
    load_all()
    out = ["# D-MOON PHANTOM tool catalog", "",
           "Generated from the registry by `tools/gen_docs.py`. Do not edit by hand.", "",
           "Permissions: `none` pure computation on supplied data, `file-read` reads a local file, "
           "`file-write` writes under `$PHANTOM_HOME`, `network` needs `--authorized`.", "",
           "Finding basis: `fact` deterministic check on the input, `heuristic` rule of thumb, "
           "`intel` match in a feed you imported.", ""]
    total = 0
    for code, cat in registry.CATEGORIES.items():
        tools = sorted((t for t in registry.REGISTRY.values() if t.id.startswith(code + "-")), key=lambda t: t.id)
        out += ["## %s (%d)" % (cat, len(tools)), ""]
        for t in tools:
            total += 1
            ins = ", ".join("%s:%s%s" % (k, v["type"], "" if v["required"] else "?") for k, v in t.inputs.items()) or "-"
            out += ["### %s `%s`" % (t.id, t.name), "", t.description, "",
                    "- Permission: `%s`   Language: %s" % (t.permission, t.language),
                    "- Inputs: `%s`  (`?` = optional)" % ins,
                    "- Outputs: `%s`" % ", ".join(t.outputs), ""]
    out.insert(2, "Total tools: **%d**" % total)
    out.insert(3, "")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    path = os.path.join(ROOT, "docs", "TOOLS.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render())
    print("wrote", path)
