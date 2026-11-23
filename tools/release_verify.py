#!/usr/bin/env python3
"""Automated release verification for D-MOON PHANTOM.

Every gate reports PASS, FAIL or NOT RUN (a required toolchain or platform is
missing). VERSION 1.0.0 is declared stable only when ALL gates PASS. Counts are
computed, never typed in. Writes registry_status.json and registry.json.
"""
import json
import os
import platform
import re
import resource
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "engine"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

PASS, FAIL, NOT_RUN = "PASS", "FAIL", "NOT RUN"
gates = {}
notes = {}


def gate(name, status, note=""):
    gates[name] = status
    notes[name] = note


def run_cases():
    import cases
    per_tool = {}
    t0 = time.time()
    for name, label, fn in cases.CASES:
        try:
            fn()
            per_tool.setdefault(name, []).append(True)
        except Exception as e:  # noqa: BLE001 - report every failure
            per_tool.setdefault(name, []).append(False)
            print("  case failed: %s [%s]: %s" % (name, label, str(e)[:150]))
    return cases, per_tool, time.time() - t0


def sh(cmd, cwd=ROOT, timeout=900):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def main():
    from phantom_engine import registry
    import gen_docs
    cases, per_tool, elapsed = run_cases()
    reg = registry.REGISTRY
    expected = registry.EXPECTED

    # 1 catalog size and shape
    per_cat = registry.counts()["per_category"]
    ok = len(reg) >= 100 and per_cat == expected
    gate("catalog: >=100 tools, category counts match", PASS if ok else FAIL,
         "%d tools" % len(reg))
    bad = [t.id for t in reg.values() if not (t.description.strip() and t.outputs and t.inputs is not None)]
    gate("registry: every tool has description/schemas", PASS if not bad else FAIL, ",".join(bad[:5]))

    # 2 per-tool tests
    tested = {n for n, r in per_tool.items() if r and all(r)}
    untested = sorted(t.name for t in reg.values() if t.name not in tested)
    gate("tests: every tool has passing cases", PASS if not untested else FAIL,
         "untested: %s" % ", ".join(untested[:8]) if untested else "%d/%d tools" % (len(tested), len(reg)))

    # 3 unittest suite (validation, protocol, safety, branding)
    r = sh([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"])
    gate("tests: unittest suite (validation, CLI protocol, safety)", PASS if r.returncode == 0 else FAIL,
         r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "")

    # 4 documentation
    docs_path = os.path.join(ROOT, "docs", "TOOLS.md")
    current = open(docs_path, encoding="utf-8").read() if os.path.isfile(docs_path) else ""
    fresh = current == gen_docs.render()
    documented = {t.name for t in reg.values() if "`%s`" % t.name in current and t.description in current}
    required_docs = ["README.md", "LICENSE", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md",
                     "docs/INSTALL.md", "docs/ARCHITECTURE.md", "docs/TOOLS.md", "docs/RELEASE_NOTES.md"]
    missing_docs = [d for d in required_docs if not os.path.isfile(os.path.join(ROOT, d))]
    gate("docs: catalog is current and release documents exist", PASS if fresh and not missing_docs else FAIL,
         ("stale TOOLS.md; run tools/gen_docs.py " if not fresh else "") + ("missing: %s" % missing_docs if missing_docs else ""))

    # 5 Ruby syntax
    rb = [os.path.join(dp, f) for dp, _, fs in os.walk(os.path.join(ROOT, "lib")) for f in fs if f.endswith(".rb")]
    rb.append(os.path.join(ROOT, "bin", "phantom"))
    if shutil.which("ruby"):
        errs = []
        for f in rb:
            p = sh(["ruby", "-c", f])
            if p.returncode != 0:
                errs.append("%s: %s" % (os.path.basename(f), (p.stderr or p.stdout).strip()[:100]))
        gate("ruby: syntax check (ruby -c)", PASS if not errs else FAIL, "; ".join(errs))
        if not errs:
            p = sh([os.path.join(ROOT, "bin", "phantom"), "--version"])
            gate("ruby: CLI starts (phantom --version)", PASS if p.returncode == 0 and "1.0.0" in p.stdout else FAIL, p.stderr.strip()[:100])
            p = sh([os.path.join(ROOT, "bin", "phantom"), "scan", "url", "http://paypa1.com/login", "--no-save", "--no-color"])
            gate("ruby+python: CLI end-to-end (scan url)", PASS if p.returncode in (0, 3) and "D-MOON" in p.stdout else FAIL,
                 (p.stderr or "")[:150])
        else:
            gate("ruby: CLI starts (phantom --version)", NOT_RUN, "syntax errors")
            gate("ruby+python: CLI end-to-end (scan url)", NOT_RUN, "syntax errors")
    else:
        for g in ("ruby: syntax check (ruby -c)", "ruby: CLI starts (phantom --version)", "ruby+python: CLI end-to-end (scan url)"):
            gate(g, NOT_RUN, "ruby not installed here (pkg install ruby)")

    # 6 Rust core
    if shutil.which("cargo"):
        c = sh(["cargo", "test", "--quiet"], cwd=os.path.join(ROOT, "core"))
        gate("rust: cargo test", PASS if c.returncode == 0 else FAIL, (c.stderr or c.stdout).strip()[-200:])
    else:
        gate("rust: cargo test", NOT_RUN, "cargo not installed here (pkg install rust)")

    # 7 ARM64
    mach = platform.machine().lower()
    if mach in ("aarch64", "arm64"):
        gate("platform: ARM64 run", PASS, "executed on %s with Python %s" % (mach, platform.python_version()))
    else:
        gate("platform: ARM64 run", NOT_RUN, "this machine is %s; run this script on the Android device" % mach)

    # 8 static security review
    py_pat = re.compile(r"shell\s*=\s*True|os\.system|\beval\(|\bexec\(|pickle|subprocess|__import__|os\.popen")
    rb_pat = re.compile(r"`|%x[\[({]|\bsystem\s*\(|\bexec\s*\(|\beval\b|IO\.popen|Kernel\.open|Open3\.capture|Kernel\.exec")
    rs_pat = re.compile(r"\bunsafe\b|std::net|std::fs|process::Command")
    problems = []
    for dp, _, fs in os.walk(os.path.join(ROOT, "engine")):
        for f in fs:
            if f.endswith(".py") and py_pat.search(open(os.path.join(dp, f), encoding="utf-8").read()):
                problems.append("py:" + f)
    for f in rb:
        if rb_pat.search(open(f, encoding="utf-8").read()):
            problems.append("rb:" + os.path.basename(f))
    for f in os.listdir(os.path.join(ROOT, "core", "src")):
        if rs_pat.search(open(os.path.join(ROOT, "core", "src", f), encoding="utf-8").read()):
            problems.append("rs:" + f)
    net_tools = sorted(t.name for t in reg.values() if t.permission == "network")
    gate("security: static review (no shell/eval/unsafe; network tools gated)", PASS if not problems else FAIL,
         ", ".join(problems) or "network tools: " + ", ".join(net_tools))

    # 9 resources
    rss_mb = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss + resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss) / 1024.0
    if sys.platform == "darwin":
        rss_mb /= 1024.0
    ok = rss_mb < 400 and elapsed < 120
    gate("resources: peak RSS < 400 MB and all tool cases < 120 s", PASS if ok else FAIL,
         "peak %.0f MB, cases took %.1f s" % (rss_mb, elapsed))

    # report
    status_ok = all(v == PASS for v in gates.values())
    summary = {
        "version": open(os.path.join(ROOT, "VERSION")).read().strip(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "implemented": len(reg), "tested": len(tested), "documented": len(documented),
        "per_category": per_cat, "gates": gates, "gate_notes": notes,
        "stable": status_ok, "machine": mach, "python": platform.python_version(),
    }
    with open(os.path.join(ROOT, "registry_status.json"), "w") as fh:
        json.dump(summary, fh, indent=1)
    catalog = []
    for t in sorted(reg.values(), key=lambda t: t.id):
        s = t.schema()
        s["test_status"] = "passing" if t.name in tested else "not passing"
        s["documentation_status"] = "documented" if t.name in documented else "missing"
        catalog.append(s)
    with open(os.path.join(ROOT, "registry.json"), "w") as fh:
        json.dump({"version": summary["version"], "tools": catalog}, fh, indent=1)

    print("\nD-MOON PHANTOM release verification")
    print("=" * 60)
    for name, st in gates.items():
        print("%-8s %s%s" % (st, name, ("  -> " + notes[name]) if notes[name] else ""))
    print("-" * 60)
    print("implemented=%d  tested=%d  documented=%d" % (len(reg), len(tested), len(documented)))
    if status_ok:
        print("RESULT: all gates PASS. VERSION %s may be marked stable." % summary["version"])
        return 0
    pending = [n for n, s in gates.items() if s != PASS]
    print("RESULT: NOT STABLE. %d gate(s) not passing:" % len(pending))
    for n in pending:
        print("  - [%s] %s" % (gates[n], n))
    return 1


if __name__ == "__main__":
    sys.exit(main())
