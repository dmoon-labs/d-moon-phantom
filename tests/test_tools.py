import json
import os
import re
import subprocess
import sys
import unittest

from cases import CASES, E, HERE, R, registry, run

ROOT = os.path.dirname(HERE)
ENGINE = os.path.join(ROOT, "engine")


class PerToolCases(unittest.TestCase):
    def test_cases(self):
        for name, label, fn in CASES:
            with self.subTest(tool=name, case=label):
                fn()


class Registry(unittest.TestCase):
    def test_counts_and_integrity(self):
        self.assertGreaterEqual(len(registry.REGISTRY), 100)
        per = registry.counts()["per_category"]
        self.assertEqual(per, registry.EXPECTED)
        names = [t.name for t in registry.REGISTRY.values()]
        self.assertEqual(len(names), len(set(names)))
        for t in registry.REGISTRY.values():
            self.assertTrue(t.description.strip(), t.id)
            self.assertTrue(t.outputs, t.id)
            self.assertIn(t.permission, registry.PERMISSIONS)
            self.assertRegex(t.id, r"^[A-Z]{3}-\d{3}$")

    def test_every_tool_has_a_case(self):
        covered = {n for n, _, _ in CASES}
        missing = sorted(t.name for t in registry.REGISTRY.values() if t.name not in covered)
        self.assertEqual(missing, [])


class InputValidation(unittest.TestCase):
    def test_missing_wrong_type_and_unknown_params(self):
        for t in registry.REGISTRY.values():
            with self.subTest(tool=t.name):
                req = [k for k, v in t.inputs.items() if v["required"]]
                if req:
                    self.assertEqual(run(t.name, {})["error"]["code"], "bad_params")
                    wrong = {k: (12345 if t.inputs[k]["type"] != "int" else "x") for k in req}
                    self.assertEqual(run(t.name, wrong)["error"]["code"], "bad_params")
                self.assertEqual(run(t.name, {"zz_unknown": 1})["error"]["code"], "bad_params")
        self.assertEqual(run("no.such.tool", {})["error"]["code"], "unknown_tool")
        self.assertEqual(run("url.normalize", [])["error"]["code"], "bad_params")

    def test_network_tools_require_authorization(self):
        params = {"dns.query": {"name": "example.test"}, "tls.live_handshake": {"host": "127.0.0.1"},
                  "http.fetch": {"url": "http://127.0.0.1:9/"}, "net.tcp_probe": {"host": "127.0.0.1", "ports": [9]}}
        nets = [t.name for t in registry.REGISTRY.values() if t.permission == "network"]
        self.assertEqual(sorted(nets), sorted(params))
        for n, p in params.items():
            self.assertEqual(run(n, p)["error"]["code"], "not_authorized", n)
            self.assertEqual(run(n, dict(p, authorized="yes"))["error"]["code"], "not_authorized", n)

    def test_hostile_inputs_never_crash(self):
        nasty = ["\x00" * 10, "A" * 100000, "http://" + "a." * 5000, "%" * 3000, "\ud800".encode("utf-8", "ignore").decode(),
                 "[::1", "http://[::1]:99999/", "http://\u202e.example/"]
        for t in registry.REGISTRY.values():
            if t.permission != "none":
                continue
            strs = [k for k, v in t.inputs.items() if v["required"] and v["type"] == "str"]
            if not strs:
                continue
            for s in nasty:
                env = run(t.name, {k: s for k in strs})
                self.assertIn("ok", env, (t.name, s[:20]))
                if not env["ok"]:
                    self.assertNotEqual(env["error"]["code"], "internal", (t.name, s[:20], env["error"]))


class Safety(unittest.TestCase):
    def test_url_tools_are_offline(self):
        for t in registry.REGISTRY.values():
            if t.id.startswith("URL-"):
                self.assertEqual(t.permission, "none", t.id)
        src = open(os.path.join(ENGINE, "phantom_engine", "tools_url.py")).read()
        for bad in ("import socket", "urllib.request", "http.client", "requests"):
            self.assertNotIn(bad, src)

    def test_no_dangerous_calls_in_engine(self):
        pat = re.compile(r"shell\s*=\s*True|os\.system|\beval\(|\bexec\(|pickle|subprocess|__import__|os\.popen")
        d = os.path.join(ENGINE, "phantom_engine")
        for f in os.listdir(d):
            if f.endswith(".py"):
                self.assertIsNone(pat.search(open(os.path.join(d, f)).read()), f)

    def test_report_html_has_no_scripts(self):
        h = R("report.render_html", report={"title": "x", "findings": []})["html"]
        self.assertNotIn("<script", h.lower())


class Protocol(unittest.TestCase):
    def _call(self, args, stdin=""):
        env = dict(os.environ, PYTHONPATH=ENGINE)
        return subprocess.run([sys.executable, "-m", "phantom_engine"] + args, input=stdin,
                              capture_output=True, text=True, env=env, timeout=60)

    def test_run_roundtrip(self):
        r = self._call(["run", "url.normalize"], json.dumps({"url": "HTTP://A.com:80/x"}))
        self.assertEqual(r.returncode, 0, r.stderr)
        env = json.loads(r.stdout)
        self.assertTrue(env["ok"])
        self.assertEqual(env["result"]["normalized"], "http://a.com/x")
        self.assertEqual(env["tool_id"], "URL-001")

    def test_error_paths(self):
        r = self._call(["run", "url.normalize"], "{not json")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(r.stdout)["error"]["code"], "bad_json")
        r = self._call(["run", "nope"], "{}")
        self.assertEqual(json.loads(r.stdout)["error"]["code"], "unknown_tool")
        self.assertEqual(self._call(["bogus"]).returncode, 2)

    def test_list_and_counts(self):
        tools = json.loads(self._call(["list"]).stdout)
        self.assertGreaterEqual(len(tools), 100)
        self.assertEqual(json.loads(self._call(["counts"]).stdout)["implemented"], len(tools))
        for t in tools:
            for k in ("id", "name", "category", "description", "language", "input_schema", "output_schema", "permission"):
                self.assertIn(k, t)


class Branding(unittest.TestCase):
    def test_logo_has_required_text_and_no_emoji(self):
        t = open(os.path.join(ROOT, "assets", "logo.txt"), encoding="utf-8").read()
        for ch in t:
            if ch == "\n":
                continue
            # plain ASCII or Unicode braille patterns (U+2800-U+28FF); never emoji
            self.assertTrue(ord(ch) < 128 or 0x2800 <= ord(ch) <= 0x28FF, "unexpected character %r" % ch)
        lines = t.splitlines()
        self.assertIn("CYBERSECURITY INTELLIGENCE SUITE", [l.strip() for l in lines])
        beside = [l for l in lines if l.endswith(("D-MOON", "PHANTOM")) and any(0x2800 <= ord(c) <= 0x28FF for c in l)]
        self.assertEqual(sorted(l.split()[-1] for l in beside), ["D-MOON", "PHANTOM"],
                         "D-MOON and PHANTOM must sit beside the moon art")
        self.assertLess(max(len(l) for l in lines), 45, "must fit a phone terminal")


if __name__ == "__main__":
    unittest.main()
