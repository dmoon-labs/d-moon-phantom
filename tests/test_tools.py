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
    ALLOWED_EXTRA = {"\u2729"}   # the star used by one of the moons

    def moons(self):
        d = os.path.join(ROOT, "assets", "moons")
        return {f[:-4]: open(os.path.join(d, f), encoding="utf-8").read() for f in os.listdir(d) if f.endswith(".txt")}

    def test_moon_files(self):
        moons = self.moons()
        self.assertEqual(sorted(moons, key=int), ["0", "1", "2", "3", "4", "5", "6"])
        for mid, text in moons.items():
            with self.subTest(moon=mid):
                lines = text.splitlines()
                self.assertGreaterEqual(len(lines), 5)
                self.assertEqual(len({len(l) for l in lines}), 1, "moon must be a padded rectangle")
                self.assertLessEqual(len(lines[0]), 60)
                self.assertTrue(text.strip())
                for ch in text:
                    if ch == "\n":
                        continue
                    ok = ord(ch) < 128 or 0x2800 <= ord(ch) <= 0x28FF or ch in self.ALLOWED_EXTRA
                    self.assertTrue(ok, "unexpected character %r (no emoji allowed)" % ch)
                    self.assertNotEqual(ch, "\u2800", "blank braille must be normalized to a space")

    def test_readme_banner_exists(self):
        readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
        self.assertIn('src="assets/banner.png"', readme)
        png = os.path.join(ROOT, "assets", "banner.png")
        self.assertTrue(os.path.isfile(png))
        self.assertEqual(open(png, "rb").read(8), b"\x89PNG\r\n\x1a\n")
        for anchor in ("quick-start", "the-100-tools", "bahasa-indonesia"):
            self.assertIn('href="#%s"' % anchor, readme)

    def test_banner_text_and_menu_are_wired(self):
        src = open(os.path.join(ROOT, "lib", "phantom", "banner.rb"), encoding="utf-8").read()
        for needle in ("D-MOON", "PHANTOM", "CYBERSECURITY INTELLIGENCE SUITE"):
            self.assertIn("'%s'" % needle, src)
        cli = open(os.path.join(ROOT, "lib", "phantom", "cli.rb"), encoding="utf-8").read()
        for needle in ("cmd_art", "art_menu", "save_setting"):
            self.assertIn(needle, cli + open(os.path.join(ROOT, "lib", "phantom", "config.rb")).read())


if __name__ == "__main__":
    unittest.main()
