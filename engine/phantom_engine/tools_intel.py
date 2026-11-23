"""I. Threat Intelligence (6 tools). Offline. 'Verified' intelligence only ever
comes from feeds YOU import; everything else is labelled heuristic."""
import json
import math
import os
import re
from datetime import datetime, timezone

from .common import F, PhantomError, home
from .registry import tool

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def refang(s):
    s = s.strip()
    s = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]", ".", s, flags=re.I)
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    s = s.replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")
    return s


def classify(s):
    v = refang(s)
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v):
        parts = v.split(".")
        return "ipv4" if all(int(x) <= 255 for x in parts) else "invalid"
    if re.fullmatch(r"[0-9a-fA-F:]{3,39}", v) and v.count(":") >= 2:
        return "ipv6"
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I):
        return "url"
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", v, re.I):
        return "cve"
    if re.fullmatch(r"[A-Fa-f0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"[A-Fa-f0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[A-Fa-f0-9]{32}", v):
        return "md5"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}", v):
        return "email"
    if re.fullmatch(r"(?:[A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,24}", v):
        return "domain"
    return "unknown"


def norm(s):
    v = refang(s)
    t = classify(s)
    if t == "cve":
        return v.upper()
    if t in ("domain", "md5", "sha1", "sha256", "email", "ipv6"):
        return v.lower()
    return v


@tool("INT-001", "intel.ioc_classify", "Detect the type of each indicator (IPv4/IPv6/domain/URL/hash/email/CVE), accepting defanged input.",
      "iocs:list", "classified, counts")
def int_classify(p):
    out, counts = [], {}
    for x in p["iocs"][:10000]:
        x = str(x)
        t = classify(x)
        counts[t] = counts.get(t, 0) + 1
        out.append({"input": x[:200], "type": t, "normalized": norm(x)[:200]})
    return {"classified": out, "counts": counts}


@tool("INT-002", "intel.defang_refang", "Defang indicators for safe sharing (hxxp, [.]) or restore them to normal form.",
      "text:str, mode:str=defang", "result, changed")
def int_defang(p):
    if p["mode"] not in ("defang", "refang"):
        raise PhantomError("bad_params", "mode must be defang or refang")
    t = p["text"]
    if p["mode"] == "refang":
        r = refang(t) if "\n" not in t else "\n".join(refang(x) for x in t.splitlines())
    else:
        r = re.sub(r"https?://", lambda m: m.group(0).replace("http", "hxxp"), t, flags=re.I)
        r = re.sub(r"(?<=[A-Za-z0-9-])\.(?=[A-Za-z0-9-])", "[.]", r)
        r = r.replace("@", "[@]")
    return {"result": r, "changed": r != t}


def _feed_dir():
    d = os.path.join(home(), "feeds")
    os.makedirs(d, exist_ok=True)
    return d


@tool("INT-003", "intel.feed_import", "Import a local IOC list (lines: ioc[,label[,source]]) into PHANTOM's local feed store under a name you choose.",
      "path:str, name:str", "name, count, types, stored_at", "file-write")
def int_import(p):
    from .common import read_file
    if not NAME_RE.match(p["name"]):
        raise PhantomError("bad_params", "name must match [A-Za-z0-9_-]{1,40}")
    text = read_file(p["path"], 32 * 1024 * 1024).decode("utf-8", "replace")
    entries, types = {}, {}
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        parts = [x.strip() for x in line.split(",")]
        ioc = norm(parts[0])
        t = classify(parts[0])
        if t in ("unknown", "invalid"):
            continue
        entries[ioc] = {"type": t, "label": parts[1] if len(parts) > 1 else "", "source": parts[2] if len(parts) > 2 else ""}
        types[t] = types.get(t, 0) + 1
    if not entries:
        raise PhantomError("empty_feed", "no valid indicators found in file")
    dest = os.path.join(_feed_dir(), p["name"] + ".json")
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump({"name": p["name"], "imported_at": datetime.now(timezone.utc).isoformat(),
                   "count": len(entries), "entries": entries}, fh)
    return {"name": p["name"], "count": len(entries), "types": types, "stored_at": dest}


@tool("INT-004", "intel.feed_lookup", "Look up indicators in your imported feeds. A match is a fact about YOUR feed, not an independent verdict.",
      "iocs:list, feed:str=", "matches, checked, feeds_searched, findings", "file-read")
def int_lookup(p):
    d, feeds = _feed_dir(), []
    names = [p["feed"]] if p["feed"] else [f[:-5] for f in sorted(os.listdir(_feed_dir())) if f.endswith(".json")]
    for n in names:
        if not NAME_RE.match(n):
            raise PhantomError("bad_params", "invalid feed name")
        fp = os.path.join(d, n + ".json")
        if not os.path.isfile(fp):
            raise PhantomError("not_found", "feed not imported: " + n)
        with open(fp, encoding="utf-8") as fh:
            feeds.append(json.load(fh))
    matches, fi = [], []
    for x in p["iocs"][:10000]:
        key = norm(str(x))
        for fd in feeds:
            e = fd["entries"].get(key)
            if e:
                matches.append({"ioc": key, "feed": fd["name"], "imported_at": fd["imported_at"], **e})
                fi.append(F("high", "%s is listed in feed '%s'" % (key[:80], fd["name"]),
                            "label=%s source=%s imported=%s" % (e["label"] or "-", e["source"] or "-", fd["imported_at"][:10]), "intel"))
    return {"matches": matches, "checked": len(p["iocs"]), "feeds_searched": [f["name"] for f in feeds], "findings": fi}


_AV = {"N": .85, "A": .62, "L": .55, "P": .2}
_AC = {"L": .77, "H": .44}
_UI = {"N": .85, "R": .62}
_CIA = {"H": .56, "L": .22, "N": 0.0}


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


@tool("INT-005", "intel.cvss_calc", "Compute the CVSS v3.0/v3.1 base score and severity from a vector string.",
      "vector:str", "base_score, severity, impact, exploitability, metrics")
def int_cvss(p):
    v = p["vector"].strip()
    m = re.match(r"^CVSS:3\.[01]/(.+)$", v)
    if not m:
        raise PhantomError("bad_input", "vector must start with CVSS:3.0/ or CVSS:3.1/")
    met = dict(x.split(":", 1) for x in m.group(1).split("/") if ":" in x)
    need = {"AV": _AV, "AC": _AC, "UI": _UI, "C": _CIA, "I": _CIA, "A": _CIA, "S": {"U": 0, "C": 0}, "PR": {"N": 0, "L": 0, "H": 0}}
    for k, allowed in need.items():
        if met.get(k) not in allowed:
            raise PhantomError("bad_input", "missing or invalid metric " + k)
    changed = met["S"] == "C"
    pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[met["PR"]]
    iss = 1 - (1 - _CIA[met["C"]]) * (1 - _CIA[met["I"]]) * (1 - _CIA[met["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    expl = 8.22 * _AV[met["AV"]] * _AC[met["AC"]] * pr * _UI[met["UI"]]
    if impact <= 0:
        base = 0.0
    else:
        base = _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))
    sev = "None" if base == 0 else "Low" if base < 4 else "Medium" if base < 7 else "High" if base < 9 else "Critical"
    return {"base_score": base, "severity": sev, "impact": round(impact, 2), "exploitability": round(expl, 2), "metrics": met}


ATTACK = [
    (r"phish|malicious (link|attachment)|spearphish", "T1566", "Phishing"),
    (r"powershell|-enc(odedcommand)?\b", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    (r"cmd\.exe|batch file", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell"),
    (r"bash -i|/bin/sh|reverse shell", "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    (r"schtasks|scheduled task|cron job", "T1053", "Scheduled Task/Job"),
    (r"run key|currentversion\\run|startup folder", "T1547.001", "Boot or Logon Autostart: Registry Run Keys / Startup Folder"),
    (r"lsass|mimikatz|credential dump", "T1003", "OS Credential Dumping"),
    (r"brute.?force|password spray|failed logins?", "T1110", "Brute Force"),
    (r"dns tunnel|dga|beacon", "T1071.004", "Application Layer Protocol: DNS"),
    (r"web ?shell|c99|r57", "T1505.003", "Server Software Component: Web Shell"),
    (r"rdp|remote desktop", "T1021.001", "Remote Services: Remote Desktop Protocol"),
    (r"\bssh\b.*(lateral|pivot)|lateral movement", "T1021", "Remote Services"),
    (r"keylog", "T1056.001", "Input Capture: Keylogging"),
    (r"ransom|encrypted files|\.locked", "T1486", "Data Encrypted for Impact"),
    (r"exfil|data theft|large upload", "T1041", "Exfiltration Over C2 Channel"),
    (r"disable (defender|antivirus|logging)|clear (event )?logs?", "T1562", "Impair Defenses"),
    (r"base64|obfuscat|packed", "T1027", "Obfuscated Files or Information"),
    (r"dll side.?load|dll hijack", "T1574.002", "Hijack Execution Flow: DLL Side-Loading"),
    (r"macro|vba|autoopen", "T1204.002", "User Execution: Malicious File"),
    (r"port scan|nmap|network scan", "T1046", "Network Service Discovery"),
    (r"sql injection|sqli|xss exploit|public-facing", "T1190", "Exploit Public-Facing Application"),
    (r"valid accounts|stolen credentials|credential stuffing", "T1078", "Valid Accounts"),
    (r"usb|removable media", "T1091", "Replication Through Removable Media"),
    (r"domain controller|dcsync|ntds", "T1003.006", "OS Credential Dumping: DCSync"),
    (r"typosquat|lookalike domain|homograph", "T1583.001", "Acquire Infrastructure: Domains"),
]


@tool("INT-006", "intel.attack_map", "Map free-text observations to candidate MITRE ATT&CK technique IDs using a built-in keyword table (heuristic leads, verify manually).",
      "text:str", "techniques, count, findings")
def int_attack(p):
    t = p["text"].lower()
    hits, seen = [], set()
    for rx, tid, name in ATTACK:
        if re.search(rx, t) and tid not in seen:
            seen.add(tid)
            hits.append({"id": tid, "name": name})
    fi = [F("info", "Candidate technique %s: %s" % (h["id"], h["name"]), "Keyword match; confirm against evidence.", "heuristic") for h in hits]
    return {"techniques": hits, "count": len(hits), "findings": fi}
