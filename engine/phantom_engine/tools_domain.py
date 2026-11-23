"""B. Domain Intelligence (12 tools). All offline / passive."""
import re

from .common import (BRANDS, F, MULTI_SUFFIX, PhantomError, RISKY_TLDS, entropy,
                     lev, parse_date, score, skeleton, split_domain, to_ascii_host,
                     utcnow, valid_hostname)
from .registry import tool

DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "yopmail.com",
              "tempmail.com", "throwaway.email", "sharklasers.com", "trashmail.com",
              "getnada.com", "maildrop.cc", "dispostable.com", "fakeinbox.com",
              "temp-mail.org", "mailnesia.com", "tempail.com"}
INTERESTING = ("admin", "dev", "test", "staging", "stage", "vpn", "internal", "git",
               "jenkins", "backup", "old", "beta", "uat", "intranet", "jira", "grafana",
               "kibana", "db", "sql", "ftp", "phpmyadmin", "panel", "cpanel")
CC_SPONSORED = {"gov", "edu", "mil", "int", "museum", "aero", "coop"}
GENERIC = {"com", "net", "org", "info", "biz", "name", "pro", "app", "dev", "io", "co"}
QWERTY = {"q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij",
          "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx", "d": "serfcx",
          "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "j": "huikmn", "k": "jiolm",
          "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
          "n": "bhjm", "m": "njk"}
HOMOGLYPH = {"a": ["а", "ɑ"], "e": ["е"], "o": ["о", "0"], "i": ["і", "1", "l"],
             "l": ["1", "i", "ӏ"], "c": ["с"], "p": ["р"], "s": ["ѕ", "5"], "m": ["rn"],
             "w": ["vv"], "d": ["cl"], "g": ["q"]}


def _lex(label):
    letters = [c for c in label if c.isalpha()]
    vowels = sum(c in "aeiou" for c in letters)
    run = best = 0
    for c in label:
        if c.isalpha() and c not in "aeiou":
            run += 1
            best = max(best, run)
        else:
            run = 0
    return {"length": len(label), "digit_ratio": round(sum(c.isdigit() for c in label) / max(1, len(label)), 3),
            "vowel_ratio": round(vowels / max(1, len(letters)), 3), "longest_consonant_run": best,
            "hyphens": label.count("-"), "entropy": round(entropy(label), 3)}


def _dga(label):
    lx = _lex(label)
    pts, why = 0, []
    if lx["length"] >= 12:
        pts += 15; why.append("long label")
    if lx["entropy"] > 3.5 and lx["length"] >= 10:
        pts += 25; why.append("high entropy")
    if lx["digit_ratio"] >= 0.3:
        pts += 20; why.append("many digits")
    if lx["vowel_ratio"] < 0.2 and lx["length"] >= 8:
        pts += 25; why.append("very few vowels")
    if lx["longest_consonant_run"] >= 5:
        pts += 20; why.append("long consonant run")
    return min(100, pts), why


@tool("DOM-001", "domain.validate", "Validate hostname syntax (RFC 1035/1123 limits) and return its punycode form.",
      "domain:str", "valid, reasons, ascii")
def dom_validate(p):
    d = p["domain"].strip().lower().rstrip(".")
    try:
        a = to_ascii_host(d) if d else ""
    except PhantomError:
        return {"valid": False, "reasons": ["cannot convert to punycode"], "ascii": ""}
    ok, why = valid_hostname(a)
    return {"valid": ok, "reasons": why, "ascii": a}


@tool("DOM-002", "domain.split", "Split a hostname into subdomain, second-level label, suffix and registrable domain (built-in suffix subset).",
      "domain:str", "subdomain, sld, suffix, registrable, note")
def dom_split(p):
    r = split_domain(p["domain"].strip().lower())
    r["note"] = "Uses a small built-in multi-part suffix list, not the full Public Suffix List."
    return r


@tool("DOM-003", "domain.idn_codec", "Convert a domain between Unicode and punycode and report scripts used.",
      "domain:str, mode:str=auto", "ascii, unicode, scripts, mixed_script")
def dom_idn(p):
    from .common import scripts_of
    d = p["domain"].strip().lower()
    mode = p["mode"]
    if mode not in ("auto", "to_ascii", "to_unicode"):
        raise PhantomError("bad_params", "mode must be auto, to_ascii or to_unicode")
    try:
        if mode == "to_unicode" or (mode == "auto" and "xn--" in d):
            uni, asc = d.encode("ascii").decode("idna"), d
        else:
            asc, uni = d.encode("idna").decode("ascii"), d
    except UnicodeError:
        raise PhantomError("bad_idn", "cannot convert domain")
    sc = scripts_of(uni)
    return {"ascii": asc, "unicode": uni, "scripts": sorted(sc), "mixed_script": len(sc) > 1}


@tool("DOM-004", "domain.dga_score", "Estimate whether the second-level label looks algorithmically generated (heuristic, 0-100).",
      "domain:str", "score, label, reasons, findings")
def dom_dga(p):
    sld = split_domain(p["domain"].lower())["sld"]
    s, why = _dga(sld)
    lab = "likely generated" if s >= 60 else "possibly generated" if s >= 35 else "looks human-chosen"
    fi = [F("medium" if s < 60 else "high", "DGA-like label: " + ", ".join(why))] if s >= 35 else []
    return {"score": s, "label": lab, "reasons": why, "findings": fi}


@tool("DOM-005", "domain.typosquat_variants", "Generate likely typosquat/lookalike variants of YOUR domain for defensive monitoring (no lookups performed).",
      "domain:str, limit:int=300", "variants, count, truncated")
def dom_typo(p):
    d = split_domain(p["domain"].strip().lower())
    if not d["sld"] or not d["suffix"]:
        raise PhantomError("bad_input", "need a domain with a suffix, e.g. example.com")
    s, suf, out = d["sld"], d["suffix"], set()
    for i in range(len(s)):
        out.add(s[:i] + s[i + 1:])                       # omission
        out.add(s[:i] + s[i] + s[i:])                    # duplication
        if i < len(s) - 1:
            out.add(s[:i] + s[i + 1] + s[i] + s[i + 2:])  # transposition
        for c in QWERTY.get(s[i], ""):
            out.add(s[:i] + c + s[i + 1:])               # adjacent key
        for g in HOMOGLYPH.get(s[i], []):
            out.add(s[:i] + g + s[i + 1:])               # homoglyph
        if 0 < i:
            out.add(s[:i] + "-" + s[i:])                 # hyphen insertion
    out = {v for v in out if v and v != s and not v.startswith("-") and not v.endswith("-")}
    res = sorted(v + "." + suf for v in out)
    for t in ("com", "net", "org", "co", "info", "xyz", "top", "id", "co.id"):
        if t != suf:
            res.append(s + "." + t)
    res.append("www" + s + "." + suf)
    res = sorted(set(res))
    lim = max(1, min(5000, p["limit"]))
    return {"variants": res[:lim], "count": len(res), "truncated": len(res) > lim}


@tool("DOM-006", "domain.similarity", "Compare two domains: edit distance, folded-skeleton equality, same label with different TLD.",
      "a:str, b:str", "edit_distance, similarity, skeleton_equal, same_label_other_tld, findings")
def dom_sim(p):
    a, b = split_domain(p["a"].lower()), split_domain(p["b"].lower())
    la, lb = a["sld"], b["sld"]
    dist = lev(la, lb)
    sim = round(1 - dist / max(1, len(la), len(lb)), 3)
    skeq = skeleton(la) == skeleton(lb) and la != lb
    same = la == lb and a["suffix"] != b["suffix"]
    fi = []
    if skeq:
        fi.append(F("high", "Labels are identical after confusable-character folding"))
    elif 0 < dist <= 2 and len(la) >= 5:
        fi.append(F("medium", "Labels differ by %d edit(s)" % dist))
    if same:
        fi.append(F("low", "Same label under a different suffix"))
    return {"edit_distance": dist, "similarity": sim, "skeleton_equal": skeq,
            "same_label_other_tld": same, "findings": fi}


@tool("DOM-007", "domain.tld_profile", "Classify the TLD (country-code, generic, sponsored) and note whether it is abuse-heavy.",
      "domain:str", "tld, type, abuse_heavy, findings")
def dom_tld(p):
    d = split_domain(p["domain"].lower())
    tld = d["suffix"].split(".")[-1]
    typ = "sponsored" if tld in CC_SPONSORED else "generic" if tld in GENERIC else \
          "country-code" if len(tld) == 2 else "new-generic"
    heavy = tld in RISKY_TLDS
    return {"tld": tld, "type": typ, "abuse_heavy": heavy,
            "findings": [F("low", "TLD frequently abused (.%s)" % tld)] if heavy else []}


_WHOIS_KEYS = {
    "registrar": ("registrar", "sponsoring registrar"),
    "created": ("creation date", "created", "created on", "registered on", "domain registration date"),
    "expires": ("registry expiry date", "expiry date", "expires", "expiration date", "registrar registration expiration date"),
    "updated": ("updated date", "last updated", "last-update", "last modified"),
}


def _date_loose(v):
    try:
        return parse_date(v)
    except PhantomError:
        return parse_date(v.split()[0])


@tool("DOM-008", "domain.whois_parse", "Parse raw WHOIS text you supply: registrar, dates, nameservers, status; flag newly registered or expiring domains.",
      "text:str, now:str=", "registrar, created, expires, updated, age_days, days_to_expiry, nameservers, status, privacy_proxy, findings")
def dom_whois(p):
    kv = {}
    ns, status = [], []
    for line in p["text"].splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip().lower(), v.strip()
        if not v:
            continue
        if k in ("name server", "nserver", "nameserver"):
            ns.append(v.split()[0].lower().rstrip("."))
        elif k in ("domain status", "status"):
            status.append(v.split()[0])
        else:
            kv.setdefault(k, v)
    out = {}
    for field, names in _WHOIS_KEYS.items():
        out[field] = next((kv[n] for n in names if n in kv), None)
    now = utcnow(p["now"] or None)
    age = left = None
    fi = []
    try:
        if out["created"]:
            age = (now - _date_loose(out["created"])).days
    except PhantomError:
        pass
    try:
        if out["expires"]:
            left = (_date_loose(out["expires"]) - now).days
    except PhantomError:
        pass
    if age is not None and age < 30:
        fi.append(F("high", "Domain registered %d days ago" % age, "", "fact"))
    elif age is not None and age < 180:
        fi.append(F("low", "Domain younger than 6 months (%d days)" % age, "", "fact"))
    if left is not None and left < 0:
        fi.append(F("high", "Registration expired %d days ago" % -left, "", "fact"))
    elif left is not None and left < 30:
        fi.append(F("medium", "Registration expires in %d days" % left, "", "fact"))
    priv = any(w in p["text"].lower() for w in ("redacted for privacy", "privacy protect", "whoisguard", "domains by proxy", "privacyguardian"))
    return {"registrar": out["registrar"], "created": out["created"], "expires": out["expires"],
            "updated": out["updated"], "age_days": age, "days_to_expiry": left,
            "nameservers": sorted(set(ns)), "status": status, "privacy_proxy": priv, "findings": fi}


@tool("DOM-009", "domain.lexical_profile", "Raw lexical features of the domain label: length, digits, vowels, consonant runs, hyphens, entropy.",
      "domain:str", "label, features, findings")
def dom_lex(p):
    sld = split_domain(p["domain"].lower())["sld"]
    lx = _lex(sld)
    fi = []
    if lx["hyphens"] >= 3:
        fi.append(F("low", "Three or more hyphens in the label"))
    if lx["digit_ratio"] > 0 and lx["digit_ratio"] < 1 and re.search(r"[a-z]\d+[a-z]", sld):
        fi.append(F("low", "Digits embedded between letters (possible lookalike)"))
    return {"label": sld, "features": lx, "findings": fi}


@tool("DOM-010", "domain.subdomain_extract", "Extract subdomains of a target domain from any text (logs, CT exports) and flag exposure-prone names.",
      "domain:str, text:str", "subdomains, count, interesting, findings")
def dom_subs(p):
    d = re.escape(p["domain"].strip().lower().rstrip("."))
    found = {m.group(0).lower() for m in re.finditer(r"(?<![a-z0-9.-])(?:[a-z0-9_*-]+\.)+" + d + r"(?![a-z0-9-])", p["text"].lower())}
    found.discard(p["domain"].strip().lower())
    inter = sorted(s for s in found if any(s.split(".")[0] == w or w in s.split(".")[0] for w in INTERESTING))
    fi = [F("info", "Exposure-prone subdomain name: " + s, "Review whether it should be public.", "fact") for s in inter[:20]]
    return {"subdomains": sorted(found), "count": len(found), "interesting": inter, "findings": fi}


@tool("DOM-011", "domain.disposable_check", "Check whether an email/domain belongs to a built-in list of disposable-mail providers.",
      "domain:str", "disposable, registrable, list_size, findings")
def dom_disp(p):
    d = p["domain"].strip().lower().split("@")[-1]
    reg = split_domain(d)["registrable"]
    hit = reg in DISPOSABLE or d in DISPOSABLE
    return {"disposable": hit, "registrable": reg, "list_size": len(DISPOSABLE),
            "findings": [F("medium", "Disposable email provider", reg, "fact")] if hit else []}


@tool("DOM-012", "domain.risk_score", "Combine syntax, DGA, lexical, TLD and brand-lookalike checks into a 0-100 domain risk score (heuristic).",
      "domain:str", "score, label, findings, disclaimer")
def dom_risk(p):
    d = p["domain"].strip().lower().rstrip(".")
    fi = []
    ok, why = valid_hostname(to_ascii_host(d)) if d else (False, ["empty"])
    if not ok:
        fi.append(F("medium", "Invalid hostname syntax", "; ".join(why), "fact"))
    sp = split_domain(d)
    s, w = _dga(sp["sld"])
    if s >= 35:
        fi.append(F("high" if s >= 60 else "medium", "DGA-like label: " + ", ".join(w)))
    if sp["suffix"].split(".")[-1] in RISKY_TLDS:
        fi.append(F("low", "Frequently abused TLD"))
    for b, official in BRANDS.items():
        if sp["registrable"] in official:
            continue
        if b in d.split(".")[:-1] or any(b in l for l in d.split(".")[:-1]):
            fi.append(F("high", "Contains brand '%s' on a non-official domain" % b))
        elif len(b) >= 5 and lev(sp["sld"], b) == 1:
            fi.append(F("high", "One edit away from brand '%s'" % b))
        elif skeleton(sp["sld"]) == b and sp["sld"] != b:
            fi.append(F("high", "Folds to brand '%s'" % b))
    s2, label = score(fi)
    return {"score": s2, "label": label, "findings": fi,
            "disclaimer": "Heuristic. No registry, reputation or WHOIS data was consulted."}
