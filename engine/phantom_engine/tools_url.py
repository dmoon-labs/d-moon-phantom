"""A. URL & Phishing Intelligence (15 tools). No tool here touches the network;
suspicious URLs are never visited."""
import re
from urllib.parse import parse_qsl, unquote

from .common import (BRANDS, DEFAULT_PORTS, F, KEYWORDS, PhantomError, RISKY_TLDS,
                     SHORTENERS, decode_ip, entropy, host_forms, lev, norm_pct,
                     parse_url, remove_dot_segments, score, scripts_of, skeleton,
                     split_domain, to_ascii_host)
from .registry import tool

REDIRECT_KEYS = {"url", "redirect", "redirect_uri", "redirect_url", "next", "return",
                 "returnurl", "return_to", "goto", "dest", "destination", "continue",
                 "target", "redir", "link", "u"}


# ------------------------------------------------------------ check functions
def c_shortener(u):
    h = host_forms(u)
    if u["host"] in SHORTENERS or h["registrable"] in SHORTENERS:
        return [F("medium", "Known URL shortener",
                  "The final destination is hidden. PHANTOM does not resolve it automatically.")]
    return []


def c_tld(u):
    h = host_forms(u)
    if h["is_ip"]:
        return []
    tld = h["suffix"].split(".")[-1]
    if tld in RISKY_TLDS:
        return [F("low", "TLD frequently abused (.%s)" % tld,
                  "Many legitimate sites use it too; weak signal on its own.")]
    return []


def c_iphost(u):
    d = decode_ip(u["host"])
    if not d:
        return []
    out = [F("medium", "IP address used instead of a domain name", d[0])]
    if d[1] == "obfuscated":
        out.append(F("high", "Obfuscated IP notation (decimal/hex/octal)",
                     "%s decodes to %s" % (u["host"], d[0]), "fact"))
    return out


def c_userinfo(u):
    ui = u["userinfo"]
    if not ui:
        return []
    sev = "high" if re.search(r"[a-z0-9-]+\.[a-z]{2,}", ui.lower()) else "medium"
    return [F(sev, "Credentials/userinfo before '@' in the URL",
              "Real host is %r, not what appears before the '@'." % u["host"])]


def c_idn(u):
    if decode_ip(u["host"]):
        return []
    out = []
    host = u["host"]
    uni = host
    if "xn--" in host:
        try:
            uni = host.encode("ascii").decode("idna")
            out.append(F("info", "Punycode host", "Decodes to %r" % uni, "fact"))
        except UnicodeError:
            out.append(F("medium", "Malformed punycode label"))
    scr = scripts_of(uni)
    if len(scr) > 1:
        out.append(F("high", "Mixed scripts in hostname: " + ", ".join(sorted(scr)),
                     "Classic homograph technique.", "fact"))
    elif scr - {"LATIN"} and re.search(r"[^\x00-\x7f]", uni):
        out.append(F("medium", "Non-Latin lookalike-capable hostname", ", ".join(sorted(scr))))
    sk = skeleton(split_domain(uni)["sld"])
    for b in BRANDS:
        if sk == b and split_domain(uni)["sld"] != b:
            out.append(F("high", "Hostname visually equals brand '%s'" % b,
                         "After confusable-character folding."))
    return out


def c_brand(u):
    h = host_forms(u)
    if h["is_ip"]:
        return []
    out, labels = [], u["host"].split(".")
    for brand, official in BRANDS.items():
        if h["registrable"] in official:
            continue
        sk_sld = skeleton(h["sld"])
        if any(brand in l for l in labels[:-1]):
            out.append(F("high", "Brand '%s' in hostname but domain is not official" % brand,
                         "Registrable domain: %s" % h["registrable"]))
        elif any(brand in skeleton(l) for l in labels[:-1]):
            out.append(F("high", "Lookalike of brand '%s' inside the hostname" % brand,
                         "Registrable domain: %s" % h["registrable"]))
        elif sk_sld == brand:
            out.append(F("high", "Lookalike of brand '%s' after character folding" % brand))
        elif len(brand) >= 5 and 0 < lev(h["sld"], brand) <= 1:
            out.append(F("high", "One edit away from brand '%s' (typosquat)" % brand))
        elif len(brand) >= 6 and lev(h["sld"], brand) == 2:
            out.append(F("medium", "Two edits from brand '%s'" % brand))
        elif brand in unquote(u["path"]).lower() and not h["registrable"] in official:
            out.append(F("low", "Brand '%s' appears in the path of an unrelated domain" % brand))
    return out


def c_keywords(u):
    text = (u["host"] + " " + unquote(u["path"]) + " " + unquote(u["query"])).lower()
    hits = sorted({k for k in KEYWORDS if k in text})
    if len(hits) >= 3:
        return [F("high", "Many credential/urgency keywords", ", ".join(hits))]
    if len(hits) == 2:
        return [F("medium", "Credential/urgency keywords", ", ".join(hits))]
    if len(hits) == 1:
        return [F("low", "Keyword commonly used in phishing: " + hits[0])]
    return []


def c_length(u):
    out = []
    n = len(u["raw"])
    if n > 150:
        out.append(F("medium", "Very long URL (%d chars)" % n))
    elif n > 75:
        out.append(F("low", "Long URL (%d chars)" % n))
    h = u["host"]
    if not decode_ip(h) and len(h) >= 12 and entropy(h.split(".")[0]) > 3.7:
        out.append(F("medium", "High-entropy hostname label (random-looking)",
                     "entropy=%.2f" % entropy(h.split(".")[0])))
    return out


def c_structure(u):
    out = []
    h = host_forms(u)
    if not h["is_ip"]:
        depth = len(h["subdomain"].split(".")) if h["subdomain"] else 0
        if depth >= 4:
            out.append(F("medium", "Deep subdomain nesting (%d levels)" % depth))
        elif depth == 3:
            out.append(F("low", "Several subdomain levels (%d)" % depth))
        if u["host"].count("-") >= 3:
            out.append(F("low", "Many hyphens in hostname"))
    if u["scheme"] not in ("http", "https"):
        out.append(F("medium", "Unusual scheme: " + u["scheme"]))
    elif u["scheme"] == "http":
        out.append(F("low", "Not HTTPS" + (" (scheme was assumed)" if u["assumed_scheme"] else "")))
    if u["port"] and u["port"] != DEFAULT_PORTS.get(u["scheme"]):
        out.append(F("low", "Non-standard port %d" % u["port"]))
    return out


def c_redirect(u):
    out = []
    for k, v in parse_qsl(u["query"], keep_blank_values=True):
        if k.lower() in REDIRECT_KEYS and re.match(r"^(https?:)?//", v, re.I):
            try:
                t = parse_url(v)
                same = split_domain(t["host"])["registrable"] == host_forms(u)["registrable"]
            except PhantomError:
                same = False
            out.append(F("low" if same else "medium", "Redirect parameter '%s' carries a URL" % k,
                         "Target host: %s" % v[:80]))
    return out


def c_encoding(u):
    out = []
    raw = u["raw"]
    if re.search(r"%25[0-9a-fA-F]{2}", raw):
        out.append(F("medium", "Double percent-encoding", "", "fact"))
    if re.search(r"%2e%2e|%2f|%5c", u["path"], re.I):
        out.append(F("medium", "Encoded traversal/separator characters in path"))
    if "%" in u["host"] or re.search(r"[\x00-\x1f\x7f]", raw):
        out.append(F("high", "Encoded or control characters in host/URL"))
    if u["backslash"]:
        out.append(F("medium", "Backslash in URL (browsers treat it as '/')"))
    pct = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    if pct > 10:
        out.append(F("low", "Heavy percent-encoding (%d sequences)" % pct))
    return out


CHECKS = [c_shortener, c_tld, c_iphost, c_userinfo, c_idn, c_brand, c_keywords,
          c_length, c_structure, c_redirect, c_encoding]


def _u(p):
    return parse_url(p["url"])


# ------------------------------------------------------------ tools
@tool("URL-001", "url.normalize", "Normalize a URL: lowercase host, punycode, default ports, dot segments, percent-encoding case.",
      "url:str, strip_fragment:bool=true", "normalized, host, changes")
def url_normalize(p):
    u = _u(p)
    changes = []
    host = u["host"]
    if re.search(r"[^\x00-\x7f]", host):
        host = to_ascii_host(host)
        changes.append("host converted to punycode")
    port = u["port"]
    if port == DEFAULT_PORTS.get(u["scheme"]):
        port = None
        changes.append("default port removed")
    path = remove_dot_segments(norm_pct(u["path"])) or "/"
    if path != (u["path"] or "/"):
        changes.append("path normalized")
    q = norm_pct(u["query"])
    frag = "" if p["strip_fragment"] else u["fragment"]
    if p["strip_fragment"] and u["fragment"]:
        changes.append("fragment removed")
    if u["assumed_scheme"]:
        changes.append("scheme assumed http")
    hp = ("[%s]" % host if ":" in host else host) + (":%d" % port if port else "")
    s = "%s://%s%s%s%s%s" % (u["scheme"], (u["userinfo"] + "@") if u["userinfo"] else "",
                             hp, path, ("?" + q) if q else "", ("#" + frag) if frag else "")
    return {"normalized": s, "host": host, "changes": changes}


@tool("URL-002", "url.parse_components", "Split a URL into scheme, userinfo, host parts, port, path, query pairs and fragment.",
      "url:str", "scheme, host, registrable_domain, subdomain, tld, is_ip, port, path, query_params, fragment, userinfo")
def url_parse(p):
    u = _u(p)
    h = host_forms(u)
    return {"scheme": u["scheme"], "userinfo": u["userinfo"], "host": u["host"],
            "registrable_domain": h["registrable"], "subdomain": h["subdomain"],
            "tld": h["suffix"], "is_ip": h["is_ip"], "port": u["port"], "path": u["path"],
            "query_params": [list(x) for x in parse_qsl(u["query"], keep_blank_values=True)],
            "fragment": u["fragment"]}


def _single(check, extra=None):
    def f(p):
        u = _u(p)
        fi = check(u)
        r = {"findings": fi, "flagged": bool(fi)}
        if extra:
            r.update(extra(u))
        return r
    return f


tool("URL-003", "url.shortener_detect", "Detect known URL-shortener hosts (destination is NOT resolved).",
     "url:str", "flagged, findings")(_single(c_shortener))
tool("URL-004", "url.suspicious_tld", "Flag top-level domains frequently abused in phishing (weak signal).",
     "url:str", "flagged, findings, tld")(_single(c_tld, lambda u: {"tld": host_forms(u)["suffix"]}))
tool("URL-005", "url.ip_host_detect", "Detect IP-literal hosts and decimal/hex/octal obfuscated IPs and decode them.",
     "url:str", "flagged, findings, decoded_ip")(_single(c_iphost, lambda u: {"decoded_ip": (decode_ip(u["host"]) or [None])[0]}))
tool("URL-006", "url.userinfo_trick", "Detect 'trusted.com@evil.com' style userinfo deception.",
     "url:str", "flagged, findings, real_host")(_single(c_userinfo, lambda u: {"real_host": u["host"]}))
tool("URL-007", "url.idn_homograph", "Detect punycode, mixed-script and brand-lookalike (homograph) hostnames.",
     "url:str", "flagged, findings, scripts")(_single(c_idn, lambda u: {"scripts": sorted(scripts_of(u["host"]))}))
tool("URL-008", "url.brand_impersonation", "Detect brand names or one/two-edit typosquats on non-official domains (built-in brand list).",
     "url:str", "flagged, findings, registrable_domain")(_single(c_brand, lambda u: {"registrable_domain": host_forms(u)["registrable"]}))
tool("URL-009", "url.keyword_score", "Count credential/urgency keywords (English and Indonesian) in host, path and query.",
     "url:str", "flagged, findings, keywords")(_single(c_keywords, lambda u: {"keywords": sorted({k for k in KEYWORDS if k in (u["host"] + unquote(u["path"] + u["query"])).lower()})}))
tool("URL-010", "url.length_entropy", "Measure URL length and hostname randomness (Shannon entropy).",
     "url:str", "flagged, findings, length, host_entropy")(_single(c_length, lambda u: {"length": len(u["raw"]), "host_entropy": round(entropy(u["host"].split(".")[0]), 3)}))
tool("URL-011", "url.structure_check", "Check scheme, port, subdomain depth and hyphen patterns.",
     "url:str", "flagged, findings, scheme, port")(_single(c_structure, lambda u: {"scheme": u["scheme"], "port": u["port"]}))
tool("URL-012", "url.redirect_params", "Find query parameters that embed another URL (open-redirect/phishing relay pattern).",
     "url:str", "flagged, findings")(_single(c_redirect))
tool("URL-013", "url.encoding_obfuscation", "Detect double encoding, encoded separators, control characters and backslash tricks.",
     "url:str", "flagged, findings")(_single(c_encoding))


@tool("URL-014", "url.phishing_score", "Aggregate all URL heuristics into one 0-100 phishing-likelihood score. Heuristic only; not verified intelligence.",
      "url:str", "score, label, findings, disclaimer")
def url_phishing_score(p):
    try:
        u = _u(p)
    except PhantomError as e:
        if e.code == "opaque_scheme":
            fi = [F("critical", "Script/data/file scheme instead of a web URL", e.message, "fact")]
            s, label = score(fi)
            return {"score": s, "label": label, "findings": fi, "disclaimer": DISCLAIMER}
        raise
    fi = []
    for c in CHECKS:
        fi += c(u)
    s, label = score(fi)
    return {"score": s, "label": label, "findings": fi, "disclaimer": DISCLAIMER}


DISCLAIMER = ("Heuristic assessment from the URL text only. It is not a verdict from "
              "threat-intelligence sources and the page was not visited.")


@tool("URL-015", "url.batch_triage", "Rank a list of URLs by phishing score (max 500) so the riskiest are reviewed first.",
      "urls:list, min_score:int=0", "ranked, total, failed")
def url_batch(p):
    urls = p["urls"][:500]
    ranked, failed = [], []
    for raw in urls:
        if not isinstance(raw, str):
            failed.append({"url": str(raw)[:80], "error": "not a string"})
            continue
        env = url_phishing_score({"url": raw})if _ok(raw) else None
        if env is None:
            failed.append({"url": raw[:120], "error": "unparseable URL"})
            continue
        if env["score"] >= p["min_score"]:
            ranked.append({"url": raw[:200], "score": env["score"], "label": env["label"],
                           "top_findings": [f["title"] for f in env["findings"][:3]]})
    ranked.sort(key=lambda r: -r["score"])
    return {"ranked": ranked, "total": len(urls), "failed": failed}


def _ok(raw):
    try:
        parse_url(raw)
        return True
    except PhantomError as e:
        return e.code == "opaque_scheme"
