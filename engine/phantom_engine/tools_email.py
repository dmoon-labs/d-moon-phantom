"""H. Email Security Analysis (8 tools). Offline, operate on text you supply."""
import email
import email.policy
import html.parser
import ipaddress
import re
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from urllib.parse import urlsplit

from .common import (BRANDS, F, KEYWORDS, PhantomError, SHORTENERS, decode_ip, parse_url,
                     split_domain, to_ascii_host, valid_hostname)
from .registry import tool
from .tools_domain import DISPOSABLE
from .tools_file import ext_findings
from .tools_url import url_phishing_score


def _msg(text):
    if not text.strip():
        raise PhantomError("bad_input", "empty message")
    return email.message_from_string(text[:4 * 1024 * 1024], policy=email.policy.default)


def _domain_of(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(" >") if "@" in addr else ""


@tool("EML-001", "email.address_validate", "Validate an email address (length limits, domain syntax, IDN) and flag disposable providers.",
      "address:str", "valid, local, domain, normalized, issues, findings")
def eml_addr(p):
    a = p["address"].strip()
    issues = []
    if a.count("@") != 1:
        return {"valid": False, "local": "", "domain": "", "normalized": "", "issues": ["must contain exactly one '@'"], "findings": []}
    local, dom = a.split("@")
    if not local or len(local) > 64:
        issues.append("local part empty or longer than 64 characters")
    if local.startswith(".") or local.endswith(".") or ".." in local:
        issues.append("misplaced dots in local part")
    if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+", local) and not re.fullmatch(r'"[^"\\]*"', local):
        issues.append("unsupported characters in local part")
    try:
        asc = to_ascii_host(dom.lower())
        ok, why = valid_hostname(asc)
        issues += why
    except PhantomError:
        asc = dom.lower()
        issues.append("domain cannot be converted to punycode")
    if "." not in asc:
        issues.append("domain has no dot")
    fi = []
    if split_domain(asc)["registrable"] in DISPOSABLE:
        fi.append(F("medium", "Disposable email provider", asc, "fact"))
    return {"valid": not issues, "local": local, "domain": dom, "normalized": local + "@" + asc,
            "issues": issues, "findings": fi}


@tool("EML-002", "email.header_parse", "Parse raw email headers: decoded From/To/Subject/Date, Message-ID, Return-Path, Reply-To, hop count; flag missing basics.",
      "raw:str", "from, to, subject, date, message_id, return_path, reply_to, received_count, auth_results, findings")
def eml_hdr(p):
    m = _msg(p["raw"])
    g = lambda k: str(m.get(k, "") or "")
    fi = []
    if not g("Message-ID"):
        fi.append(F("low", "No Message-ID header", "", "fact"))
    if not g("Date"):
        fi.append(F("low", "No Date header", "", "fact"))
    else:
        try:
            parsedate_to_datetime(g("Date"))
        except (TypeError, ValueError):
            fi.append(F("low", "Unparseable Date header", g("Date")[:40], "fact"))
    if not g("From"):
        fi.append(F("high", "No From header", "", "fact"))
    return {"from": g("From"), "to": g("To"), "subject": g("Subject"), "date": g("Date"),
            "message_id": g("Message-ID"), "return_path": g("Return-Path"), "reply_to": g("Reply-To"),
            "received_count": len(m.get_all("Received", [])), "auth_results": m.get_all("Authentication-Results", []),
            "findings": fi}


@tool("EML-003", "email.auth_results", "Parse Authentication-Results (spf/dkim/dmarc/arc) and flag failures or missing mechanisms.",
      "raw:str", "results, domains, findings")
def eml_auth(p):
    m = _msg(p["raw"])
    ar = " ".join(str(x) for x in m.get_all("Authentication-Results", [])) if m.get_all("Authentication-Results") else \
        (p["raw"] if re.search(r"\b(spf|dkim|dmarc)=", p["raw"]) else "")
    res = {}
    for k, v in re.findall(r"\b(spf|dkim|dmarc|arc)\s*=\s*(\w+)", ar, re.I):
        res.setdefault(k.lower(), []).append(v.lower())
    doms = sorted(set(re.findall(r"header\.(?:d|from|i)=([\w.@-]+)", ar)))
    fi = []
    if not ar:
        fi.append(F("medium", "No Authentication-Results header: sender authentication unknown", "", "fact"))
    for k in ("spf", "dkim", "dmarc"):
        vals = res.get(k)
        if ar and not vals:
            fi.append(F("low", "No %s result present" % k, "", "fact"))
        elif vals and not any(v == "pass" for v in vals):
            fi.append(F("high" if k == "dmarc" else "medium", "%s did not pass (%s)" % (k.upper(), ",".join(vals)), "", "fact"))
    return {"results": res, "domains": doms, "findings": fi}


@tool("EML-004", "email.received_chain", "Analyze Received headers: hops, per-hop delay, out-of-order timestamps, long delays, hop count.",
      "raw:str", "hops, total_delay_seconds, findings")
def eml_recv(p):
    m = _msg(p["raw"])
    recs = m.get_all("Received", [])
    hops, fi, times = [], [], []
    for r in reversed(recs):              # oldest first
        r = " ".join(str(r).split())
        ts = None
        if ";" in r:
            try:
                ts = parsedate_to_datetime(r.rsplit(";", 1)[1].strip())
            except (TypeError, ValueError):
                ts = None
        ip = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39})\]", r)
        fr = re.search(r"from\s+(\S+)", r, re.I)
        by = re.search(r"\bby\s+(\S+)", r, re.I)
        hops.append({"from": fr.group(1) if fr else None, "by": by.group(1) if by else None,
                     "ip": ip.group(1) if ip else None, "time": ts.isoformat() if ts else None})
        times.append(ts)
    delay = 0
    prev = None
    for i, t in enumerate(times):
        if t and prev:
            d = (t - prev).total_seconds()
            hops[i]["delay_seconds"] = int(d)
            delay += max(0, d)
            if d < -300:
                fi.append(F("medium", "Hop %d timestamp precedes previous hop by %d s" % (i + 1, -d), "Clock skew or forged header.", "fact"))
            elif d > 3600:
                fi.append(F("low", "Hop %d delayed %d minutes" % (i + 1, d // 60), "", "fact"))
        if t:
            prev = t
    if len(recs) > 12:
        fi.append(F("low", "Unusually many hops (%d)" % len(recs), "", "fact"))
    if not recs:
        fi.append(F("info", "No Received headers (locally generated or stripped)", "", "fact"))
    return {"hops": hops, "total_delay_seconds": int(delay), "findings": fi}


@tool("EML-005", "email.sender_mismatch", "Compare From, Return-Path and Reply-To domains and check display names that impersonate a brand or another address.",
      "raw:str", "from_address, from_domain, return_path_domain, reply_to_domain, display_name, findings")
def eml_mismatch(p):
    m = _msg(p["raw"])
    name, addr = parseaddr(str(m.get("From", "")))
    fd = _domain_of(addr)
    rp = _domain_of(parseaddr(str(m.get("Return-Path", "")))[1])
    rt = _domain_of(parseaddr(str(m.get("Reply-To", "")))[1])
    fi = []
    reg = lambda d: split_domain(d)["registrable"]
    if rp and fd and reg(rp) != reg(fd):
        fi.append(F("medium", "Return-Path domain (%s) differs from From domain (%s)" % (rp, fd), "Normal for mailing services; suspicious otherwise.", "heuristic"))
    if rt and fd and reg(rt) != reg(fd):
        fi.append(F("high", "Reply-To domain (%s) differs from From domain (%s)" % (rt, fd), "Replies would go elsewhere.", "heuristic"))
    if "@" in name and _domain_of(name.strip()) != fd:
        fi.append(F("high", "Display name contains a different email address", name[:60], "fact"))
    lname = name.lower()
    for b, official in BRANDS.items():
        if b in lname and fd and reg(fd) not in official:
            fi.append(F("high", "Display name mentions '%s' but sender domain is %s" % (b, fd), "", "heuristic"))
            break
    return {"from_address": addr, "from_domain": fd, "return_path_domain": rp, "reply_to_domain": rt,
            "display_name": name, "findings": fi}


class _Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href"), []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


@tool("EML-006", "email.link_analyze", "Extract links from an HTML/text email body, compare visible text with the real target, and score each URL (never visited).",
      "body:str", "links, findings")
def eml_links(p):
    lp = _Links()
    lp.feed(p["body"][:2 * 1024 * 1024])
    pairs = lp.links[:300]
    for u in re.findall(r"https?://[^\s<>\"']+", p["body"][:2 * 1024 * 1024])[:300]:
        if not any(u == h for h, _ in pairs):
            pairs.append((u, ""))
    out, fi = [], []
    for href, text in pairs:
        try:
            u = parse_url(href)
        except PhantomError:
            if href.lower().startswith(("javascript:", "data:")):
                fi.append(F("critical", "Link uses a script/data scheme", href[:60], "fact"))
            continue
        env = url_phishing_score({"url": href})
        out.append({"href": href[:200], "text": text[:80], "host": u["host"], "score": env["score"]})
        shown = re.search(r"((?:[a-z0-9-]+\.)+[a-z]{2,})", text.lower())
        if shown and split_domain(shown.group(1))["registrable"] != split_domain(u["host"])["registrable"]:
            fi.append(F("high", "Link text shows %s but goes to %s" % (shown.group(1), u["host"]), "", "fact"))
        if decode_ip(u["host"]):
            fi.append(F("medium", "Link points to a raw IP address", u["host"], "fact"))
        if u["host"] in SHORTENERS:
            fi.append(F("medium", "Link uses a URL shortener", u["host"], "fact"))
        if env["score"] >= 55:
            fi.append(F("high", "High-scoring URL in body (%d)" % env["score"], href[:80], "heuristic"))
    return {"links": out, "findings": fi}


@tool("EML-007", "email.attachment_risk", "Rate attachment file names (and optional content types) for dangerous extensions, double extensions and macro formats.",
      "filenames:list, content_types:list=", "attachments, findings")
def eml_attach(p):
    out, fi = [], []
    for i, n in enumerate(p["filenames"][:200]):
        n = str(n)
        f, ext = ext_findings(n)
        ct = str(p["content_types"][i]) if i < len(p["content_types"]) else ""
        if ct and ext in ("exe", "scr", "js", "vbs", "bat") and not ct.startswith("application/"):
            f.append(F("medium", "Content-Type %s does not match executable name" % ct, "", "fact"))
        worst = max((x["severity"] for x in f), key=lambda s: ["info", "low", "medium", "high", "critical"].index(s), default="info")
        out.append({"filename": n[:120], "extension": ext, "risk": worst})
        fi += [dict(x, title="%s: %s" % (n[:40], x["title"])) for x in f]
    return {"attachments": out, "findings": fi}


URGENCY = ("urgent", "immediately", "within 24 hours", "act now", "final notice", "suspended",
           "verify your account", "confirm your identity", "unusual activity", "password expires",
           "segera", "dalam 24 jam", "akun anda diblokir", "verifikasi akun", "hadiah", "selamat anda menang")
MONEY = ("wire transfer", "gift card", "bitcoin", "payment failed", "invoice attached", "refund", "transfer dana", "pulsa")


@tool("EML-008", "email.content_score", "Score email text for phishing language: urgency, credential requests, payment pressure, shouting, generic greeting (English + Indonesian).",
      "subject:str=, body:str", "score, label, signals, findings")
def eml_content(p):
    t = (p["subject"] + "\n" + p["body"]).lower()
    sig, pts = [], 0
    u = [k for k in URGENCY if k in t]
    if u:
        pts += min(30, 10 * len(u)); sig.append("urgency: " + ", ".join(u[:4]))
    mo = [k for k in MONEY if k in t]
    if mo:
        pts += min(25, 10 * len(mo)); sig.append("payment pressure: " + ", ".join(mo[:3]))
    kw = [k for k in ("password", "pin", "otp", "kata sandi", "login", "credential") if k in t]
    if kw:
        pts += min(25, 10 * len(kw)); sig.append("credential words: " + ", ".join(kw[:3]))
    if re.search(r"dear (customer|user|client|member)|yth\.? (pelanggan|nasabah)", t):
        pts += 10; sig.append("generic greeting")
    letters = [c for c in p["subject"] if c.isalpha()]
    if len(letters) > 8 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
        pts += 10; sig.append("shouting subject")
    if p["body"].count("!") >= 4:
        pts += 5; sig.append("many exclamation marks")
    s = min(100, pts)
    label = "low" if s < 20 else "medium" if s < 45 else "high"
    return {"score": s, "label": label, "signals": sig,
            "findings": [F("high" if s >= 45 else "medium" if s >= 20 else "info", "Phishing-style language: " + "; ".join(sig[:3]), "Language heuristics only.", "heuristic")] if sig else []}
