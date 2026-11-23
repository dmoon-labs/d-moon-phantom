"""E. HTTP Security Analysis (12 tools). Analysis tools work on header text you
provide (offline). Only HTP-012 touches the network."""
import http.client
import re
import ssl
import time

from .common import (F, PhantomError, hv, net_timeout, parse_headers, parse_url,
                     rate_limit, score)
from .registry import tool

UA = "D-MOON-PHANTOM/1.0 (authorized defensive assessment)"


def _directives(v):
    out = {}
    for part in v.split(";"):
        part = part.strip()
        if part:
            bits = part.split()
            out[bits[0].lower()] = bits[1:]
    return out


def k_hsts(h, https=True):
    v = hv(h, "strict-transport-security")
    if not v:
        return [F("medium" if https else "info", "Missing Strict-Transport-Security",
                  "" if https else "Only meaningful over HTTPS.", "fact")]
    fi = []
    m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if not m:
        fi.append(F("high", "HSTS without max-age", v, "fact"))
    elif age == 0:
        fi.append(F("high", "HSTS max-age=0 disables the policy", v, "fact"))
    elif age < 15552000:
        fi.append(F("low", "HSTS max-age under 180 days (%d s)" % age, v, "fact"))
    if "includesubdomains" not in v.lower():
        fi.append(F("low", "HSTS lacks includeSubDomains", v, "fact"))
    if "preload" in v.lower() and (age < 31536000 or "includesubdomains" not in v.lower()):
        fi.append(F("low", "preload requires max-age>=31536000 and includeSubDomains", v, "fact"))
    return fi


def k_csp(h):
    v = hv(h, "content-security-policy")
    ro = hv(h, "content-security-policy-report-only")
    if not v:
        return [F("medium", "Missing Content-Security-Policy",
                  "A report-only policy is present but not enforced." if ro else "", "fact")]
    d = _directives(v)
    fi = []
    script = d.get("script-src", d.get("default-src"))
    strict = script is not None and any(x.startswith(("'nonce-", "'sha")) for x in script) and "'strict-dynamic'" in script
    if script is None:
        fi.append(F("medium", "CSP has neither script-src nor default-src", v[:80], "fact"))
    else:
        if "'unsafe-inline'" in script:
            fi.append(F("info" if strict else "high", "script-src allows 'unsafe-inline'" + (" (neutralized by nonce+strict-dynamic)" if strict else ""), "", "fact"))
        if "'unsafe-eval'" in script:
            fi.append(F("medium", "script-src allows 'unsafe-eval'", "", "fact"))
        if "*" in script or "http:" in script or "data:" in script:
            fi.append(F("high", "script-src allows wildcard/http:/data: sources", " ".join(script), "fact"))
    if "object-src" not in d and not (d.get("default-src") and "'none'" in d["default-src"]):
        fi.append(F("low", "No object-src 'none'", "", "fact"))
    if "base-uri" not in d:
        fi.append(F("low", "No base-uri directive", "", "fact"))
    if "frame-ancestors" not in d:
        fi.append(F("low", "No frame-ancestors directive", "", "fact"))
    return fi


def k_frame(h):
    xfo = (hv(h, "x-frame-options") or "").upper()
    csp = _directives(hv(h, "content-security-policy") or "")
    if "frame-ancestors" in csp:
        return []
    if not xfo:
        return [F("medium", "No clickjacking protection (X-Frame-Options / frame-ancestors)", "", "fact")]
    if xfo.startswith("ALLOW-FROM"):
        return [F("low", "X-Frame-Options ALLOW-FROM is obsolete", xfo, "fact")]
    if xfo not in ("DENY", "SAMEORIGIN"):
        return [F("medium", "Invalid X-Frame-Options value", xfo, "fact")]
    return []


def k_ctype(h):
    fi = []
    if (hv(h, "x-content-type-options") or "").lower() != "nosniff":
        fi.append(F("low", "Missing X-Content-Type-Options: nosniff", "", "fact"))
    ct = hv(h, "content-type")
    if not ct:
        fi.append(F("low", "Missing Content-Type", "", "fact"))
    elif ct.lower().startswith("text/") and "charset" not in ct.lower():
        fi.append(F("low", "Text content type without charset", ct, "fact"))
    return fi


def k_referrer(h):
    v = hv(h, "referrer-policy")
    if not v:
        return [F("low", "Missing Referrer-Policy", "", "fact")]
    last = v.split(",")[-1].strip().lower()
    if last in ("unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"):
        return [F("medium", "Referrer-Policy leaks full URL cross-origin: " + last, "", "fact")]
    return []


def k_perm(h):
    v = hv(h, "permissions-policy")
    if not v:
        extra = " (legacy Feature-Policy present)" if hv(h, "feature-policy") else ""
        return [F("low", "Missing Permissions-Policy" + extra, "", "fact")]
    fi = []
    for feat in ("camera", "microphone", "geolocation", "payment"):
        if re.search(r"\b%s\s*=\s*\(?\s*\*" % feat, v):
            fi.append(F("medium", "Permissions-Policy grants %s to every origin" % feat, "", "fact"))
    return fi


def k_cookies(h):
    fi = []
    for c in h.get("set-cookie", []):
        parts = [x.strip() for x in c.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = {x.split("=", 1)[0].lower(): (x.split("=", 1)[1] if "=" in x else "") for x in parts[1:]}
        t = "cookie '%s'" % name[:24]
        if "secure" not in attrs:
            fi.append(F("medium", t + " lacks Secure", "", "fact"))
        if "httponly" not in attrs:
            fi.append(F("medium" if re.search(r"sess|auth|token|sid|jwt", name, re.I) else "low", t + " lacks HttpOnly", "", "fact"))
        ss = attrs.get("samesite", "").lower()
        if not ss:
            fi.append(F("low", t + " has no SameSite (browser default applies)", "", "fact"))
        elif ss == "none" and "secure" not in attrs:
            fi.append(F("high", t + " SameSite=None without Secure is rejected/unsafe", "", "fact"))
        if name.startswith("__Host-") and (("domain" in attrs) or attrs.get("path") != "/" or "secure" not in attrs):
            fi.append(F("medium", t + " violates __Host- prefix rules", "", "fact"))
        if name.startswith("__Secure-") and "secure" not in attrs:
            fi.append(F("medium", t + " violates __Secure- prefix rules", "", "fact"))
        m = re.search(r"max-age=(\d+)", c, re.I)
        if m and int(m.group(1)) > 365 * 86400 * 2:
            fi.append(F("low", t + " lives longer than 2 years", "", "fact"))
    return fi


def k_cors(h, origin=""):
    acao = hv(h, "access-control-allow-origin")
    if acao is None:
        return []
    cred = (hv(h, "access-control-allow-credentials") or "").lower() == "true"
    fi = []
    if acao == "*" and cred:
        fi.append(F("high", "ACAO '*' with Allow-Credentials: true (invalid and dangerous intent)", "", "fact"))
    elif acao == "*":
        fi.append(F("info", "ACAO '*': any origin can read non-credentialed responses", "", "fact"))
    if acao.lower() == "null":
        fi.append(F("high", "ACAO 'null' is exploitable from sandboxed iframes/data: URLs", "", "fact"))
    if origin and acao == origin and cred:
        fi.append(F("medium", "Origin reflected with credentials allowed",
                    "Confirm the server validates origins against an allowlist.", "heuristic"))
    if acao not in ("*", "null") and "origin" not in (hv(h, "vary") or "").lower():
        fi.append(F("low", "Specific ACAO without 'Vary: Origin' can poison caches", "", "fact"))
    return fi


def k_disclose(h):
    fi = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                 "x-generator", "x-runtime", "x-drupal-cache", "x-debug-token", "x-backend-server"):
        v = hv(h, name)
        if not v:
            continue
        if re.search(r"\d+\.\d+", v):
            fi.append(F("low", "%s discloses a version: %s" % (name, v[:40]), "", "fact"))
        elif name in ("x-debug-token", "x-backend-server"):
            fi.append(F("medium", "Debug/backend header exposed: " + name, "", "fact"))
        elif name not in ("server",):
            fi.append(F("info", "Technology disclosure header: %s: %s" % (name, v[:30]), "", "fact"))
    return fi


def k_cache(h, sensitive=False):
    cc = (hv(h, "cache-control") or "").lower()
    fi = []
    if sensitive and "no-store" not in cc:
        fi.append(F("high", "Sensitive response is cacheable (no 'no-store')", cc or "no Cache-Control", "fact"))
    if h.get("set-cookie") and "public" in cc:
        fi.append(F("high", "Response sets a cookie yet is Cache-Control: public", "", "fact"))
    if not cc and not hv(h, "expires") and not hv(h, "pragma"):
        fi.append(F("low", "No caching directives at all", "", "fact"))
    return fi


def _hdr_tool(tid, name, desc, fn, extra_inputs="", outs="findings"):
    spec = "headers:str" + (", " + extra_inputs if extra_inputs else "")

    def run(p):
        return {"findings": fn(parse_headers(p["headers"]), p)}
    tool(tid, name, desc, spec, outs)(run)


@tool("HTP-001", "http.headers_audit", "Audit all security headers of a response (HSTS, CSP, framing, nosniff, referrer, permissions, cookies, CORS, disclosure, cache) and grade A-F.",
      "headers:str, https:bool=true, sensitive:bool=false, origin:str=", "grade, score, findings, headers_seen")
def htp_audit(p):
    h = parse_headers(p["headers"])
    if not h:
        raise PhantomError("bad_input", "no headers could be parsed")
    fi = (k_hsts(h, p["https"]) + k_csp(h) + k_frame(h) + k_ctype(h) + k_referrer(h) +
          k_perm(h) + k_cookies(h) + k_cors(h, p["origin"]) + k_disclose(h) + k_cache(h, p["sensitive"]))
    s, _ = score(fi)
    grade = "A" if s < 10 else "B" if s < 25 else "C" if s < 45 else "D" if s < 70 else "F"
    return {"grade": grade, "score": s, "findings": fi, "headers_seen": sorted(h)}


_hdr_tool("HTP-002", "http.hsts_check", "Check Strict-Transport-Security max-age, includeSubDomains and preload eligibility.",
          lambda h, p: k_hsts(h, p["https"]), "https:bool=true")
_hdr_tool("HTP-003", "http.csp_analyze", "Analyze Content-Security-Policy for unsafe-inline/eval, wildcards and missing base-uri/object-src/frame-ancestors.",
          lambda h, p: k_csp(h))
_hdr_tool("HTP-004", "http.framing_check", "Check clickjacking protection via X-Frame-Options and CSP frame-ancestors.",
          lambda h, p: k_frame(h))
_hdr_tool("HTP-005", "http.content_type_check", "Check X-Content-Type-Options nosniff and Content-Type/charset.",
          lambda h, p: k_ctype(h))
_hdr_tool("HTP-006", "http.referrer_policy_check", "Evaluate the Referrer-Policy value for URL leakage.",
          lambda h, p: k_referrer(h))
_hdr_tool("HTP-007", "http.permissions_policy_check", "Check Permissions-Policy presence and over-broad feature grants.",
          lambda h, p: k_perm(h))
_hdr_tool("HTP-008", "http.cookie_audit", "Audit every Set-Cookie: Secure, HttpOnly, SameSite, __Host-/__Secure- rules, lifetime.",
          lambda h, p: k_cookies(h))
_hdr_tool("HTP-009", "http.cors_check", "Check CORS headers for wildcard+credentials, null origin, reflected origin and missing Vary.",
          lambda h, p: k_cors(h, p["origin"]), "origin:str=")
_hdr_tool("HTP-010", "http.disclosure_check", "Find version/technology disclosure and debug headers (Server, X-Powered-By, ...).",
          lambda h, p: k_disclose(h))
_hdr_tool("HTP-011", "http.cache_check", "Check Cache-Control for sensitive responses and cookie+public combinations.",
          lambda h, p: k_cache(h, p["sensitive"]), "sensitive:bool=false")


@tool("HTP-012", "http.fetch", "Fetch response headers (HEAD by default) with optional bounded redirect following. Network tool: authorized=true.",
      "url:str, method:str=HEAD, follow:bool=false, max_redirects:int=3, timeout:int=5, verify_tls:bool=true, max_body:int=0",
      "status, final_url, headers_text, chain, body_bytes_read, tls_verified", "network")
def htp_fetch(p):
    if p["method"].upper() not in ("HEAD", "GET"):
        raise PhantomError("bad_params", "method must be HEAD or GET")
    method, t = p["method"].upper(), net_timeout(p)
    max_body = max(0, min(65536, p["max_body"])) if method == "GET" else 0
    url, chain = p["url"], []
    for _ in range(max(0, min(5, p["max_redirects"])) + 1):
        u = parse_url(url)
        if u["scheme"] not in ("http", "https"):
            raise PhantomError("bad_url", "only http/https can be fetched")
        port = u["port"] or (443 if u["scheme"] == "https" else 80)
        rate_limit()
        try:
            if u["scheme"] == "https":
                ctx = ssl.create_default_context()
                if not p["verify_tls"]:
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                conn = http.client.HTTPSConnection(u["host"], port, timeout=t, context=ctx)
            else:
                conn = http.client.HTTPConnection(u["host"], port, timeout=t)
            path = (u["path"] or "/") + ("?" + u["query"] if u["query"] else "")
            conn.request(method, path, headers={"User-Agent": UA, "Accept": "*/*", "Connection": "close"})
            r = conn.getresponse()
            body = r.read(max_body) if max_body else b""
            hdrs = r.getheaders()
            status = r.status
            conn.close()
        except ssl.SSLError as e:
            raise PhantomError("tls_error", "TLS error: %s (use verify_tls=false only on hosts you own)" % e)
        except (OSError, http.client.HTTPException) as e:
            raise PhantomError("network", "request failed: %s" % e)
        text = "\n".join("%s: %s" % kv for kv in hdrs)
        chain.append({"url": url, "status": status})
        loc = dict((k.lower(), v) for k, v in hdrs).get("location")
        if p["follow"] and status in (301, 302, 303, 307, 308) and loc and len(chain) <= p["max_redirects"]:
            if loc.startswith("/"):
                loc = "%s://%s%s" % (u["scheme"], u["host"] + (":%d" % u["port"] if u["port"] else ""), loc)
            url = loc
            continue
        return {"status": status, "final_url": url, "headers_text": text, "chain": chain,
                "body_bytes_read": len(body), "tls_verified": u["scheme"] == "https" and p["verify_tls"]}
    raise PhantomError("redirect_limit", "too many redirects")
