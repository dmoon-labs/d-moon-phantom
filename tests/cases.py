"""Per-tool test cases. Imported by test_tools.py (unittest) and by
tools/release_verify.py, which counts a tool as 'tested' only if at least one
of its cases passes."""
import http.server
import json
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "engine"))

TMP = tempfile.mkdtemp(prefix="phantom-test-")
os.environ["PHANTOM_HOME"] = os.path.join(TMP, "home")

from phantom_engine import registry, run  # noqa: E402
from phantom_engine.runner import load_all  # noqa: E402

load_all()
FIX = os.path.join(HERE, "fixtures")
CASES = []   # (tool_name, label, fn)


def case(name, label="basic"):
    def deco(fn):
        CASES.append((name, label, fn))
        return fn
    return deco


def R(_tool, **params):
    """Run a tool, require success and the declared output keys."""
    env = run(_tool, params)
    assert env["ok"], env
    t = registry.BY_NAME[_tool]
    missing = set(t.outputs) - set(env["result"])
    assert not missing, "missing declared outputs %s" % missing
    return env["result"]


def E(_tool, **params):
    env = run(_tool, params)
    assert not env["ok"], "expected failure, got %r" % env
    return env["error"]["code"]


def titles(res):
    return " | ".join(f["title"] for f in res.get("findings", []))


def tmpfile(name, data):
    d = tempfile.mkdtemp(dir=TMP)
    p = os.path.join(d, name)
    with open(p, "wb") as fh:
        fh.write(data if isinstance(data, bytes) else data.encode())
    return p


def fx(n):
    return os.path.join(FIX, n)


PHISH = "http://paypal.com.secure-login.xyz/verify?account=1"

# ============================================================ A. URL
@case("url.normalize")
def _():
    r = R("url.normalize", url="HTTP://Example.COM:80/a/./b/../c?x=1#frag")
    assert r["normalized"] == "http://example.com/a/c?x=1", r
    assert "default port removed" in r["changes"]
    assert R("url.normalize", url="example.com/%7euser/%2f")["normalized"] == "http://example.com/~user/%2F"
    assert E("url.normalize", url="") == "bad_url"


@case("url.parse_components")
def _():
    r = R("url.parse_components", url="https://user@sub.example.co.uk:8443/p?a=1&b=2#f")
    assert r["registrable_domain"] == "example.co.uk" and r["subdomain"] == "sub" and r["port"] == 8443
    assert r["query_params"] == [["a", "1"], ["b", "2"]] and r["userinfo"] == "user"


@case("url.shortener_detect")
def _():
    assert R("url.shortener_detect", url="https://bit.ly/abc")["flagged"]
    assert not R("url.shortener_detect", url="https://example.com")["flagged"]


@case("url.suspicious_tld")
def _():
    r = R("url.suspicious_tld", url="http://x.tk/")
    assert r["flagged"] and r["tld"] == "tk"
    assert not R("url.suspicious_tld", url="http://x.com/")["flagged"]


@case("url.ip_host_detect")
def _():
    assert R("url.ip_host_detect", url="http://2130706433/login")["decoded_ip"] == "127.0.0.1"
    assert R("url.ip_host_detect", url="http://0x7f.0.0.1/")["decoded_ip"] == "127.0.0.1"
    assert not R("url.ip_host_detect", url="http://example.com/")["flagged"]


@case("url.userinfo_trick")
def _():
    r = R("url.userinfo_trick", url="http://paypal.com@evil.example/")
    assert r["real_host"] == "evil.example" and r["findings"][0]["severity"] == "high"


@case("url.idn_homograph")
def _():
    r = R("url.idn_homograph", url="http://xn--pple-43d.com/")
    assert r["flagged"] and "Mixed scripts" in titles(r), r


@case("url.brand_impersonation")
def _():
    assert R("url.brand_impersonation", url="http://paypa1.com/")["flagged"]
    assert R("url.brand_impersonation", url="http://paypal.com.evil.top/")["flagged"]
    assert not R("url.brand_impersonation", url="https://www.paypal.com/")["flagged"]


@case("url.keyword_score")
def _():
    r = R("url.keyword_score", url="http://x.test/login/verify/account")
    assert {"login", "verify", "account"} <= set(r["keywords"]) and r["findings"][0]["severity"] == "high"


@case("url.length_entropy")
def _():
    r = R("url.length_entropy", url="http://example.com/" + "a" * 200)
    assert r["flagged"] and r["length"] > 200
    assert R("url.length_entropy", url="http://xkqjzvhwplr93.com/")["host_entropy"] > 3


@case("url.structure_check")
def _():
    r = R("url.structure_check", url="http://a.b.c.d.example.com:8080/")
    assert r["port"] == 8080 and "Deep subdomain" in titles(r) and "Non-standard port" in titles(r)


@case("url.redirect_params")
def _():
    assert R("url.redirect_params", url="https://a.test/r?url=https://evil.example/x")["flagged"]
    assert not R("url.redirect_params", url="https://a.test/r?page=2")["flagged"]


@case("url.encoding_obfuscation")
def _():
    assert "Double percent" in titles(R("url.encoding_obfuscation", url="http://a.test/%252e%252e/x"))
    assert "Backslash" in titles(R("url.encoding_obfuscation", url="http://a.test\\evil"))


@case("url.phishing_score")
def _():
    r = R("url.phishing_score", url=PHISH)
    assert r["score"] >= 55 and r["label"] in ("high", "critical"), r
    assert R("url.phishing_score", url="https://www.google.com/")["score"] < 10
    r = R("url.phishing_score", url="javascript:alert(1)")
    assert r["findings"][0]["severity"] == "critical"
    assert "not a verdict" in r["disclaimer"]


@case("url.batch_triage")
def _():
    r = R("url.batch_triage", urls=["https://www.google.com/", PHISH, "javascript:alert(1)", ""])
    assert r["ranked"][0]["url"] == PHISH and len(r["failed"]) == 1 and r["total"] == 4


# ============================================================ B. DOMAIN
@case("domain.validate")
def _():
    assert R("domain.validate", domain="example.com")["valid"]
    assert not R("domain.validate", domain="-bad.com")["valid"]
    assert R("domain.validate", domain="bücher.de")["ascii"] == "xn--bcher-kva.de"


@case("domain.split")
def _():
    r = R("domain.split", domain="a.b.example.co.id")
    assert r["registrable"] == "example.co.id" and r["subdomain"] == "a.b"


@case("domain.idn_codec")
def _():
    assert R("domain.idn_codec", domain="bücher.de")["ascii"] == "xn--bcher-kva.de"
    assert R("domain.idn_codec", domain="xn--bcher-kva.de")["unicode"] == "bücher.de"
    assert E("domain.idn_codec", domain="a.com", mode="zzz") == "bad_params"


@case("domain.dga_score")
def _():
    assert R("domain.dga_score", domain="xkqjzvhwpl3849.com")["score"] >= 60
    assert R("domain.dga_score", domain="google.com")["score"] < 35


@case("domain.typosquat_variants")
def _():
    r = R("domain.typosquat_variants", domain="example.com")
    v = set(r["variants"])
    assert {"exmple.com", "examlpe.com", "example.net", "wwwexample.com"} <= v and r["count"] > 50
    assert E("domain.typosquat_variants", domain="localhost") == "bad_input"


@case("domain.similarity")
def _():
    r = R("domain.similarity", a="paypal.com", b="paypa1.com")
    assert r["skeleton_equal"] and r["edit_distance"] == 1
    assert R("domain.similarity", a="example.com", b="example.net")["same_label_other_tld"]


@case("domain.tld_profile")
def _():
    assert R("domain.tld_profile", domain="x.tk")["abuse_heavy"]
    assert R("domain.tld_profile", domain="x.com")["type"] == "generic"
    assert R("domain.tld_profile", domain="x.co.id")["type"] == "country-code"


@case("domain.whois_parse")
def _():
    txt = ("Domain Name: EXAMPLE.TEST\nRegistrar: Example Registrar\nCreation Date: 2026-11-10T00:00:00Z\n"
           "Registry Expiry Date: 2027-11-10T00:00:00Z\nName Server: NS1.EXAMPLE.TEST\nDomain Status: clientTransferProhibited\n")
    r = R("domain.whois_parse", text=txt, now="2026-11-22")
    assert r["age_days"] == 12 and r["registrar"] == "Example Registrar" and r["nameservers"] == ["ns1.example.test"]
    assert "registered 12 days ago" in titles(r)


@case("domain.lexical_profile")
def _():
    r = R("domain.lexical_profile", domain="my-site-1-2-3-shop.com")
    assert r["features"]["hyphens"] == 5 and r["findings"]


@case("domain.subdomain_extract")
def _():
    r = R("domain.subdomain_extract", domain="example.com",
          text="api.example.com, dev.example.com, mail.other.com, admin.eu.example.com")
    assert r["count"] == 3 and "dev.example.com" in r["interesting"] and "admin.eu.example.com" in r["interesting"]


@case("domain.disposable_check")
def _():
    assert R("domain.disposable_check", domain="user@mailinator.com")["disposable"]
    assert not R("domain.disposable_check", domain="gmail.com")["disposable"]


@case("domain.risk_score")
def _():
    r = R("domain.risk_score", domain="secure-paypal.xyz")
    assert r["score"] >= 30 and "paypal" in titles(r)
    assert R("domain.risk_score", domain="example.com")["score"] < 10


# ============================================================ C. DNS
def _qname(name):
    return b"".join(bytes([len(l)]) + l.encode() for l in name.strip(".").split(".")) + b"\0"


def dns_response(qid, qname, qtype, answers, rcode=0):
    hdr = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0)
    pkt = hdr + _qname(qname) + struct.pack(">HH", qtype, 1)
    for rt, ttl, rdata in answers:
        pkt += b"\xc0\x0c" + struct.pack(">HHIH", rt, 1, ttl, len(rdata)) + rdata
    return pkt


def _udp_server(reply_fn):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(5)

    def loop():
        try:
            data, addr = s.recvfrom(512)
            s.sendto(reply_fn(data), addr)
        except OSError:
            pass
        finally:
            s.close()
    threading.Thread(target=loop, daemon=True).start()
    return s.getsockname()[1]


@case("dns.query")
def _():
    def reply(q):
        return dns_response(struct.unpack(">H", q[:2])[0], "example.test", 1, [(1, 300, bytes([93, 184, 216, 34]))])
    port = _udp_server(reply)
    r = R("dns.query", name="example.test", rtype="A", server="127.0.0.1", port=port, authorized=True)
    assert r["rcode"] == "NOERROR" and r["answers"][0]["data"] == "93.184.216.34" and r["answers"][0]["ttl"] == 300
    assert E("dns.query", name="example.test", server="127.0.0.1", port=port) == "not_authorized"
    assert E("dns.query", name="example.test", server="not-an-ip", authorized=True) == "bad_params"


@case("dns.packet_decode")
def _():
    mx = struct.pack(">H", 10) + b"\x04mail\xc0\x0c"          # compressed name -> mail.example.test
    txt = bytes([11]) + b"hello world"
    pkt = dns_response(0x1234, "example.test", 15, [(15, 60, mx), (16, 60, txt)])
    r = R("dns.packet_decode", hex=pkt.hex())
    assert r["answers"][0]["data"] == "10 mail.example.test" and r["answers"][1]["data"] == "hello world"
    assert E("dns.packet_decode", hex="zz") == "bad_input"
    assert E("dns.packet_decode", hex="0102") == "bad_packet"


@case("dns.zone_parse")
def _():
    z = ("$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 hostmaster ( 1 2\n 3 4 5 )\n@ IN NS ns1\n"
         "www 300 IN A 192.0.2.1\n    IN TXT \"v=spf1 -all\" ; comment\n")
    r = R("dns.zone_parse", text=z)
    assert r["count"] == 4 and r["by_type"]["A"] == 1
    txt = [x for x in r["records"] if x["type"] == "TXT"][0]
    assert txt["name"] == "www.example.test" and txt["data"] == "v=spf1 -all"
    assert [x for x in r["records"] if x["type"] == "A"][0]["ttl"] == 300


@case("dns.spf_analyze")
def _():
    r = R("dns.spf_analyze", record="v=spf1 include:_spf.google.com ~all")
    assert r["all_qualifier"] == "~" and r["lookup_mechanisms"] == 1
    assert R("dns.spf_analyze", record="v=spf1 +all")["findings"][0]["severity"] == "critical"
    assert "whole Internet" in titles(R("dns.spf_analyze", record="v=spf1 ip4:0.0.0.0/0 -all"))
    many = "v=spf1 " + " ".join("include:s%d.example.test" % i for i in range(11)) + " -all"
    assert "More than 10" in titles(R("dns.spf_analyze", record=many))
    assert not R("dns.spf_analyze", record="hello")["valid"]


@case("dns.dmarc_analyze")
def _():
    r = R("dns.dmarc_analyze", record="v=DMARC1; p=none; rua=mailto:a@example.test")
    assert r["policy"] == "none" and "monitoring only" in titles(r)
    assert "p=reject configured" in titles(R("dns.dmarc_analyze", record="v=DMARC1; p=reject; rua=mailto:a@example.test"))
    assert not R("dns.dmarc_analyze", record="p=reject")["valid"]


@case("dns.dkim_analyze")
def _():
    good = open(fx("dkim_p.txt")).read().strip()
    weak = open(fx("dkim_weak_p.txt")).read().strip()
    r = R("dns.dkim_analyze", record="v=DKIM1; k=rsa; p=" + good)
    assert r["key_bits"] == 2048 and not r["findings"]
    r = R("dns.dkim_analyze", record="v=DKIM1; k=rsa; t=y; p=" + weak)
    assert r["key_bits"] == 1024 and "below 2048" in titles(r) and "testing" in titles(r)
    assert R("dns.dkim_analyze", record="v=DKIM1; p=")["revoked"]


@case("dns.caa_analyze")
def _():
    r = R("dns.caa_analyze", records=['0 issue "letsencrypt.org"', '0 iodef "mailto:sec@example.test"'])
    assert r["issuers"] == ["letsencrypt.org"] and not r["findings"]
    assert "No CAA" in titles(R("dns.caa_analyze", records=[]))


@case("dns.mx_analyze")
def _():
    r = R("dns.mx_analyze", records=["20 mx2.example.test.", "10 mx1.example.test."])
    assert r["parsed"][0]["host"] == "mx1.example.test" and not r["findings"]
    assert R("dns.mx_analyze", records=["0 ."])["null_mx"]
    assert "Single MX" in titles(R("dns.mx_analyze", records=["10 mx1.example.test."]))


@case("dns.ttl_analyze")
def _():
    r = R("dns.ttl_analyze", records=[{"name": "a", "type": "A", "ttl": 10, "data": "1.1.1.1"}])
    assert "under 60s" in titles(r) and r["stats"]["min"] == 10
    ff = [{"name": "x", "type": "A", "ttl": 60, "data": "10.0.0.%d" % i} for i in range(6)]
    assert "Fast-flux" in titles(R("dns.ttl_analyze", records=ff))


@case("dns.takeover_hint")
def _():
    r = R("dns.takeover_hint", cnames=["old.example.test -> abandoned.github.io"], nxdomain_targets=["abandoned.github.io"])
    assert len(r["candidates"]) == 1 and r["findings"][0]["severity"] == "high"
    assert not R("dns.takeover_hint", cnames=["a.example.test cdn.example.test"], nxdomain_targets=[])["candidates"]


# ============================================================ D. TLS
@case("tls.cert_parse")
def _():
    r = R("tls.cert_parse", path=fx("leaf.pem"))
    assert r["subject"] == [["CN", "example.test"]] and "DNS:example.test" in r["san"]
    assert r["key"]["type"] == "RSA" and r["key"]["bits"] == 2048 and r["is_ca"] is False and not r["self_signed"]
    assert R("tls.cert_parse", path=fx("ca.pem"))["is_ca"] is True
    ec = R("tls.cert_parse", path=fx("ec.pem"))
    assert ec["key"]["type"] == "EC" and ec["key"]["curve"] == "P-256" and ec["self_signed"]
    assert E("tls.cert_parse") == "bad_input"


@case("tls.expiry_check")
def _():
    assert not R("tls.expiry_check", path=fx("leaf.pem"), now="2027-01-01")["findings"]
    r = R("tls.expiry_check", path=fx("leaf.pem"), now="2028-01-01")
    assert r["expired"] and r["findings"][0]["severity"] == "critical"
    assert R("tls.expiry_check", path=fx("ec.pem"), now="2026-12-20")["findings"][0]["severity"] == "high"


@case("tls.hostname_match")
def _():
    assert R("tls.hostname_match", path=fx("leaf.pem"), hostname="x.wild.test")["matches"]
    assert R("tls.hostname_match", path=fx("leaf.pem"), hostname="example.test")["matches"]
    assert not R("tls.hostname_match", path=fx("leaf.pem"), hostname="a.b.wild.test")["matches"]
    assert not R("tls.hostname_match", path=fx("leaf.pem"), hostname="other.test")["matches"]


@case("tls.sigalg_check")
def _():
    assert R("tls.sigalg_check", path=fx("weak.pem"))["strength"] == "weak"
    assert not R("tls.sigalg_check", path=fx("leaf.pem"))["findings"]


@case("tls.key_strength")
def _():
    assert "under 2048" in titles(R("tls.key_strength", path=fx("weak.pem")))
    r = R("tls.key_strength", path=fx("ec.pem"))
    assert r["curve"] == "P-256" and not r["findings"]


@case("tls.chain_analyze")
def _():
    r = R("tls.chain_analyze", path=fx("chain.pem"))
    assert r["linked"] and r["complete"] and r["length"] == 2
    assert "Only the leaf" in titles(R("tls.chain_analyze", path=fx("leaf.pem")))
    rev = open(fx("ca.pem")).read() + open(fx("leaf.pem")).read()
    assert not R("tls.chain_analyze", pem=rev)["linked"]


@case("tls.live_handshake")
def _():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(fx("leaf.pem"), fx("leaf.key"))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    srv.settimeout(6)
    stop = []

    def serve():
        while not stop:
            try:
                c, _ = srv.accept()
            except OSError:
                break
            try:
                with ctx.wrap_socket(c, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass
    threading.Thread(target=serve, daemon=True).start()
    try:
        r = R("tls.live_handshake", host="127.0.0.1", port=srv.getsockname()[1], authorized=True, timeout=5)
        assert r["verified"] is False and r["protocol"] in ("TLSv1.2", "TLSv1.3")
        assert r["certificate"]["subject_str"] == "CN=example.test" and "BEGIN CERTIFICATE" in r["pem"]
        assert "did not verify" in titles(r)
        assert E("tls.live_handshake", host="127.0.0.1") == "not_authorized"
    finally:
        stop.append(1)
        srv.close()


@case("tls.protocol_policy")
def _():
    assert not R("tls.protocol_policy", protocol="TLSv1.0")["acceptable"]
    r = R("tls.protocol_policy", protocol="TLSv1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256")
    assert r["acceptable"] and not r["findings"]
    assert "forward secrecy" in titles(R("tls.protocol_policy", protocol="TLSv1.2", cipher="AES128-SHA"))
    assert not R("tls.protocol_policy", protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384")["findings"]


@case("tls.fingerprint")
def _():
    import hashlib
    der = ssl.PEM_cert_to_DER_cert(open(fx("leaf.pem")).read())
    r = R("tls.fingerprint", path=fx("leaf.pem"))
    assert r["sha256"] == hashlib.sha256(der).hexdigest()
    assert r["spki_sha256"] == "a545b1f57432ab8c44328dbe192b47b2bd2614ab2b42e4f6da5eec07ef26f10b"   # openssl-verified


@case("tls.lifetime_check")
def _():
    r = R("tls.lifetime_check", path=fx("leaf.pem"), now="2026-12-01")
    assert r["lifetime_days"] == 365 and not r["findings"]
    w = R("tls.lifetime_check", path=fx("weak.pem"))
    assert w["over_398"] and "398" in titles(w)


# ============================================================ E. HTTP
GOOD = ("HTTP/1.1 200 OK\nStrict-Transport-Security: max-age=31536000; includeSubDomains\n"
        "Content-Security-Policy: default-src 'none'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'\n"
        "X-Content-Type-Options: nosniff\nContent-Type: text/html; charset=utf-8\nReferrer-Policy: no-referrer\n"
        "Permissions-Policy: camera=()\nCache-Control: no-store\n")


@case("http.headers_audit")
def _():
    r = R("http.headers_audit", headers=GOOD)
    assert r["grade"] in ("A", "B"), r
    bad = R("http.headers_audit", headers="HTTP/1.1 200 OK\nServer: Apache/2.4.1\nSet-Cookie: sid=1\n")
    assert bad["grade"] in ("D", "F") and "Missing Strict-Transport-Security" in titles(bad)
    assert E("http.headers_audit", headers="") == "bad_input"


@case("http.hsts_check")
def _():
    assert not R("http.hsts_check", headers="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")["findings"]
    assert R("http.hsts_check", headers="Strict-Transport-Security: max-age=0")["findings"][0]["severity"] == "high"
    assert "Missing" in titles(R("http.hsts_check", headers="X-A: 1"))


@case("http.csp_analyze")
def _():
    r = R("http.csp_analyze", headers="Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' *")
    assert "unsafe-inline" in titles(r) and "wildcard" in titles(r)
    strict = "Content-Security-Policy: script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    assert all(f["severity"] != "high" for f in R("http.csp_analyze", headers=strict)["findings"])


@case("http.framing_check")
def _():
    assert not R("http.framing_check", headers="X-Frame-Options: DENY")["findings"]
    assert R("http.framing_check", headers="X-A: 1")["findings"][0]["severity"] == "medium"
    assert not R("http.framing_check", headers="Content-Security-Policy: frame-ancestors 'none'")["findings"]


@case("http.content_type_check")
def _():
    assert not R("http.content_type_check", headers="X-Content-Type-Options: nosniff\nContent-Type: text/html; charset=utf-8")["findings"]
    assert "nosniff" in titles(R("http.content_type_check", headers="Content-Type: text/html; charset=utf-8"))


@case("http.referrer_policy_check")
def _():
    assert R("http.referrer_policy_check", headers="Referrer-Policy: unsafe-url")["findings"][0]["severity"] == "medium"
    assert not R("http.referrer_policy_check", headers="Referrer-Policy: strict-origin-when-cross-origin")["findings"]


@case("http.permissions_policy_check")
def _():
    assert "camera" in titles(R("http.permissions_policy_check", headers="Permissions-Policy: camera=*"))
    assert "Missing" in titles(R("http.permissions_policy_check", headers="X-A: 1"))


@case("http.cookie_audit")
def _():
    r = R("http.cookie_audit", headers="Set-Cookie: sessionid=abc; Path=/")
    assert "lacks Secure" in titles(r) and "lacks HttpOnly" in titles(r) and "SameSite" in titles(r)
    assert not R("http.cookie_audit", headers="Set-Cookie: a=b; Secure; HttpOnly; SameSite=Lax")["findings"]
    assert "SameSite=None without Secure" in titles(R("http.cookie_audit", headers="Set-Cookie: a=b; SameSite=None; HttpOnly"))


@case("http.cors_check")
def _():
    r = R("http.cors_check", headers="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true")
    assert r["findings"][0]["severity"] == "high"
    assert "null" in titles(R("http.cors_check", headers="Access-Control-Allow-Origin: null"))
    assert "Vary" in titles(R("http.cors_check", headers="Access-Control-Allow-Origin: https://a.test"))


@case("http.disclosure_check")
def _():
    r = R("http.disclosure_check", headers="Server: Apache/2.4.49\nX-Powered-By: PHP/7.4.1")
    assert len(r["findings"]) == 2


@case("http.cache_check")
def _():
    assert R("http.cache_check", headers="Cache-Control: public", sensitive=True)["findings"][0]["severity"] == "high"
    assert not R("http.cache_check", headers="Cache-Control: no-store", sensitive=True)["findings"]


class _H(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        if self.path == "/r":
            self.send_response(302)
            self.send_header("Location", "/final")
        else:
            self.send_response(200)
            self.send_header("X-Test", "1")
        self.end_headers()

    def log_message(self, *a):
        pass


@case("http.fetch")
def _():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = "http://127.0.0.1:%d/r" % srv.server_address[1]
        r = R("http.fetch", url=url, follow=True, authorized=True)
        assert r["status"] == 200 and len(r["chain"]) == 2 and "X-Test: 1" in r["headers_text"]
        r2 = R("http.fetch", url=url, authorized=True)
        assert r2["status"] == 302 and len(r2["chain"]) == 1
        assert E("http.fetch", url=url) == "not_authorized"
        assert E("http.fetch", url="ftp://127.0.0.1/", authorized=True) == "bad_url"
    finally:
        srv.shutdown()


# ============================================================ F. NET
@case("ip.classify")
def _():
    assert R("ip.classify", ip="10.0.0.5")["scope"] == "private"
    assert R("ip.classify", ip="8.8.8.8")["scope"] == "global"
    assert R("ip.classify", ip="100.64.1.1")["scope"] == "cgnat"
    r = R("ip.classify", ip="2130706433")
    assert r["ip"] == "127.0.0.1" and r["scope"] == "loopback" and r["obfuscated"]
    assert E("ip.classify", ip="nope") == "bad_input"


@case("ip.cidr_calc")
def _():
    r = R("ip.cidr_calc", cidr="192.168.1.10/24")
    assert (r["network"], r["broadcast"], r["first_host"], r["last_host"], r["num_addresses"]) == \
        ("192.168.1.0", "192.168.1.255", "192.168.1.1", "192.168.1.254", 256)


@case("ip.range_match")
def _():
    r = R("ip.range_match", ip="10.1.2.3", cidrs=["10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/16"])
    assert r["matches"] == ["10.1.0.0/16", "10.0.0.0/8"]


@case("ip.reverse_pointer")
def _():
    assert R("ip.reverse_pointer", value="8.8.4.4")["result"] == "4.4.8.8.in-addr.arpa."
    assert R("ip.reverse_pointer", value="4.4.8.8.in-addr.arpa")["result"] == "8.8.4.4"
    v6 = R("ip.reverse_pointer", value="2001:db8::1")["result"]
    assert R("ip.reverse_pointer", value=v6)["result"] == "2001:db8::1"


@case("ip.prefix_lookup")
def _():
    t = "203.0.113.0/24,AS64500,TestNet\n203.0.113.128/25,AS64501,Sub\n# c\n"
    r = R("ip.prefix_lookup", ip="203.0.113.200", table=t)
    assert r["prefix"] == "203.0.113.128/25" and r["asn"] == "AS64501" and r["rows_loaded"] == 2
    assert not R("ip.prefix_lookup", ip="8.8.8.8", table=t)["matched"]


@case("ip.blocklist_match")
def _():
    r = R("ip.blocklist_match", ips=["203.0.113.5", "198.51.100.1"], blocklist="203.0.113.0/24 # bad\n")
    assert len(r["hits"]) == 1 and r["findings"][0]["kind"] == "intel"


@case("net.port_map")
def _():
    r = R("net.port_map", ports=[23, 443, 6379])
    assert [f["severity"] for f in r["findings"]] == ["critical", "critical"]
    assert E("net.port_map", ports=[70000]) == "bad_input"


@case("net.tcp_probe")
def _():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    closed = free.getsockname()[1]
    free.close()
    try:
        r = R("net.tcp_probe", host="127.0.0.1", ports=[srv.getsockname()[1], closed], authorized=True, timeout=2)
        assert r["open_ports"] == [srv.getsockname()[1]]
        assert E("net.tcp_probe", host="127.0.0.1", ports=[80]) == "not_authorized"
        assert E("net.tcp_probe", host="127.0.0.1", ports=list(range(1, 30)), authorized=True) == "bad_params"
    finally:
        srv.close()


@case("net.banner_parse")
def _():
    r = R("net.banner_parse", banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu")
    assert r["products"][0] == {"product": "OpenSSH", "version": "8.9p1"}
    t = titles(R("net.banner_parse", banner="Server: Apache/2.2.15 PHP/5.3.3"))
    assert "Apache httpd 2.2.15" in t and "PHP 5.3.3" in t


@case("ip.cidr_summarize")
def _():
    r = R("ip.cidr_summarize", items=["10.0.0.0/25", "10.0.0.128/25", "10.0.1.0/24"])
    assert r["summary"] == ["10.0.0.0/23"] and r["input_count"] == 3


@case("net.log_ip_extract")
def _():
    r = R("net.log_ip_extract", text="1.2.3.4 GET /\n1.2.3.4 GET /x\n10.0.0.1 GET /y")
    assert r["unique"] == 2 and r["total"] == 3 and r["top"][0] == {"ip": "1.2.3.4", "count": 2}
    assert r["by_scope"]["private"] == 1


@case("net.request_burst_detect")
def _():
    line = '203.0.113.9 - - [10/Oct/2026:13:55:%02d +0000] "GET / HTTP/1.1" 200 5\n'
    log = "".join(line % s for s in (36, 36, 37, 37, 38, 38)) + '198.51.100.2 - - [10/Oct/2026:13:55:40 +0000] "GET / HTTP/1.1" 200 5\n'
    r = R("net.request_burst_detect", text=log, threshold=5, window_seconds=10)
    assert len(r["offenders"]) == 1 and r["offenders"][0]["ip"] == "203.0.113.9" and r["lines_parsed"] == 7


# ============================================================ G. FILE
def make_pe(with_wx=True):
    b = bytearray(0x800)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", b, 0x84, 0x8664, 2 if with_wx else 1, 1600000000, 0, 0, 240, 0x22)
    opt = 0x98
    struct.pack_into("<H", b, opt, 0x20B)
    struct.pack_into("<I", b, opt + 16, 0x1000)
    sec = opt + 240
    b[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", b, sec + 8, 0x1000, 0x1000, 0x200, 0x400)
    struct.pack_into("<I", b, sec + 36, 0x60000020)
    b[0x400:0x420] = b"\x90" * 32
    if with_wx:
        s2 = sec + 40
        b[s2:s2 + 8] = b".evil\0\0\0"
        struct.pack_into("<IIII", b, s2 + 8, 0x1000, 0x2000, 0x200, 0x600)
        struct.pack_into("<I", b, s2 + 36, 0xE0000020)
        b[0x600:0x800] = os.urandom(0x200)
    return bytes(b)


def make_elf(exec_stack=True):
    b = bytearray(64 + 112)
    b[0:4] = b"\x7fELF"
    b[4], b[5], b[6] = 2, 1, 1
    struct.pack_into("<HHIQQQIHHHHHH", b, 16, 2, 0x3E, 1, 0x400000, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", b, 64, 0x6474E551, 7 if exec_stack else 6, 0, 0, 0, 0, 0, 16)
    struct.pack_into("<IIQQQQQQ", b, 120, 1, 5, 0, 0x400000, 0, 0x100, 0x100, 0x1000)
    return bytes(b)


@case("file.hash")
def _():
    p = tmpfile("a.txt", b"hello")
    r = R("file.hash", path=p, algorithms=["md5", "sha256"])
    assert r["hashes"]["sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert r["hashes"]["md5"] == "5d41402abc4b2a76b9719d911017c592" and r["size"] == 5
    assert E("file.hash", path=p, algorithms=["crc32"]) == "bad_params"
    assert E("file.hash", path="/nonexistent/zzz") == "not_found"


@case("file.type_detect")
def _():
    assert R("file.type_detect", path=tmpfile("x.bin", b"\x89PNG\r\n\x1a\n" + b"0" * 20))["type"] == "PNG image"
    assert R("file.type_detect", path=tmpfile("y.bin", make_pe()))["category"] == "executable"
    z = tmpfile("z.bin", b"")
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("AndroidManifest.xml", "x")
        zf.writestr("classes.dex", "x")
    assert R("file.type_detect", path=z)["type"] == "Android APK"
    assert R("file.type_detect", path=tmpfile("t.txt", "plain words here"))["type"] == "Plain text"


@case("file.extension_check")
def _():
    r = R("file.extension_check", path=tmpfile("invoice.pdf.exe", make_pe(False)))
    assert "Double extension" in titles(r)
    r = R("file.extension_check", path=tmpfile("photo.jpg", make_pe(False)))
    assert r["mismatch"] and r["findings"][0]["severity"] in ("high", "critical")
    assert not R("file.extension_check", path=tmpfile("ok.png", b"\x89PNG\r\n\x1a\n" + b"0" * 9))["findings"]
    assert "Right-to-left" in titles(R("file.extension_check", path=tmpfile("cv\u202egpj.exe", make_pe(False))))


@case("file.entropy")
def _():
    r = R("file.entropy", path=tmpfile("rnd.bin", os.urandom(16384)))
    assert r["entropy"] > 7.9 and r["findings"]
    assert R("file.entropy", path=tmpfile("zero.bin", b"\0" * 8192))["entropy"] == 0


@case("file.strings")
def _():
    data = b"\x00\x01powershell -enc AAAA\x00cmd.exe /c dir\x00" + "http://evil.example".encode("utf-16le") + b"\x00\x00"
    r = R("file.strings", path=tmpfile("s.bin", data))
    assert "powershell" in r["suspicious"] and r["utf16_count"] >= 1 and r["ascii_count"] >= 2


@case("file.ioc_extract")
def _():
    t = ("see http://evil.example/a.php and 203.0.113.7 mail bob@evil.example hash d41d8cd98f00b204e9800998ecf8427e "
         "CVE-2024-12345 dropper.exe 999.1.1.1")
    r = R("file.ioc_extract", path=tmpfile("i.txt", t))
    assert r["urls"] == ["http://evil.example/a.php"] and r["ips"] == ["203.0.113.7"]
    assert "evil.example" in r["domains"] and "dropper.exe" not in r["domains"]
    assert r["hashes"] and r["cves"] == ["CVE-2024-12345"] and r["emails"] == ["bob@evil.example"]
    d = R("file.ioc_extract", path=tmpfile("i2.txt", t), defanged=True)
    assert d["urls"][0].startswith("hxxp://") and d["ips"] == ["203[.]0[.]113[.]7"]


@case("file.pe_analyze")
def _():
    r = R("file.pe_analyze", path=tmpfile("a.exe", make_pe()))
    assert r["machine"] == "x86-64" and not r["aslr"] and not r["dep"] and len(r["sections"]) == 2
    t = titles(r)
    assert "writable AND executable" in t and "high entropy" in t and "ASLR" in t
    assert E("file.pe_analyze", path=tmpfile("n.exe", b"nope")) == "bad_format"


@case("file.elf_analyze")
def _():
    r = R("file.elf_analyze", path=tmpfile("e.elf", make_elf()))
    assert r["bits"] == 64 and r["machine"] == "x86-64" and r["type"] == "executable" and r["nx_stack"] is False
    assert "Executable stack" in titles(r) and "No RELRO" in titles(r)
    assert R("file.elf_analyze", path=tmpfile("e2.elf", make_elf(False)))["nx_stack"] is True


@case("file.archive_inspect")
def _():
    p = tmpfile("a.zip", b"")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("docs/readme.txt", "hi")
        z.writestr("../evil.sh", "x")
        z.writestr("run.exe", "MZ")
        z.writestr("zeros.bin", b"\0" * (20 * 1024 * 1024))
    r = R("file.archive_inspect", path=p)
    assert r["format"] == "zip" and "../evil.sh" in r["suspicious_names"] and "run.exe" in r["executables"]
    assert r["ratio"] > 100 and "zip-slip" in titles(r) and "Zip-bomb" in titles(r)
    assert E("file.archive_inspect", path=tmpfile("n.zip", b"not an archive")) == "bad_format"


@case("file.document_indicators")
def _():
    pdf = b"%PDF-1.4\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert(1)) /JS (x) /Launch >>\n"
    r = R("file.document_indicators", path=tmpfile("d.pdf", pdf))
    assert r["format"] == "pdf" and r["indicators"]["JavaScript"] == 1 and "Launch" in r["indicators"]
    docx = tmpfile("d.docx", b"")
    rels = ('<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            'relationships/attachedTemplate" Target="http://evil.example/t.dotm" TargetMode="External"/></Relationships>')
    with zipfile.ZipFile(docx, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/vbaProject.bin", "x")
        z.writestr("word/_rels/document.xml.rels", rels)
    r = R("file.document_indicators", path=docx)
    assert r["format"] == "ooxml" and r["indicators"]["vba_project"] == 1 and r["indicators"]["external_attachedTemplate"] == 1
    assert "remote template" in titles(r)
    rtf = R("file.document_indicators", path=tmpfile("d.rtf", b"{\\rtf1 {\\object\\objemb {\\*\\objdata 0102}}}"))
    assert "\\objdata" in rtf["indicators"]


# ============================================================ H. EMAIL
@case("email.address_validate")
def _():
    assert R("email.address_validate", address="user@example.com")["valid"]
    assert not R("email.address_validate", address="bad@@x")["valid"]
    assert "Disposable" in titles(R("email.address_validate", address="a@mailinator.com"))
    assert R("email.address_validate", address="user@bücher.de")["normalized"] == "user@xn--bcher-kva.de"


HDR = ("From: Alice <alice@example.test>\nTo: bob@example.test\nSubject: Hello\nDate: Sun, 22 Nov 2026 10:06:00 +0000\n"
       "Message-ID: <1@example.test>\nReturn-Path: <alice@example.test>\n"
       "Received: from b.example.test (b [192.0.2.2]) by c.example.test; Sun, 22 Nov 2026 10:05:00 +0000\n"
       "Received: from a.example.test (a [203.0.113.1]) by b.example.test; Sun, 22 Nov 2026 10:00:00 +0000\n")


@case("email.header_parse")
def _():
    r = R("email.header_parse", raw=HDR)
    assert r["received_count"] == 2 and r["subject"] == "Hello" and not r["findings"]
    assert "No Message-ID" in titles(R("email.header_parse", raw="From: a@b.test\nSubject: x\n"))


@case("email.auth_results")
def _():
    raw = "Authentication-Results: mx.example.test; spf=pass smtp.mailfrom=a@x.test; dkim=fail header.d=x.test; dmarc=fail header.from=x.test\n"
    r = R("email.auth_results", raw=raw)
    assert r["results"]["dmarc"] == ["fail"] and any(f["severity"] == "high" for f in r["findings"])
    assert "No Authentication-Results" in titles(R("email.auth_results", raw="From: a@b.test\n"))


@case("email.received_chain")
def _():
    r = R("email.received_chain", raw=HDR)
    assert r["total_delay_seconds"] == 300 and r["hops"][0]["ip"] == "203.0.113.1" and not r["findings"]
    forged = HDR.replace("10:00:00", "08:00:00").replace("10:05:00", "07:00:00")
    assert "precedes" in titles(R("email.received_chain", raw=forged))


@case("email.sender_mismatch")
def _():
    raw = 'From: "PayPal Support" <help@evil.example>\nReply-To: <x@other.example>\nReturn-Path: <bounce@evil.example>\n'
    t = titles(R("email.sender_mismatch", raw=raw))
    assert "Reply-To domain" in t and "mentions 'paypal'" in t and "Return-Path domain" not in t


@case("email.link_analyze")
def _():
    body = '<a href="http://evil.example/login">www.paypal.com</a> <a href="javascript:alert(1)">x</a> <a href="http://bit.ly/z">ok</a>'
    r = R("email.link_analyze", body=body)
    t = titles(r)
    assert "Link text shows www.paypal.com" in t and "script/data scheme" in t and "shortener" in t


@case("email.attachment_risk")
def _():
    r = R("email.attachment_risk", filenames=["invoice.pdf.exe", "report.docm", "notes.txt"], content_types=[])
    risk = {a["filename"]: a["risk"] for a in r["attachments"]}
    assert risk["invoice.pdf.exe"] == "high" and risk["report.docm"] == "medium" and risk["notes.txt"] == "info"


@case("email.content_score")
def _():
    r = R("email.content_score", subject="URGENT: verify your account",
          body="Dear customer, your password expires immediately. Act now!!!!")
    assert r["score"] >= 45 and r["label"] == "high"
    assert R("email.content_score", subject="Lunch?", body="Are we still on for noon?")["score"] == 0


# ============================================================ I. INTEL
@case("intel.ioc_classify")
def _():
    r = R("intel.ioc_classify", iocs=["8.8.8.8", "hxxp://evil[.]example/x", "d41d8cd98f00b204e9800998ecf8427e",
                                      "cve-2024-1234", "a@b.example", "evil.example", "???"])
    assert [c["type"] for c in r["classified"]] == ["ipv4", "url", "md5", "cve", "email", "domain", "unknown"]
    assert r["classified"][1]["normalized"] == "http://evil.example/x" and r["classified"][3]["normalized"] == "CVE-2024-1234"


@case("intel.defang_refang")
def _():
    d = R("intel.defang_refang", text="http://evil.example/a", mode="defang")["result"]
    assert d == "hxxp://evil[.]example/a"
    assert R("intel.defang_refang", text=d, mode="refang")["result"] == "http://evil.example/a"
    assert E("intel.defang_refang", text="x", mode="zz") == "bad_params"


def _import_feed(name="t1"):
    p = tmpfile("feed.txt", "203.0.113.9,botnet,mylist\nevil.example\n# comment\n" + "a" * 32 + "\nnot an ioc !!\n")
    return R("intel.feed_import", path=p, name=name)


@case("intel.feed_import")
def _():
    r = _import_feed("t1")
    assert r["count"] == 3 and r["types"]["ipv4"] == 1 and os.path.isfile(r["stored_at"])
    assert E("intel.feed_import", path=tmpfile("e.txt", "garbage only"), name="t2") == "empty_feed"
    assert E("intel.feed_import", path=tmpfile("e2.txt", "1.2.3.4"), name="../x") == "bad_params"


@case("intel.feed_lookup")
def _():
    _import_feed("t3")
    r = R("intel.feed_lookup", iocs=["203.0.113.9", "evil[.]example", "8.8.8.8"], feed="t3")
    assert len(r["matches"]) == 2 and r["findings"][0]["kind"] == "intel" and r["matches"][0]["label"] == "botnet"
    assert E("intel.feed_lookup", iocs=["x"], feed="nope") == "not_found"


@case("intel.cvss_calc")
def _():
    r = R("intel.cvss_calc", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert r["base_score"] == 9.8 and r["severity"] == "Critical"
    r = R("intel.cvss_calc", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert r["base_score"] == 6.1 and r["severity"] == "Medium"
    assert R("intel.cvss_calc", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")["base_score"] == 0
    assert E("intel.cvss_calc", vector="AV:N") == "bad_input"


@case("intel.attack_map")
def _():
    r = R("intel.attack_map", text="Encoded PowerShell launched from a phishing attachment macro; lsass access")
    ids = {t["id"] for t in r["techniques"]}
    assert {"T1059.001", "T1566", "T1003", "T1204.002"} <= ids


# ============================================================ J. REPORT
_REPORT = {}


def _build():
    envs = [run("url.phishing_score", {"url": PHISH}), run("http.hsts_check", {"headers": "X-A: 1"}),
            run("url.normalize", {"url": ""})]
    return R("report.build", title="Test <b>run</b>", target="example.test", results=envs)


@case("report.build")
def _():
    r = _build()
    import re
    assert re.match(r"^RPT-\d{8}-\d{6}-[0-9a-f]{8}$", r["id"]) and r["summary"]["high"] >= 1
    assert r["summary"]["tools_run"] == 2 and r["summary"]["tools_failed"] == 1 and os.path.isfile(r["saved_to"])
    assert r["findings"][0]["severity"] in ("critical", "high")
    assert R("report.build", title="t", results=[], save=False)["saved_to"] is None


@case("report.render_txt")
def _():
    t = R("report.render_txt", report=_build())["text"]
    assert "D-MOON PHANTOM REPORT" in t and "[HIGH]" in t and "heuristic" in t


@case("report.render_html")
def _():
    rep = _build()
    rep["findings"].append({"severity": "low", "title": "<script>alert(1)</script>", "detail": "\"><img src=x>", "kind": "fact", "tool": "t"})
    h = R("report.render_html", report=rep)["html"]
    assert "<script>alert" not in h and "&lt;script&gt;alert(1)" in h and "<img src=x>" not in h
    assert "default-src 'none'" in h and "http://" not in h.replace("http://www.w3.org", "")


@case("report.list")
def _():
    _build()
    r = R("report.list", limit=5)
    assert r["total"] >= 1 and r["reports"][0]["id"].startswith("RPT-")


@case("report.show")
def _():
    rid = _build()["id"]
    assert R("report.show", id=rid)["report"]["id"] == rid
    assert "D-MOON PHANTOM REPORT" in R("report.show", id=rid, format="txt")["rendered"]
    assert E("report.show", id="../../etc/passwd") == "bad_params"
    assert E("report.show", id="RPT-20200101-000000-deadbeef") == "not_found"
