"""D. TLS & SSL Inspection (10 tools). Includes a minimal X.509 DER parser."""
import base64
import binascii
import hashlib
import re
import socket
import ssl
from datetime import datetime, timezone

from .common import (F, PhantomError, der_children, der_oid, der_read, net_timeout,
                     rate_limit, read_file, utcnow)
from .registry import tool

OID_NAMES = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
             "2.5.4.10": "O", "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "emailAddress"}
SIG_ALGS = {
    "1.2.840.113549.1.1.2": ("md2WithRSA", "broken"), "1.2.840.113549.1.1.4": ("md5WithRSA", "broken"),
    "1.2.840.113549.1.1.5": ("sha1WithRSA", "weak"), "1.2.840.113549.1.1.11": ("sha256WithRSA", "ok"),
    "1.2.840.113549.1.1.12": ("sha384WithRSA", "ok"), "1.2.840.113549.1.1.13": ("sha512WithRSA", "ok"),
    "1.2.840.113549.1.1.10": ("rsassa-pss", "ok"), "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "weak"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", "ok"), "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", "ok"),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", "ok"), "1.3.101.112": ("ed25519", "ok"),
}
CURVES = {"1.2.840.10045.3.1.7": ("P-256", 256), "1.3.132.0.34": ("P-384", 384),
          "1.3.132.0.35": ("P-521", 521), "1.3.132.0.10": ("secp256k1", 256)}


def _str(buf, tag, cs, ce):
    raw = buf[cs:ce]
    if tag == 0x1E:
        return raw.decode("utf-16-be", "replace")
    return raw.decode("utf-8", "replace")


def _name(buf, cs, ce):
    parts = []
    for _t, s1, e1 in der_children(buf, cs, ce):          # RDN SET
        for _t2, s2, e2 in der_children(buf, s1, e1):     # AttributeTypeAndValue
            kids = der_children(buf, s2, e2)
            if len(kids) == 2:
                oid = der_oid(buf, kids[0][1], kids[0][2])
                parts.append([OID_NAMES.get(oid, oid), _str(buf, kids[1][0], kids[1][1], kids[1][2])])
    return parts


def _time(buf, tag, cs, ce):
    s = buf[cs:ce].decode("ascii", "replace")
    try:
        if tag == 0x17:
            yy = int(s[:2])
            return datetime.strptime(("19" if yy >= 50 else "20") + s[:12], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        return datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        raise PhantomError("bad_der", "bad certificate time")


def _spki(buf, cs, ce):
    kids = der_children(buf, cs, ce)
    alg = der_children(buf, kids[0][1], kids[0][2])
    oid = der_oid(buf, alg[0][1], alg[0][2])
    out = {"algorithm": oid, "type": "unknown", "bits": None, "curve": None}
    if oid == "1.2.840.113549.1.1.1":
        _t, c2, e2 = der_read(buf, kids[1][1] + 1)
        nums = der_children(buf, c2, e2)
        out.update(type="RSA", bits=int.from_bytes(buf[nums[0][1]:nums[0][2]], "big").bit_length())
    elif oid == "1.2.840.10045.2.1" and len(alg) > 1:
        cname = CURVES.get(der_oid(buf, alg[1][1], alg[1][2]), ("unknown", None))
        out.update(type="EC", curve=cname[0], bits=cname[1])
    elif oid == "1.3.101.112":
        out.update(type="Ed25519", bits=256)
    return out


def parse_cert(der):
    tag, cs, ce = der_read(der, 0)
    if tag != 0x30:
        raise PhantomError("bad_cert", "not a DER certificate")
    top = der_children(der, cs, ce)
    if len(top) < 3:
        raise PhantomError("bad_cert", "certificate structure too short")
    tbs = der_children(der, top[0][1], top[0][2])
    i, version = 0, 1
    if tbs[0][0] == 0xA0:
        _t, s, e = der_read(der, tbs[0][1])
        version = der[s] + 1
        i = 1
    serial = der[tbs[i][1]:tbs[i][2]].hex()
    sigoid = der_oid(der, *der_children(der, tbs[i + 1][1], tbs[i + 1][2])[0][1:3])
    issuer = _name(der, tbs[i + 2][1], tbs[i + 2][2])
    val = der_children(der, tbs[i + 3][1], tbs[i + 3][2])
    nb, na = _time(der, val[0][0], val[0][1], val[0][2]), _time(der, val[1][0], val[1][1], val[1][2])
    subject = _name(der, tbs[i + 4][1], tbs[i + 4][2])
    spki = _spki(der, tbs[i + 5][1], tbs[i + 5][2])
    san, is_ca = [], None
    for t, s, e in tbs[i + 6:]:
        if t != 0xA3:
            continue
        _t, es, ee = der_read(der, s)
        for _tt, xs, xe in der_children(der, es, ee):
            parts = der_children(der, xs, xe)
            oid = der_oid(der, parts[0][1], parts[0][2])
            octet = parts[-1]
            if oid == "2.5.29.17":
                _t3, gs, ge = der_read(der, octet[1])
                for gt, a, b in der_children(der, gs, ge):
                    if gt == 0x82:
                        san.append("DNS:" + der[a:b].decode("ascii", "replace"))
                    elif gt == 0x87:
                        san.append("IP:" + ".".join(map(str, der[a:b])) if b - a == 4 else "IP:" + der[a:b].hex())
                    elif gt == 0x81:
                        san.append("email:" + der[a:b].decode("ascii", "replace"))
            elif oid == "2.5.29.19":
                _t3, bs, be = der_read(der, octet[1])
                kids = der_children(der, bs, be)
                is_ca = bool(kids and kids[0][0] == 0x01 and der[kids[0][1]] != 0)
    return {"version": version, "serial": serial,
            "signature_algorithm": SIG_ALGS.get(sigoid, (sigoid, "unknown"))[0],
            "signature_strength": SIG_ALGS.get(sigoid, (sigoid, "unknown"))[1],
            "issuer": issuer, "subject": subject,
            "issuer_str": ", ".join("%s=%s" % tuple(kv) for kv in issuer),
            "subject_str": ", ".join("%s=%s" % tuple(kv) for kv in subject),
            "not_before": nb.isoformat(), "not_after": na.isoformat(),
            "_nb": nb, "_na": na, "key": spki, "san": san, "is_ca": is_ca,
            "self_signed": issuer == subject and issuer != [],
            "sha256": hashlib.sha256(der).hexdigest()}


def pem_blocks(text):
    out = []
    for m in re.finditer(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", text, re.S):
        try:
            out.append(base64.b64decode(re.sub(r"\s+", "", m.group(1)), validate=True))
        except (binascii.Error, ValueError):
            raise PhantomError("bad_cert", "certificate block is not valid base64")
    return out


def load_certs(p):
    if p.get("path"):
        text = read_file(p["path"], 1024 * 1024).decode("latin-1")
    else:
        text = p.get("pem", "")
    blocks = pem_blocks(text)
    if not blocks:
        raise PhantomError("bad_input", "provide a PEM certificate via 'pem' or 'path'")
    return blocks


def pub(c):
    return {k: v for k, v in c.items() if not k.startswith("_")}


def _first(p):
    der = load_certs(p)[0]
    return der, parse_cert(der)


IN = "pem:str=, path:str="


@tool("TLS-001", "tls.cert_parse", "Parse a PEM X.509 certificate: subject, issuer, validity, SAN, key, signature algorithm.",
      IN, "subject, issuer, not_before, not_after, san, key, signature_algorithm, serial, is_ca, self_signed")
def tls_parse(p):
    return pub(_first(p)[1])


@tool("TLS-002", "tls.expiry_check", "Days until certificate expiry; flags expired, not-yet-valid and expiring-soon certificates.",
      IN + ", warn_days:int=30, now:str=", "days_left, expired, not_yet_valid, findings")
def tls_expiry(p):
    c = _first(p)[1]
    now = utcnow(p["now"] or None)
    left = (c["_na"] - now).days
    exp, early = c["_na"] < now, c["_nb"] > now
    fi = []
    if exp:
        fi.append(F("critical", "Certificate expired %d days ago" % -left, "", "fact"))
    elif left <= p["warn_days"]:
        fi.append(F("medium" if left > 7 else "high", "Certificate expires in %d days" % left, "", "fact"))
    if early:
        fi.append(F("high", "Certificate is not yet valid", c["not_before"], "fact"))
    return {"days_left": left, "expired": exp, "not_yet_valid": early, "findings": fi}


def san_match(host, sans):
    host = host.lower().rstrip(".")
    for s in sans:
        if not s.startswith("DNS:"):
            continue
        pat = s[4:].lower()
        if pat == host:
            return s
        if pat.startswith("*.") and host.count(".") == pat.count(".") and host.endswith(pat[1:]):
            return s
    return None


@tool("TLS-003", "tls.hostname_match", "Check whether a hostname is covered by the certificate SAN (wildcards: one left-most label only).",
      IN + ", hostname:str", "matches, matched_entry, san, findings")
def tls_host(p):
    c = _first(p)[1]
    hit = san_match(p["hostname"], c["san"])
    fi = []
    if not c["san"]:
        fi.append(F("high", "No SAN extension; modern clients ignore the CN", "", "fact"))
    if not hit:
        fi.append(F("high", "Hostname %s is not covered by this certificate" % p["hostname"], "", "fact"))
    return {"matches": bool(hit), "matched_entry": hit, "san": c["san"], "findings": fi}


@tool("TLS-004", "tls.sigalg_check", "Flag MD5/SHA-1 based certificate signatures.",
      IN, "algorithm, strength, findings")
def tls_sig(p):
    c = _first(p)[1]
    s, a, fi = c["signature_strength"], c["signature_algorithm"], []
    if s == "broken":
        fi.append(F("critical", "Broken signature algorithm: " + a, "", "fact"))
    elif s == "weak":
        fi.append(F("high", "Weak signature algorithm: " + a, "", "fact"))
    elif s == "unknown":
        fi.append(F("low", "Unrecognized signature algorithm OID: " + a, "", "fact"))
    return {"algorithm": a, "strength": s, "findings": fi}


@tool("TLS-005", "tls.key_strength", "Evaluate public-key type and size (RSA bits / EC curve).",
      IN, "type, bits, curve, findings")
def tls_key(p):
    k = _first(p)[1]["key"]
    fi = []
    if k["type"] == "RSA":
        if k["bits"] < 1024:
            fi.append(F("critical", "RSA key under 1024 bits", str(k["bits"]), "fact"))
        elif k["bits"] < 2048:
            fi.append(F("high", "RSA key under 2048 bits", str(k["bits"]), "fact"))
    elif k["type"] == "EC" and (k["bits"] or 0) < 256:
        fi.append(F("high", "EC key below 256 bits", str(k["curve"]), "fact"))
    elif k["type"] == "unknown":
        fi.append(F("low", "Unknown key algorithm", k["algorithm"], "fact"))
    return {"type": k["type"], "bits": k["bits"], "curve": k["curve"], "findings": fi}


@tool("TLS-006", "tls.chain_analyze", "Analyze a PEM bundle: leaf first, issuer-to-subject linkage, self-signed root, missing intermediates.",
      IN, "length, chain, linked, complete, findings")
def tls_chain(p):
    certs = [parse_cert(d) for d in load_certs(p)]
    fi, linked = [], True
    for a, b in zip(certs, certs[1:]):
        if a["issuer"] != b["subject"]:
            linked = False
            fi.append(F("high", "Certificate '%s' is not issued by the next certificate in the bundle" % a["subject_str"][:60],
                        "Wrong order or missing intermediate.", "fact"))
    last = certs[-1]
    complete = last["self_signed"]
    if len(certs) == 1 and not last["self_signed"]:
        fi.append(F("medium", "Only the leaf was supplied; intermediates may be missing", "", "fact"))
    elif not complete and linked:
        fi.append(F("info", "Chain ends at a non-root certificate (root is normally in the trust store)", "", "fact"))
    if certs[0]["self_signed"]:
        fi.append(F("high", "Leaf certificate is self-signed", "", "fact"))
    for c in certs[1:]:
        if c["is_ca"] is False:
            fi.append(F("high", "Issuer certificate lacks CA=true", c["subject_str"][:60], "fact"))
    return {"length": len(certs), "chain": [{"subject": c["subject_str"], "issuer": c["issuer_str"]} for c in certs],
            "linked": linked, "complete": complete, "findings": fi}


@tool("TLS-007", "tls.live_handshake", "Connect to host:port, report TLS version, cipher, verification result and certificate. Network tool: authorized=true.",
      "host:str, port:int=443, timeout:int=5, sni:str=", "protocol, cipher, verified, verify_error, certificate, pem, findings", "network")
def tls_live(p):
    if not 1 <= p["port"] <= 65535 or not p["host"].strip():
        raise PhantomError("bad_params", "invalid host/port")
    t, host = net_timeout(p), p["host"].strip()
    sni = p["sni"] or host
    rate_limit()
    verified, verr = True, None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, p["port"]), timeout=t) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                proto, cipher, der = s.version(), s.cipher(), s.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as e:
        verified, verr = False, e.verify_message or str(e)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, p["port"]), timeout=t) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as s:
                    proto, cipher, der = s.version(), s.cipher(), s.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError) as e2:
            raise PhantomError("network", "TLS handshake failed: %s" % e2)
    except (OSError, ssl.SSLError) as e:
        raise PhantomError("network", "connection/handshake failed: %s" % e)
    pem = ssl.DER_cert_to_PEM_cert(der)
    c = parse_cert(der)
    fi = []
    if not verified:
        fi.append(F("high", "Certificate did not verify against the system trust store", verr or "", "fact"))
    fi += tls_policy({"protocol": proto or "", "cipher": cipher[0] if cipher else ""})["findings"]
    return {"protocol": proto, "cipher": cipher[0] if cipher else None, "verified": verified,
            "verify_error": verr, "certificate": pub(c), "pem": pem, "findings": fi}


@tool("TLS-008", "tls.protocol_policy", "Evaluate a negotiated protocol/cipher: legacy versions, CBC/RC4/3DES/NULL/EXPORT/anon, missing forward secrecy.",
      "protocol:str, cipher:str=", "acceptable, findings")
def tls_policy(p):
    proto, cipher = p["protocol"].strip(), p["cipher"].upper()
    fi = []
    if proto in ("SSLv2", "SSLv3"):
        fi.append(F("critical", proto + " is broken", "", "fact"))
    elif proto in ("TLSv1", "TLSv1.0", "TLSv1.1"):
        fi.append(F("high", proto + " is deprecated (RFC 8996)", "", "fact"))
    elif proto not in ("TLSv1.2", "TLSv1.3"):
        fi.append(F("low", "Unrecognized protocol string: %r" % proto, "", "fact"))
    for bad, sev in (("NULL", "critical"), ("EXPORT", "critical"), ("ANON", "critical"),
                     ("RC4", "high"), ("3DES", "high"), ("DES-", "high"), ("MD5", "medium")):
        if bad in cipher:
            fi.append(F(sev, "Weak cipher component: " + bad, cipher, "fact"))
    if proto == "TLSv1.2" and cipher:
        if "CBC" in cipher:
            fi.append(F("low", "CBC mode cipher with TLS 1.2; prefer AEAD (GCM/CHACHA20)", cipher, "fact"))
        if "ECDHE" not in cipher and "DHE" not in cipher:
            fi.append(F("medium", "No forward secrecy (static key exchange)", cipher, "fact"))
    return {"acceptable": not any(f["severity"] in ("high", "critical") for f in fi), "findings": fi}


@tool("TLS-009", "tls.fingerprint", "SHA-256/SHA-1/MD5 certificate fingerprints and SPKI SHA-256 (for pinning).",
      IN, "sha256, sha1, md5, spki_sha256")
def tls_fp(p):
    der = load_certs(p)[0]
    _tag, cs, ce = der_read(der, 0)
    top = der_children(der, cs, ce)
    tbs_start, tbs_end = top[0][1], top[0][2]
    off, idx, spki = tbs_start, 0, b""
    first = True
    while off < tbs_end:
        _t, ccs, cce = der_read(der, off)
        if first and _t == 0xA0:
            first = False
            off = cce
            continue
        first = False
        idx += 1
        if idx == 6:           # serial(1) sigalg(2) issuer(3) validity(4) subject(5) spki(6)
            spki = der[off:cce]
            break
        off = cce
    return {"sha256": hashlib.sha256(der).hexdigest(), "sha1": hashlib.sha1(der).hexdigest(),
            "md5": hashlib.md5(der).hexdigest(), "spki_sha256": hashlib.sha256(spki).hexdigest()}


@tool("TLS-010", "tls.lifetime_check", "Compare validity length with the 398-day public-CA limit (private CAs are exempt) and report age.",
      IN + ", now:str=", "lifetime_days, over_398, age_days, findings")
def tls_life(p):
    c = _first(p)[1]
    days = (c["_na"] - c["_nb"]).days
    now = utcnow(p["now"] or None)
    fi = []
    if days > 398 and c["_nb"] >= datetime(2020, 9, 1, tzinfo=timezone.utc):
        fi.append(F("medium", "Validity %d days exceeds 398 days" % days,
                    "Browsers distrust public certificates issued after 2020-09-01 with longer lifetimes. Ignore for private CAs.", "fact"))
    if days > 825:
        fi.append(F("low", "Very long validity (%d days)" % days, "", "fact"))
    return {"lifetime_days": days, "over_398": days > 398, "age_days": (now - c["_nb"]).days, "findings": fi}
