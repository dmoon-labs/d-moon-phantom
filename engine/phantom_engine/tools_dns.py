"""C. DNS Analysis (10 tools). Includes a small RFC 1035 wire-format client."""
import base64
import binascii
import ipaddress
import os
import re
import socket
import struct
import time

from .common import (F, PhantomError, der_children, der_read, net_timeout,
                     rate_limit, to_ascii_host, valid_hostname)
from .registry import tool

RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
          "AAAA": 28, "SRV": 33, "CAA": 257}
RNAMES = {v: k for k, v in RTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


# ------------------------------------------------------------ wire format
def build_query(name, rtype, qid):
    q = b""
    for lab in [l for l in name.strip(".").split(".") if l != ""]:
        b = lab.encode("ascii")
        if not 0 < len(b) <= 63:
            raise PhantomError("bad_input", "invalid label length")
        q += bytes([len(b)]) + b
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + b"\0" + struct.pack(">HH", RTYPES[rtype], 1)


def read_name(buf, off):
    labels, end, hops = [], None, 0
    while True:
        if off >= len(buf):
            raise PhantomError("bad_packet", "name runs past end of packet")
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise PhantomError("bad_packet", "truncated compression pointer")
            if end is None:
                end = off + 2
            off = ((ln & 0x3F) << 8) | buf[off + 1]
            hops += 1
            if hops > 20 or off >= len(buf):
                raise PhantomError("bad_packet", "bad compression pointer")
            continue
        if ln & 0xC0:
            raise PhantomError("bad_packet", "unsupported label type")
        labels.append(buf[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels), (end if end is not None else off)


def _rdata(buf, off, rlen, rtype):
    raw = buf[off:off + rlen]
    if len(raw) != rlen:
        raise PhantomError("bad_packet", "truncated rdata")
    if rtype == 1 and rlen == 4:
        return socket.inet_ntoa(raw)
    if rtype == 28 and rlen == 16:
        return ipaddress.IPv6Address(raw).compressed
    if rtype in (2, 5, 12):
        return read_name(buf, off)[0]
    if rtype == 15 and rlen >= 3:
        return "%d %s" % (struct.unpack(">H", raw[:2])[0], read_name(buf, off + 2)[0])
    if rtype == 16:
        parts, i = [], 0
        while i < rlen:
            n = raw[i]
            parts.append(raw[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(parts)
    if rtype == 6:
        mn, o = read_name(buf, off)
        rn, o = read_name(buf, o)
        nums = struct.unpack(">IIIII", buf[o:o + 20])
        return "%s %s %s" % (mn, rn, " ".join(map(str, nums)))
    if rtype == 257 and rlen >= 2:
        tl = raw[1]
        return '%d %s "%s"' % (raw[0], raw[2:2 + tl].decode("ascii", "replace"),
                               raw[2 + tl:].decode("utf-8", "replace"))
    if rtype == 33 and rlen >= 7:
        pr, wt, pt = struct.unpack(">HHH", raw[:6])
        return "%d %d %d %s" % (pr, wt, pt, read_name(buf, off + 6)[0])
    return raw.hex()


def parse_packet(buf):
    if len(buf) < 12:
        raise PhantomError("bad_packet", "shorter than a DNS header")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    off = 12
    questions = []
    for _ in range(qd):
        name, off = read_name(buf, off)
        if off + 4 > len(buf):
            raise PhantomError("bad_packet", "truncated question")
        qt, _qc = struct.unpack(">HH", buf[off:off + 4])
        off += 4
        questions.append({"name": name, "type": RNAMES.get(qt, str(qt))})
    sections = {}
    for label, n in (("answers", an), ("authority", ns), ("additional", ar)):
        recs = []
        for _ in range(n):
            name, off = read_name(buf, off)
            if off + 10 > len(buf):
                raise PhantomError("bad_packet", "truncated record")
            rt, _rc, ttl, rl = struct.unpack(">HHIH", buf[off:off + 10])
            off += 10
            recs.append({"name": name, "type": RNAMES.get(rt, str(rt)), "ttl": ttl,
                         "data": _rdata(buf, off, rl, rt)})
            off += rl
        sections[label] = recs
    return {"id": qid, "rcode": RCODES.get(flags & 0xF, str(flags & 0xF)),
            "truncated": bool(flags & 0x200), "authoritative": bool(flags & 0x400),
            "recursion_available": bool(flags & 0x80), "questions": questions, **sections}


def _query_udp(server, port, pkt, timeout):
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, port))
        while True:
            data, addr = s.recvfrom(4096)
            if addr[0] == server and data[:2] == pkt[:2]:
                return data
    except socket.timeout:
        raise PhantomError("timeout", "no DNS reply within %ds" % timeout)
    except OSError as e:
        raise PhantomError("network", "DNS UDP error: %s" % e)
    finally:
        s.close()


def _query_tcp(server, port, pkt, timeout):
    try:
        with socket.create_connection((server, port), timeout=timeout) as s:
            s.sendall(struct.pack(">H", len(pkt)) + pkt)
            hdr = s.recv(2)
            if len(hdr) < 2:
                raise PhantomError("network", "short TCP DNS reply")
            n, data = struct.unpack(">H", hdr)[0], b""
            while len(data) < n:
                chunk = s.recv(n - len(data))
                if not chunk:
                    break
                data += chunk
            return data
    except OSError as e:
        raise PhantomError("network", "DNS TCP error: %s" % e)


@tool("DNS-001", "dns.query", "Query one record type from a DNS server (UDP, TCP fallback). Network tool: needs authorized=true.",
      "name:str, rtype:str=A, server:str=1.1.1.1, port:int=53, timeout:int=5",
      "rcode, answers, authority, server, elapsed_ms, retried_over_tcp", "network")
def dns_query(p):
    rtype = p["rtype"].upper()
    if rtype not in RTYPES:
        raise PhantomError("bad_params", "rtype must be one of " + ",".join(RTYPES))
    try:
        ipaddress.ip_address(p["server"])
    except ValueError:
        raise PhantomError("bad_params", "server must be an IP address")
    if not 1 <= p["port"] <= 65535:
        raise PhantomError("bad_params", "invalid port")
    name = to_ascii_host(p["name"].strip().rstrip("."))
    ok, why = valid_hostname(name)
    if not ok:
        raise PhantomError("bad_input", "invalid name: " + "; ".join(why))
    t = net_timeout(p)
    pkt = build_query(name, rtype, int.from_bytes(os.urandom(2), "big"))
    rate_limit()
    t0 = time.monotonic()
    data = _query_udp(p["server"], p["port"], pkt, t)
    res, tcp = parse_packet(data), False
    if res["truncated"]:
        data, tcp = _query_tcp(p["server"], p["port"], pkt, t), True
        res = parse_packet(data)
    return {"rcode": res["rcode"], "answers": res["answers"], "authority": res["authority"],
            "server": p["server"], "elapsed_ms": int((time.monotonic() - t0) * 1000),
            "retried_over_tcp": tcp}


@tool("DNS-002", "dns.packet_decode", "Decode a raw DNS response given as hex (offline), including compressed names.",
      "hex:str", "rcode, questions, answers, authority, additional, truncated")
def dns_decode(p):
    try:
        raw = binascii.unhexlify(re.sub(r"\s+", "", p["hex"]))
    except (binascii.Error, ValueError):
        raise PhantomError("bad_input", "not valid hex")
    r = parse_packet(raw)
    return {k: r[k] for k in ("rcode", "questions", "answers", "authority", "additional", "truncated")}


def _strip_comment(line):
    out, q = [], False
    for ch in line:
        if ch == '"':
            q = not q
        if ch == ";" and not q:
            break
        out.append(ch)
    return "".join(out)


@tool("DNS-003", "dns.zone_parse", "Parse zone-file text (BIND style, $ORIGIN/$TTL, parentheses) into records.",
      "text:str, origin:str=", "records, count, by_type, warnings")
def dns_zone(p):
    origin = p["origin"].strip().rstrip(".") + "." if p["origin"] else ""
    ttl_default, last, recs, warns = None, "", [], []
    lines, buf, depth, first_cont = [], "", 0, False
    for raw in p["text"].splitlines():
        ln = _strip_comment(raw.rstrip())
        if not ln.strip() and depth == 0:
            continue
        if not buf:
            first_cont = raw[:1] in (" ", "\t")
        depth += ln.count("(") - ln.count(")")
        buf += (" " if buf else "") + ln.replace("(", " ").replace(")", " ")
        if depth <= 0:
            lines.append((buf, first_cont))
            buf, depth = "", 0
    for text, cont in lines:
        toks = re.findall(r'"[^"]*"|\S+', text)
        if not toks:
            continue
        if toks[0].upper() == "$ORIGIN" and len(toks) > 1:
            origin = toks[1]
            continue
        if toks[0].upper() == "$TTL" and len(toks) > 1 and toks[1].isdigit():
            ttl_default = int(toks[1])
            continue
        i, name = 0, last
        if not cont:
            name, i = toks[0], 1
            if name == "@":
                name = origin
            elif not name.endswith(".") and origin:
                name = name + "." + origin
            last = name
        ttl = ttl_default
        while i < len(toks) and (toks[i].isdigit() or toks[i].upper() in ("IN", "CH", "HS")):
            if toks[i].isdigit():
                ttl = int(toks[i])
            i += 1
        if i >= len(toks):
            warns.append("unparsed: " + text[:60])
            continue
        recs.append({"name": name.rstrip("."), "ttl": ttl, "type": toks[i].upper(),
                     "data": " ".join(t.strip('"') if t.startswith('"') else t for t in toks[i + 1:])})
    by = {}
    for r in recs:
        by[r["type"]] = by.get(r["type"], 0) + 1
    return {"records": recs, "count": len(recs), "by_type": by, "warnings": warns}


# ------------------------------------------------------------ mail DNS policies
@tool("DNS-004", "dns.spf_analyze", "Analyze an SPF TXT record: qualifiers, +all, lookup count (limit 10), ptr, broad ip4 ranges.",
      "record:str", "valid, mechanisms, lookup_mechanisms, all_qualifier, findings")
def dns_spf(p):
    rec = p["record"].strip().strip('"')
    fi = []
    if not rec.lower().startswith("v=spf1"):
        return {"valid": False, "mechanisms": [], "lookup_mechanisms": 0, "all_qualifier": None,
                "findings": [F("critical", "Not an SPF record (must start with v=spf1)", "", "fact")]}
    toks = rec.split()[1:]
    mech, lookups, allq, redirect = [], 0, None, False
    for t in toks:
        q = t[0] if t[0] in "+-~?" else "+"
        body = t.lstrip("+-~?")
        name = re.split(r"[:=/]", body, 1)[0].lower()
        mech.append(t)
        if name in ("include", "a", "mx", "ptr", "exists", "redirect"):
            lookups += 1
        if name == "redirect":
            redirect = True
        if name == "all":
            allq = q
        if name == "ptr":
            fi.append(F("medium", "ptr mechanism is deprecated and slow", t, "fact"))
        if name == "ip4":
            try:
                net = ipaddress.ip_network(body.split(":", 1)[1], strict=False)
                if net.prefixlen == 0:
                    fi.append(F("critical", "ip4 range authorizes the whole Internet", t, "fact"))
                elif net.prefixlen < 16:
                    fi.append(F("medium", "Very broad ip4 range", t, "fact"))
            except (ValueError, IndexError):
                fi.append(F("medium", "Malformed ip4 mechanism", t, "fact"))
    if lookups > 10:
        fi.append(F("high", "More than 10 DNS-lookup mechanisms (%d): receivers return permerror" % lookups,
                    "Nested include lookups are not counted offline, so the real number may be higher.", "fact"))
    if allq == "+":
        fi.append(F("critical", "'+all' (or bare 'all') allows any sender", "", "fact"))
    elif allq == "?":
        fi.append(F("medium", "'?all' is neutral: SPF gives no protection", "", "fact"))
    elif allq == "~":
        fi.append(F("low", "'~all' softfail; '-all' is stricter once senders are inventoried", "", "fact"))
    elif allq == "-":
        fi.append(F("info", "'-all' hard fail configured", "", "fact"))
    elif not redirect:
        fi.append(F("medium", "No 'all' mechanism or redirect: default result is neutral", "", "fact"))
    return {"valid": True, "mechanisms": mech, "lookup_mechanisms": lookups,
            "all_qualifier": allq, "findings": fi}


def _tags(rec):
    out = {}
    for part in rec.strip().strip('"').split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out.setdefault(k.strip().lower(), v.strip())
    return out


@tool("DNS-005", "dns.dmarc_analyze", "Analyze a DMARC TXT record: policy strength, pct, subdomain policy, reporting URIs, alignment.",
      "record:str", "valid, tags, policy, findings")
def dns_dmarc(p):
    rec = p["record"].strip().strip('"')
    t = _tags(rec)
    fi = []
    if not re.match(r"^\s*v\s*=\s*DMARC1", rec, re.I):
        return {"valid": False, "tags": t, "policy": None,
                "findings": [F("critical", "Not a DMARC record (must start with v=DMARC1)", "", "fact")]}
    pol = t.get("p", "").lower()
    if pol not in ("none", "quarantine", "reject"):
        fi.append(F("high", "Missing or invalid p= policy", pol, "fact"))
    elif pol == "none":
        fi.append(F("medium", "p=none is monitoring only; spoofed mail is still delivered", "", "fact"))
    elif pol == "quarantine":
        fi.append(F("low", "p=quarantine; p=reject gives the strongest protection", "", "fact"))
    else:
        fi.append(F("info", "p=reject configured", "", "fact"))
    sp = t.get("sp", "").lower()
    if sp == "none" and pol in ("quarantine", "reject"):
        fi.append(F("medium", "sp=none leaves subdomains unprotected", "", "fact"))
    pct = t.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and pol != "none":
        fi.append(F("low", "pct=%s: policy applies to only part of the mail" % pct, "", "fact"))
    rua = t.get("rua", "")
    if not rua:
        fi.append(F("low", "No rua= aggregate report address", "", "fact"))
    elif not all(u.strip().lower().startswith("mailto:") for u in rua.split(",")):
        fi.append(F("low", "rua should use mailto: URIs", rua, "fact"))
    for k in ("adkim", "aspf"):
        if t.get(k, "r").lower() not in ("r", "s"):
            fi.append(F("low", "Invalid %s value" % k, t.get(k), "fact"))
    return {"valid": True, "tags": t, "policy": pol or None, "findings": fi}


def _rsa_bits(der):
    tag, cs, ce = der_read(der, 0)
    kids = der_children(der, cs, ce)
    if len(kids) < 2 or kids[1][0] != 0x03:
        raise PhantomError("bad_der", "not a SubjectPublicKeyInfo")
    bs = kids[1]
    t2, c2, e2 = der_read(der, bs[1] + 1)
    nums = der_children(der, c2, e2)
    n = int.from_bytes(der[nums[0][1]:nums[0][2]], "big")
    return n.bit_length()


@tool("DNS-006", "dns.dkim_analyze", "Analyze a DKIM selector TXT record: key type, RSA key size, revoked key, testing flag, hash algorithms.",
      "record:str", "valid, key_type, key_bits, revoked, findings")
def dns_dkim(p):
    t = _tags(p["record"])
    fi, bits, kt = [], None, t.get("k", "rsa").lower()
    key = re.sub(r"\s+", "", t.get("p", ""))
    revoked = "p" in t and key == ""
    if "p" not in t:
        return {"valid": False, "key_type": kt, "key_bits": None, "revoked": False,
                "findings": [F("high", "No p= public key tag", "", "fact")]}
    if revoked:
        fi.append(F("medium", "Key is revoked (empty p=): signatures will fail", "", "fact"))
    else:
        try:
            der = base64.b64decode(key + "=" * (-len(key) % 4), validate=True)
        except (binascii.Error, ValueError):
            return {"valid": False, "key_type": kt, "key_bits": None, "revoked": False,
                    "findings": [F("high", "p= is not valid base64", "", "fact")]}
        if kt == "ed25519":
            bits = 256
            if len(der) != 32:
                fi.append(F("high", "ed25519 key must be 32 bytes", "", "fact"))
        else:
            try:
                bits = _rsa_bits(der)
            except PhantomError:
                fi.append(F("high", "Could not parse RSA public key", "", "fact"))
            if bits and bits < 1024:
                fi.append(F("critical", "RSA key under 1024 bits (%d)" % bits, "", "fact"))
            elif bits and bits < 2048:
                fi.append(F("medium", "RSA key below 2048 bits (%d)" % bits, "", "fact"))
    if "y" in t.get("t", "").lower().split(":"):
        fi.append(F("low", "t=y testing mode: verifiers may ignore failures", "", "fact"))
    if "sha1" in t.get("h", "").lower():
        fi.append(F("medium", "h=sha1 allowed; rsa-sha1 is deprecated", "", "fact"))
    return {"valid": True, "key_type": kt, "key_bits": bits, "revoked": revoked, "findings": fi}


@tool("DNS-007", "dns.caa_analyze", "Analyze CAA records (e.g. '0 issue \"letsencrypt.org\"'): who may issue, wildcard, iodef, critical flag.",
      "records:list", "parsed, issuers, findings")
def dns_caa(p):
    parsed, issuers, fi = [], set(), []
    for r in p["records"]:
        m = re.match(r'^\s*(\d+)\s+(\w+)\s+"?([^"]*)"?\s*$', str(r))
        if not m:
            fi.append(F("low", "Unparseable CAA record", str(r)[:60], "fact"))
            continue
        flag, tag, val = int(m.group(1)), m.group(2).lower(), m.group(3)
        parsed.append({"flags": flag, "tag": tag, "value": val})
        if tag in ("issue", "issuewild") and val.strip() not in ("", ";"):
            issuers.add(val.split(";")[0].strip().lower())
        if tag not in ("issue", "issuewild", "iodef") and flag & 128:
            fi.append(F("medium", "Critical flag on unknown tag '%s'" % tag, "", "fact"))
    if not parsed:
        fi.append(F("low", "No CAA records: any CA may issue certificates", "", "fact"))
    else:
        if not any(x["tag"] == "iodef" for x in parsed):
            fi.append(F("info", "No iodef contact for violation reports", "", "fact"))
        if not any(x["tag"] == "issue" for x in parsed):
            fi.append(F("low", "No 'issue' property", "", "fact"))
    return {"parsed": parsed, "issuers": sorted(issuers), "findings": fi}


@tool("DNS-008", "dns.mx_analyze", "Analyze MX records ('10 mail.example.com.'): null MX, redundancy, IP-literal targets, priority ties.",
      "records:list", "parsed, null_mx, findings")
def dns_mx(p):
    parsed, fi = [], []
    for r in p["records"]:
        m = re.match(r"^\s*(\d+)\s+(\S+)\s*$", str(r))
        if not m:
            fi.append(F("low", "Unparseable MX record", str(r)[:60], "fact"))
            continue
        parsed.append({"priority": int(m.group(1)), "host": m.group(2).rstrip(".").lower()})
    parsed.sort(key=lambda x: x["priority"])
    null = len(parsed) == 1 and parsed[0]["host"] == ""
    if null:
        fi.append(F("info", "Null MX (RFC 7505): domain accepts no mail", "", "fact"))
    else:
        for x in parsed:
            if re.fullmatch(r"[\d.]+|[0-9a-f:]+", x["host"]) and x["host"]:
                fi.append(F("high", "MX target is an IP literal (invalid)", x["host"], "fact"))
        if len(parsed) == 1:
            fi.append(F("low", "Single MX host: no mail redundancy", "", "fact"))
        if not parsed:
            fi.append(F("info", "No MX records (mail falls back to A/AAAA)", "", "fact"))
    return {"parsed": parsed, "null_mx": null, "findings": fi}


@tool("DNS-009", "dns.ttl_analyze", "Review record TTLs for very low/high values and fast-flux-like patterns. records: [{name,type,ttl,data}].",
      "records:list", "stats, findings")
def dns_ttl(p):
    fi, ttls, ips = [], [], {}
    for r in p["records"]:
        if not isinstance(r, dict) or not isinstance(r.get("ttl"), int):
            continue
        ttls.append(r["ttl"])
        ty = str(r.get("type", "")).upper()
        if ty in ("A", "AAAA"):
            ips.setdefault(r.get("name", ""), []).append((r["ttl"], r.get("data")))
        if r["ttl"] < 60:
            fi.append(F("low", "TTL under 60s on %s %s" % (ty, r.get("name", "")), "", "fact"))
        elif r["ttl"] > 7 * 86400:
            fi.append(F("low", "TTL over 7 days on %s %s" % (ty, r.get("name", "")), "Slows emergency changes.", "fact"))
        if ty in ("NS", "SOA") and r["ttl"] < 300:
            fi.append(F("low", "Short TTL on %s record" % ty, "", "fact"))
    for name, lst in ips.items():
        if len({d for _, d in lst}) >= 5 and max(t for t, _ in lst) <= 300:
            fi.append(F("medium", "Fast-flux-like pattern for %s" % name, "5+ addresses with TTL <= 300s."))
    st = {"count": len(ttls), "min": min(ttls) if ttls else None, "max": max(ttls) if ttls else None,
          "avg": round(sum(ttls) / len(ttls), 1) if ttls else None}
    return {"stats": st, "findings": fi}


TAKEOVER = ("github.io", "herokuapp.com", "azurewebsites.net", "cloudapp.net", "trafficmanager.net",
            "s3.amazonaws.com", "elasticbeanstalk.com", "surge.sh", "netlify.app", "pages.dev",
            "bitbucket.io", "ghost.io", "readme.io", "zendesk.com", "statuspage.io", "myshopify.com",
            "unbouncepages.com", "helpscoutdocs.com", "tumblr.com", "wordpress.com", "fastly.net")


@tool("DNS-010", "dns.takeover_hint", "Flag CNAMEs pointing at third-party hosting that is commonly claimable; combine with targets you know are NXDOMAIN.",
      "cnames:list, nxdomain_targets:list=", "checked, candidates, findings")
def dns_takeover(p):
    nx = {str(x).rstrip(".").lower() for x in p["nxdomain_targets"]}
    fi, cands, n = [], [], 0
    for line in p["cnames"]:
        parts = str(line).replace("->", " ").split()
        if len(parts) < 2:
            continue
        n += 1
        name, tgt = parts[0].rstrip(".").lower(), parts[-1].rstrip(".").lower()
        prov = next((s for s in TAKEOVER if tgt == s or tgt.endswith("." + s)), None)
        if prov and tgt in nx:
            cands.append({"name": name, "target": tgt, "provider": prov})
            fi.append(F("high", "Dangling CNAME %s -> %s (target does not resolve)" % (name, tgt),
                        "Provider '%s' often lets others claim unused names. Verify, then remove the record or reclaim the resource." % prov))
        elif prov:
            fi.append(F("info", "CNAME to claimable-hosting provider: %s -> %s" % (name, tgt),
                        "Confirm the resource still exists.", "fact"))
        elif tgt in nx:
            fi.append(F("medium", "CNAME target does not resolve: %s -> %s" % (name, tgt)))
    return {"checked": n, "candidates": cands, "findings": fi}
