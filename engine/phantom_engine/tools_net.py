"""F. IP & Network Intelligence (12 tools)."""
import ipaddress
import re
import socket
from collections import Counter
from datetime import datetime

from .common import F, PhantomError, decode_ip, net_timeout, rate_limit
from .registry import tool

CGNAT = ipaddress.ip_network("100.64.0.0/10")
PORTS = {
    21: ("ftp", "high", "cleartext credentials"), 22: ("ssh", "medium", "restrict by IP/keys"),
    23: ("telnet", "critical", "cleartext remote shell"), 25: ("smtp", "low", "mail relay surface"),
    53: ("dns", "low", "open resolvers are abused for amplification"), 80: ("http", "info", ""),
    110: ("pop3", "medium", "cleartext mail"), 111: ("rpcbind", "high", "RPC exposure"),
    135: ("msrpc", "high", "Windows RPC"), 139: ("netbios", "high", "SMB legacy"),
    143: ("imap", "medium", "cleartext mail"), 161: ("snmp", "high", "default community risk"),
    389: ("ldap", "high", "cleartext directory"), 443: ("https", "info", ""),
    445: ("smb", "critical", "frequent worm/ransomware target"), 465: ("smtps", "info", ""),
    587: ("submission", "info", ""), 993: ("imaps", "info", ""), 995: ("pop3s", "info", ""),
    1433: ("mssql", "high", "database exposed"), 1521: ("oracle", "high", "database exposed"),
    2049: ("nfs", "high", "file share exposed"), 2375: ("docker-api", "critical", "unauthenticated Docker daemon"),
    3306: ("mysql", "high", "database exposed"), 3389: ("rdp", "high", "brute force/ransomware entry"),
    5432: ("postgresql", "high", "database exposed"), 5900: ("vnc", "high", "remote desktop"),
    6379: ("redis", "critical", "often unauthenticated"), 8080: ("http-alt", "low", ""),
    8443: ("https-alt", "info", ""), 9200: ("elasticsearch", "critical", "often unauthenticated"),
    11211: ("memcached", "critical", "amplification and data exposure"), 27017: ("mongodb", "critical", "often unauthenticated"),
}
BANNERS = [
    (r"SSH-[\d.]+-OpenSSH[_-]([\w.]+)", "OpenSSH"), (r"Apache/([\d.]+)", "Apache httpd"),
    (r"nginx/([\d.]+)", "nginx"), (r"vsFTPd ([\d.]+)", "vsftpd"), (r"ProFTPD ([\d.]+)", "ProFTPD"),
    (r"Postfix", "Postfix"), (r"Exim ([\d.]+)", "Exim"), (r"Microsoft-IIS/([\d.]+)", "IIS"),
    (r"PHP/([\d.]+)", "PHP"), (r"OpenSSL/([\d.]+\w?)", "OpenSSL"), (r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB"),
    (r"^([\d.]+)\x00?[\w-]*mysql", "MySQL"), (r"Dropbear sshd", "Dropbear"),
]


def _ip(s):
    d = decode_ip(str(s).strip())
    if not d:
        raise PhantomError("bad_input", "not an IP address: %r" % str(s)[:40])
    return ipaddress.ip_address(d[0]), d[1]


def _nets(items):
    out = []
    for x in items:
        x = str(x).split("#")[0].strip()
        if x:
            try:
                out.append(ipaddress.ip_network(x, strict=False))
            except ValueError:
                raise PhantomError("bad_input", "bad CIDR/IP: %r" % x[:40])
    return out


@tool("NET-001", "ip.classify", "Classify an IP: version, private/loopback/link-local/multicast/reserved/CGNAT/global, decode obfuscated notation.",
      "ip:str", "ip, version, scope, is_global, obfuscated, findings")
def ip_classify(p):
    a, form = _ip(p["ip"])
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    scope = ("loopback" if a.is_loopback else "link-local" if a.is_link_local else
             "multicast" if a.is_multicast else "unspecified" if a.is_unspecified else
             "cgnat" if a.version == 4 and a in CGNAT else "private" if a.is_private else
             "reserved" if a.is_reserved else "global")
    fi = [F("medium", "Obfuscated notation", "%s -> %s" % (p["ip"], a), "fact")] if form == "obfuscated" else []
    return {"ip": str(a), "version": a.version, "scope": scope, "is_global": scope == "global",
            "obfuscated": form == "obfuscated", "findings": fi}


@tool("NET-002", "ip.cidr_calc", "Network math for a CIDR: network, mask, broadcast, host range, address count.",
      "cidr:str", "network, netmask, broadcast, first_host, last_host, num_addresses, prefixlen, version")
def ip_cidr(p):
    try:
        n = ipaddress.ip_network(p["cidr"].strip(), strict=False)
    except ValueError:
        raise PhantomError("bad_input", "invalid CIDR")
    first = n.network_address + (1 if n.num_addresses > 2 else 0)
    last = n.broadcast_address - (1 if n.num_addresses > 2 and n.version == 4 else 0)
    return {"network": str(n.network_address), "netmask": str(n.netmask),
            "broadcast": str(n.broadcast_address) if n.version == 4 else None,
            "first_host": str(first), "last_host": str(last), "num_addresses": n.num_addresses,
            "prefixlen": n.prefixlen, "version": n.version}


@tool("NET-003", "ip.range_match", "Check which of your CIDR ranges contain an IP (most specific first).",
      "ip:str, cidrs:list", "matches, matched")
def ip_range(p):
    a, _ = _ip(p["ip"])
    m = sorted((n for n in _nets(p["cidrs"]) if n.version == a.version and a in n), key=lambda n: -n.prefixlen)
    return {"matches": [str(n) for n in m], "matched": bool(m)}


@tool("NET-004", "ip.reverse_pointer", "IP to reverse-DNS name (in-addr.arpa / ip6.arpa) and back.",
      "value:str", "direction, result")
def ip_rev(p):
    v = p["value"].strip().lower()
    m = re.match(r"^((?:[0-9a-f]\.){32})ip6\.arpa\.?$", v)
    if m:
        h = m.group(1).replace(".", "")[::-1]
        return {"direction": "ptr_to_ip", "result": str(ipaddress.IPv6Address(int(h, 16)))}
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa\.?$", v)
    if m:
        return {"direction": "ptr_to_ip", "result": ".".join(m.groups()[::-1])}
    a, _ = _ip(v)
    return {"direction": "ip_to_ptr", "result": a.reverse_pointer + "."}


@tool("NET-005", "ip.prefix_lookup", "Longest-prefix match of an IP against a prefix table you supply (CSV: cidr,asn,org). Offline; no bundled data.",
      "ip:str, table:str", "matched, prefix, asn, org, rows_loaded")
def ip_prefix(p):
    a, _ = _ip(p["ip"])
    best, rows = None, 0
    for line in p["table"].splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        parts = [x.strip() for x in line.split(",")]
        try:
            n = ipaddress.ip_network(parts[0], strict=False)
        except ValueError:
            continue
        rows += 1
        if n.version == a.version and a in n and (best is None or n.prefixlen > best[0].prefixlen):
            best = (n, parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "")
    return {"matched": best is not None, "prefix": str(best[0]) if best else None,
            "asn": best[1] if best else None, "org": best[2] if best else None, "rows_loaded": rows}


@tool("NET-006", "ip.blocklist_match", "Match IPs against a local blocklist (one IP/CIDR per line, # comments). The result is a local-list match, not live reputation.",
      "ips:list, blocklist:str", "hits, checked, findings")
def ip_block(p):
    nets = _nets(p["blocklist"].splitlines())
    hits, fi = [], []
    for raw in p["ips"][:10000]:
        try:
            a, _ = _ip(raw)
        except PhantomError:
            continue
        for n in nets:
            if n.version == a.version and a in n:
                hits.append({"ip": str(a), "listed_in": str(n)})
                fi.append(F("high", "%s matches local blocklist entry %s" % (a, n), "", "intel"))
                break
    return {"hits": hits, "checked": len(p["ips"]), "findings": fi}


@tool("NET-007", "net.port_map", "Map port numbers to services and rate the risk of exposing them to the Internet.",
      "ports:list", "ports, findings")
def net_ports(p):
    out, fi = [], []
    for x in p["ports"][:1000]:
        if not isinstance(x, int) or isinstance(x, bool) or not 0 < x < 65536:
            raise PhantomError("bad_input", "invalid port: %r" % x)
        svc, risk, why = PORTS.get(x, ("unknown", "info", ""))
        out.append({"port": x, "service": svc, "exposure_risk": risk, "note": why})
        if risk in ("high", "critical"):
            fi.append(F(risk, "Port %d (%s) exposed: %s" % (x, svc, why), "", "fact"))
    return {"ports": out, "findings": fi}


@tool("NET-008", "net.tcp_probe", "TCP connect check (no payload) for up to 20 ports on a host you are authorized to test. Network tool: authorized=true.",
      "host:str, ports:list, timeout:int=3", "host, results, open_ports, findings", "network")
def net_probe(p):
    ports = p["ports"]
    if not ports or len(ports) > 20:
        raise PhantomError("bad_params", "provide 1-20 ports")
    if any((not isinstance(x, int)) or isinstance(x, bool) or not 0 < x < 65536 for x in ports):
        raise PhantomError("bad_params", "invalid port in list")
    t, res, fi = net_timeout(p, 3), [], []
    for port in ports:
        rate_limit()
        s = socket.socket(socket.AF_INET6 if ":" in p["host"] else socket.AF_INET)
        s.settimeout(t)
        try:
            state = "open" if s.connect_ex((p["host"], port)) == 0 else "closed"
        except socket.gaierror:
            raise PhantomError("network", "cannot resolve host")
        except OSError:
            state = "filtered"
        finally:
            s.close()
        res.append({"port": port, "state": state})
        info = PORTS.get(port)
        if state == "open" and info and info[1] in ("high", "critical"):
            fi.append(F(info[1], "Port %d (%s) is open: %s" % (port, info[0], info[2]), "", "fact"))
    return {"host": p["host"], "results": res, "open_ports": [r["port"] for r in res if r["state"] == "open"], "findings": fi}


EOL = [(r"^PHP$", lambda v: tuple(map(int, v.split(".")[:2])) <= (8, 0), "PHP 8.0 and older no longer receive security fixes"),
       (r"^Apache httpd$", lambda v: v.startswith(("1.", "2.0", "2.2")), "Apache 2.2 and older are end-of-life"),
       (r"^OpenSSL$", lambda v: v.startswith(("0.", "1.0", "1.1.0")), "this OpenSSL branch is end-of-life")]


@tool("NET-009", "net.banner_parse", "Extract product/version from a service banner and flag known end-of-life branches (verify with vendor advisories).",
      "banner:str", "products, findings")
def net_banner(p):
    prods, fi = [], []
    text = p["banner"][:4096]
    for rx, name in BANNERS:
        m = re.search(rx, text, re.I | re.M)
        if m:
            ver = m.group(1) if m.groups() else ""
            prods.append({"product": name, "version": ver})
            for prx, test, msg in EOL:
                if re.match(prx, name) and ver:
                    try:
                        if test(ver):
                            fi.append(F("high", "%s %s: %s" % (name, ver, msg), "Version-only inference; the vendor may backport fixes.", "heuristic"))
                    except ValueError:
                        pass
    if prods:
        fi.append(F("info", "Service banner discloses product/version", ", ".join(x["product"] for x in prods), "fact"))
    return {"products": prods, "findings": fi}


@tool("NET-010", "ip.cidr_summarize", "Collapse a list of IPs/CIDRs into the minimal set of CIDR blocks.",
      "items:list", "summary, input_count, output_count")
def ip_summ(p):
    nets = _nets(p["items"])
    v4 = ipaddress.collapse_addresses([n for n in nets if n.version == 4])
    v6 = ipaddress.collapse_addresses([n for n in nets if n.version == 6])
    out = [str(n) for n in v4] + [str(n) for n in v6]
    return {"summary": out, "input_count": len(nets), "output_count": len(out)}


_V4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_V6 = re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])")


def _extract_ips(text):
    out = []
    for m in list(_V4.finditer(text)) + list(_V6.finditer(text)):
        try:
            out.append(ipaddress.ip_address(m.group(0)))
        except ValueError:
            pass
    return out


@tool("NET-011", "net.log_ip_extract", "Extract IPs from log text, count them, rank the top talkers and classify scope.",
      "text:str, top:int=10", "unique, total, top, by_scope")
def net_logips(p):
    ips = _extract_ips(p["text"])
    c = Counter(str(i) for i in ips)
    scopes = Counter()
    for s in c:
        a = ipaddress.ip_address(s)
        scopes["private" if a.is_private else "global" if a.is_global else "other"] += c[s]
    return {"unique": len(c), "total": len(ips), "top": [{"ip": k, "count": v} for k, v in c.most_common(max(1, min(100, p["top"])))],
            "by_scope": dict(scopes)}


_TS = [(re.compile(r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) [+-]\d{4}\]"), "%d/%b/%Y:%H:%M:%S"),
       (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"), None)]


@tool("NET-012", "net.request_burst_detect", "Find IPs that exceed N requests inside a time window in access-log text (defensive anomaly detection).",
      "text:str, threshold:int=100, window_seconds:int=60", "offenders, lines_parsed, findings")
def net_burst(p):
    per, parsed = {}, 0
    for line in p["text"].splitlines()[:500000]:
        ips = _extract_ips(line)
        if not ips:
            continue
        ts = None
        for rx, fmt in _TS:
            m = rx.search(line)
            if m:
                try:
                    ts = datetime.strptime(m.group(1), fmt).timestamp() if fmt else datetime.fromisoformat(m.group(1).replace(" ", "T")).timestamp()
                except ValueError:
                    ts = None
                break
        if ts is None:
            continue
        parsed += 1
        per.setdefault(str(ips[0]), []).append(ts)
    off, fi = [], []
    w = max(1, p["window_seconds"])
    for ip, tl in per.items():
        tl.sort()
        best, j = 0, 0
        for i in range(len(tl)):
            while tl[i] - tl[j] > w:
                j += 1
            best = max(best, i - j + 1)
        if best >= p["threshold"]:
            off.append({"ip": ip, "max_in_window": best, "total": len(tl)})
            fi.append(F("medium", "%s made %d requests within %ds" % (ip, best, w), "Could be a scraper, scanner or brute-force attempt.", "fact"))
    off.sort(key=lambda x: -x["max_in_window"])
    return {"offenders": off, "lines_parsed": parsed, "findings": fi}
