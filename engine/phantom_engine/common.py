"""Shared helpers. Standard library only (Termux friendly)."""
import ipaddress
import math
import os
import re
import string
import time
import unicodedata
from collections import Counter
from datetime import datetime, timezone

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TEXT_BYTES = 8 * 1024 * 1024


class PhantomError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------- findings
POINTS = {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 45}


def F(sev, title, detail="", kind="heuristic"):
    """kind: 'heuristic' (rule of thumb), 'fact' (deterministic computation
    on the given input) or 'intel' (match in a user-imported feed)."""
    assert sev in POINTS
    return {"severity": sev, "title": title, "detail": detail, "kind": kind}


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        k = (f["severity"], f["title"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def score(findings):
    s = min(100, sum(POINTS[f["severity"]] for f in dedupe(findings)))
    if s < 10:
        label = "minimal"
    elif s < 30:
        label = "low"
    elif s < 55:
        label = "medium"
    elif s < 80:
        label = "high"
    else:
        label = "critical"
    return s, label


# ---------------------------------------------------------------- numbers
def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in Counter(data).values())


def lev(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def utcnow(now=None):
    if now:
        return parse_date(now)
    return datetime.now(timezone.utc)


def parse_date(s):
    s = (s or "").strip()
    fmts = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d", "%d-%b-%Y", "%d-%b-%Y %H:%M:%S", "%Y.%m.%d", "%d/%m/%Y",
            "%a, %d %b %Y %H:%M:%S %z", "%d %b %Y %H:%M:%S %z",
            "%Y-%m-%dT%H:%M:%S.%fZ")
    s2 = s.replace("Z", "+0000") if s.endswith("Z") and "%z" else s
    for f in fmts:
        for cand in (s, s2):
            try:
                d = datetime.strptime(cand, f)
                return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    raise PhantomError("bad_date", "cannot parse date: %r" % s[:60])


# ---------------------------------------------------------------- domains
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ο": "o", "ν": "v",
    "α": "a", "ι": "i", "ρ": "p", "ѵ": "v", "ɡ": "g", "ⅼ": "l", "ı": "i",
    "ο": "o", "ɑ": "a", "ӏ": "l",
}
MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "co.id", "or.id", "go.id", "ac.id", "sch.id", "web.id", "my.id",
    "com.br", "co.in", "com.sg", "co.nz", "com.cn", "com.tr", "co.za", "com.my",
    "com.ph", "com.hk", "com.mx", "com.ar",
}
BRANDS = {
    "google": {"google.com", "google.co.id", "goo.gl"},
    "paypal": {"paypal.com"}, "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "amazon": {"amazon.com"}, "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"}, "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"}, "github": {"github.com"},
    "binance": {"binance.com"}, "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"}, "discord": {"discord.com", "discord.gg"},
    "telegram": {"telegram.org", "t.me"}, "steam": {"steampowered.com", "steamcommunity.com"},
    "bca": {"bca.co.id", "klikbca.com"}, "bni": {"bni.co.id"}, "bri": {"bri.co.id"},
    "mandiri": {"bankmandiri.co.id", "livin.id"}, "gopay": {"gopay.co.id", "gojek.com"},
    "shopee": {"shopee.co.id", "shopee.com"}, "tokopedia": {"tokopedia.com"},
    "telkomsel": {"telkomsel.com"}, "dana": {"dana.id"}, "ovo": {"ovo.id"},
}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "s.id",
              "tiny.cc", "rb.gy", "bl.ink", "lnkd.in", "t.ly", "v.gd", "x.co"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
              "country", "kim", "loan", "work", "party", "review", "stream",
              "download", "racing", "win", "bid", "men", "icu", "buzz", "cyou",
              "rest", "monster", "cam", "sbs", "support", "link", "gdn"}
KEYWORDS = ("login", "signin", "verify", "account", "update", "secure",
            "banking", "confirm", "password", "wallet", "suspend", "unlock",
            "invoice", "payment", "billing", "recover", "authenticate",
            "validate", "credential", "webscr", "otp", "promo", "hadiah",
            "undian", "klaim", "verifikasi", "blokir", "akun")


def split_domain(host):
    host = host.strip(".").lower()
    labels = host.split(".")
    if len(labels) < 2:
        return {"subdomain": "", "sld": host, "suffix": "", "registrable": host}
    suffix = labels[-1]
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIX:
        suffix = ".".join(labels[-2:])
    n = suffix.count(".") + 1
    if len(labels) <= n:
        return {"subdomain": "", "sld": "", "suffix": suffix, "registrable": host}
    sld = labels[-n - 1]
    return {"subdomain": ".".join(labels[:-n - 1]), "sld": sld,
            "suffix": suffix, "registrable": sld + "." + suffix}


def scripts_of(s):
    out = set()
    for ch in s:
        if ch.isalpha():
            try:
                out.add(unicodedata.name(ch).split()[0])
            except ValueError:
                out.add("UNKNOWN")
    return out


def skeleton(s):
    s = unicodedata.normalize("NFKC", s.lower())
    s = "".join(CONFUSABLES.get(c, c) for c in s)
    s = s.replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w")
    return s


_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def valid_hostname(host):
    """Return (ok, reasons) for an ASCII hostname."""
    reasons = []
    if not host:
        return False, ["empty hostname"]
    h = host[:-1] if host.endswith(".") else host
    if len(h) > 253:
        reasons.append("longer than 253 characters")
    for lab in h.split("."):
        if not lab:
            reasons.append("empty label")
        elif len(lab) > 63:
            reasons.append("label longer than 63 characters")
        elif not _LABEL.match(lab.lower()):
            reasons.append("invalid label %r" % lab[:20])
    if h.split(".")[-1].isdigit():
        reasons.append("numeric top-level label")
    return (not reasons), reasons


def to_ascii_host(host):
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        raise PhantomError("bad_idn", "cannot convert host to punycode")


# ---------------------------------------------------------------- IP
def decode_ip(h):
    """Return (ip_string, form) for plain or obfuscated (decimal/hex/octal
    inet_aton style) IPs, else None."""
    h = h.strip("[]")
    try:
        ip = ipaddress.ip_address(h)
        return str(ip), "standard"
    except ValueError:
        pass
    parts = h.split(".")
    if not (1 <= len(parts) <= 4) or not all(parts):
        return None
    vals = []
    for x in parts:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", x):
            vals.append(int(x, 16))
        elif re.fullmatch(r"0[0-7]+", x):
            vals.append(int(x, 8))
        elif x.isdigit():
            vals.append(int(x))
        else:
            return None
    n = len(vals)
    if any(v > 255 for v in vals[:-1]) or vals[-1] >= 256 ** (5 - n):
        return None
    ip = 0
    for v in vals[:-1]:
        ip = (ip << 8) | v
    ip = (ip << (8 * (5 - n))) | vals[-1]
    return str(ipaddress.IPv4Address(ip)), "obfuscated"


# ---------------------------------------------------------------- URL
DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}
UNRESERVED = set(string.ascii_letters + string.digits + "-._~")


def parse_url(raw):
    if not isinstance(raw, str) or not raw.strip():
        raise PhantomError("bad_url", "empty URL")
    s = raw.strip()
    if len(s) > 8192:
        raise PhantomError("bad_url", "URL longer than 8192 characters")
    m = re.match(r"^(javascript|data|vbscript|file|blob):", s, re.I)
    if m:
        raise PhantomError("opaque_scheme", "non-network scheme: " + m.group(1).lower())
    assumed = False
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://", s):
        s = ("http:" + s) if s.startswith("//") else ("http://" + s)
        assumed = True
    scheme, rest = s.split("://", 1)
    m = re.match(r"^([^/?#\\]*)(.*)$", rest, re.S)
    authority, tail = m.group(1), m.group(2)
    userinfo, hostport = "", authority
    if "@" in authority:
        userinfo, hostport = authority.rsplit("@", 1)
    host, port = hostport, None
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            raise PhantomError("bad_url", "unterminated IPv6 literal")
        host, rem = hostport[1:end], hostport[end + 1:]
        if rem.startswith(":"):
            port = rem[1:]
        elif rem:
            raise PhantomError("bad_url", "garbage after IPv6 literal")
    elif ":" in hostport:
        host, port = hostport.rsplit(":", 1)
    if port not in (None, ""):
        if not port.isdigit() or int(port) > 65535:
            raise PhantomError("bad_url", "invalid port")
        port = int(port)
    else:
        port = None
    host = host.lower().rstrip(".")
    if not host:
        raise PhantomError("bad_url", "missing host")
    frag = query = ""
    if "#" in tail:
        tail, frag = tail.split("#", 1)
    if "?" in tail:
        tail, query = tail.split("?", 1)
    return {"scheme": scheme.lower(), "userinfo": userinfo, "host": host,
            "port": port, "path": tail, "query": query, "fragment": frag,
            "assumed_scheme": assumed, "backslash": "\\" in s, "raw": s}


def remove_dot_segments(path):
    if not path:
        return path
    segs, out = path.split("/"), []
    for i, seg in enumerate(segs):
        last = i == len(segs) - 1
        if seg == ".":
            if last:
                out.append("")
        elif seg == "..":
            if len(out) > 1:
                out.pop()
            if last:
                out.append("")
        else:
            out.append(seg)
    return "/".join(out)


def norm_pct(s):
    def rep(m):
        ch = chr(int(m.group(1), 16))
        return ch if ch in UNRESERVED else "%" + m.group(1).upper()
    return re.sub(r"%([0-9A-Fa-f]{2})", rep, s)


def host_forms(u):
    """Helper: registrable parts or IP for a parsed URL."""
    ip = decode_ip(u["host"])
    if ip:
        return {"is_ip": True, "ip": ip[0], "ip_form": ip[1], "sld": "",
                "suffix": "", "subdomain": "", "registrable": u["host"]}
    d = split_domain(u["host"])
    d.update({"is_ip": False, "ip": None, "ip_form": None})
    return d


# ---------------------------------------------------------------- headers
def parse_headers(text):
    """Raw header block -> dict lower-name -> [values]. Skips status lines."""
    out, last = {}, None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if line[0] in " \t" and last:
            out[last][-1] += " " + line.strip()
            continue
        if line.upper().startswith("HTTP/") and ":" not in line.split(" ", 1)[0]:
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        last = k.strip().lower()
        out.setdefault(last, []).append(v.strip())
    return out


def hv(h, name):
    v = h.get(name.lower())
    return v[0] if v else None


# ---------------------------------------------------------------- files
def read_file(path, limit=MAX_TEXT_BYTES):
    if not isinstance(path, str) or not path:
        raise PhantomError("bad_input", "path required")
    p = os.path.realpath(os.path.expanduser(path))
    if not os.path.exists(p):
        raise PhantomError("not_found", "file not found: " + path)
    if not os.path.isfile(p):
        raise PhantomError("not_file", "not a regular file: " + path)
    size = os.path.getsize(p)
    if size > limit:
        raise PhantomError("too_large", "file is %d bytes, limit %d" % (size, limit))
    with open(p, "rb") as fh:
        return fh.read()


def home():
    h = os.environ.get("PHANTOM_HOME") or os.path.join(os.path.expanduser("~"), ".d-moon")
    os.makedirs(h, exist_ok=True)
    return h


# ---------------------------------------------------------------- network
_last_net = [0.0]
MIN_INTERVAL = 0.2


def net_timeout(p, default=5):
    t = p.get("timeout", default)
    return max(1, min(15, int(t)))


def rate_limit():
    wait = MIN_INTERVAL - (time.monotonic() - _last_net[0])
    if wait > 0:
        time.sleep(wait)
    _last_net[0] = time.monotonic()


# ---------------------------------------------------------------- ASN.1 DER
def der_read(buf, off):
    if off + 2 > len(buf):
        raise PhantomError("bad_der", "truncated DER")
    tag = buf[off]
    ln = buf[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or off + n > len(buf):
            raise PhantomError("bad_der", "bad DER length")
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    if off + ln > len(buf):
        raise PhantomError("bad_der", "DER length exceeds buffer")
    return tag, off, off + ln


def der_children(buf, start, end):
    out, off = [], start
    while off < end:
        tag, cs, ce = der_read(buf, off)
        out.append((tag, cs, ce))
        off = ce
    return out


def der_oid(buf, cs, ce):
    b = buf[cs:ce]
    if not b:
        return ""
    parts = [str(b[0] // 40), str(b[0] % 40)]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(str(v))
            v = 0
    return ".".join(parts)
