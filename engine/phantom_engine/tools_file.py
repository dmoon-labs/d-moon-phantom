"""G. File Security Analysis (10 tools). Local, read-only; files are never
executed or extracted to disk."""
import hashlib
import ipaddress
import os
import re
import struct
import tarfile
import time
import zipfile

from .common import (F, MAX_FILE_BYTES, PhantomError, entropy, read_file)
from .registry import tool

MAGIC = [
    (b"MZ", 0, "Windows PE executable", "application/vnd.microsoft.portable-executable", "executable"),
    (b"\x7fELF", 0, "ELF executable/library", "application/x-elf", "executable"),
    (b"\xfe\xed\xfa\xce", 0, "Mach-O 32-bit", "application/x-mach-binary", "executable"),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O 64-bit", "application/x-mach-binary", "executable"),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O 64-bit (LE)", "application/x-mach-binary", "executable"),
    (b"dex\n", 0, "Android DEX", "application/vnd.android.dex", "executable"),
    (b"\x00asm", 0, "WebAssembly", "application/wasm", "executable"),
    (b"%PDF-", 0, "PDF document", "application/pdf", "document"),
    (b"{\\rtf", 0, "RTF document", "application/rtf", "document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "OLE2 (legacy Office)", "application/x-ole-storage", "document"),
    (b"PK\x03\x04", 0, "ZIP container", "application/zip", "archive"),
    (b"PK\x05\x06", 0, "ZIP (empty)", "application/zip", "archive"),
    (b"Rar!\x1a\x07", 0, "RAR archive", "application/vnd.rar", "archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive", "application/x-7z-compressed", "archive"),
    (b"\x1f\x8b", 0, "gzip", "application/gzip", "archive"),
    (b"BZh", 0, "bzip2", "application/x-bzip2", "archive"),
    (b"\xfd7zXZ\x00", 0, "xz", "application/x-xz", "archive"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image", "image/png", "image"),
    (b"\xff\xd8\xff", 0, "JPEG image", "image/jpeg", "image"),
    (b"GIF87a", 0, "GIF image", "image/gif", "image"),
    (b"GIF89a", 0, "GIF image", "image/gif", "image"),
    (b"SQLite format 3\x00", 0, "SQLite database", "application/vnd.sqlite3", "data"),
    (b"#!", 0, "Script with shebang", "text/x-script", "script"),
    (b"<?xml", 0, "XML", "application/xml", "document"),
]
EXEC_EXT = {"exe", "scr", "pif", "com", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1",
            "msi", "jar", "lnk", "hta", "dll", "cpl", "reg", "iso", "img", "vhd", "chm", "sh", "elf"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "tgz", "bz2", "xz", "iso"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "mp3", "mp4", "csv"}
EXT_TO_CAT = {"exe": "executable", "dll": "executable", "elf": "executable", "pdf": "document",
              "doc": "document", "docx": "document", "xls": "document", "xlsx": "document",
              "ppt": "document", "pptx": "document", "rtf": "document", "png": "image", "jpg": "image",
              "jpeg": "image", "gif": "image", "zip": "archive", "rar": "archive", "7z": "archive",
              "gz": "archive", "sh": "script", "txt": "text"}


def detect(data):
    head = data[:16]
    for sig, off, name, mime, cat in MAGIC:
        if head[off:off + len(sig)] == sig:
            return name, mime, cat
    sample = data[:512].lstrip().lower()
    if sample.startswith((b"<html", b"<!doctype html")):
        return "HTML", "text/html", "document"
    if data[:4096] and all(32 <= b < 127 or b in (9, 10, 13) for b in data[:4096]):
        return "Plain text", "text/plain", "text"
    return "Unknown binary", "application/octet-stream", "unknown"


def ext_findings(name):
    fi, low = [], name.lower()
    if "\u202e" in name:
        fi.append(F("critical", "Right-to-left override character in file name (disguises the real extension)", "", "fact"))
    base = os.path.basename(low)
    parts = base.split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    if len(parts) >= 3 and parts[-2].strip() in DECOY_EXT and ext in EXEC_EXT:
        fi.append(F("high", "Double extension: looks like .%s but is .%s" % (parts[-2].strip(), ext), "", "fact"))
    if re.search(r"\s{3,}\.\w+$", base):
        fi.append(F("medium", "Many spaces before extension (hides the real type)", "", "fact"))
    if base.endswith((" ", ".")):
        fi.append(F("medium", "Trailing space/dot in file name", "", "fact"))
    if ext in EXEC_EXT:
        fi.append(F("medium", "Executable/script extension .%s" % ext, "", "fact"))
    elif ext in MACRO_EXT:
        fi.append(F("medium", "Macro-enabled Office extension .%s" % ext, "", "fact"))
    elif ext in ARCHIVE_EXT:
        fi.append(F("low", "Archive attachment/file (contents unknown)", "", "fact"))
    return fi, ext


FP = "path:str"


@tool("FIL-001", "file.hash", "Compute MD5, SHA-1, SHA-256 and SHA-512 of a file (streamed) for lookup or integrity checks.",
      FP + ", algorithms:list=", "size, hashes")
def file_hash(p):
    algs = [a for a in (p["algorithms"] or ["md5", "sha1", "sha256"])]
    for a in algs:
        if a not in ("md5", "sha1", "sha256", "sha512"):
            raise PhantomError("bad_params", "unsupported algorithm: %s" % str(a)[:20])
    path = os.path.realpath(os.path.expanduser(p["path"]))
    if not os.path.isfile(path):
        raise PhantomError("not_found", "file not found")
    size = os.path.getsize(path)
    if size > 1 << 30:
        raise PhantomError("too_large", "file larger than 1 GiB")
    hs = {a: hashlib.new(a) for a in algs}
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            for h in hs.values():
                h.update(chunk)
    return {"size": size, "hashes": {a: h.hexdigest() for a, h in hs.items()}}


@tool("FIL-002", "file.type_detect", "Identify the real file type from magic bytes instead of trusting the extension.",
      FP, "type, mime, category, size")
def file_type(p):
    data = _head(p["path"], 8192)
    name, mime, cat = detect(data)
    if cat == "archive" and name == "ZIP container":
        try:
            with zipfile.ZipFile(os.path.realpath(os.path.expanduser(p["path"]))) as z:
                n = set(z.namelist())
            if "AndroidManifest.xml" in n and any(x.endswith(".dex") for x in n):
                name, mime = "Android APK", "application/vnd.android.package-archive"
            elif "[Content_Types].xml" in n:
                name, mime, cat = "Office Open XML", "application/vnd.openxmlformats", "document"
            elif "META-INF/MANIFEST.MF" in n:
                name, mime = "Java JAR", "application/java-archive"
        except (zipfile.BadZipFile, OSError):
            pass
    return {"type": name, "mime": mime, "category": cat, "size": os.path.getsize(os.path.realpath(os.path.expanduser(p["path"])))}


def _head(path, n):
    p = os.path.realpath(os.path.expanduser(path))
    if not os.path.isfile(p):
        raise PhantomError("not_found", "file not found: " + path)
    with open(p, "rb") as fh:
        return fh.read(n)


@tool("FIL-003", "file.extension_check", "Compare the declared extension with the real type; detect double extensions, RTLO and executable disguises.",
      FP, "extension, detected_type, detected_category, mismatch, findings")
def file_ext(p):
    head = _head(p["path"], 8192)
    name, _mime, cat = detect(head)
    fi, ext = ext_findings(os.path.basename(p["path"]))
    expected = EXT_TO_CAT.get(ext)
    mismatch = bool(expected and cat not in (expected, "unknown") and not (expected == "document" and cat in ("archive", "document")))
    if mismatch:
        sev = "high" if cat == "executable" else "medium"
        fi.append(F(sev, "Extension .%s but content is %s" % (ext, name), "", "fact"))
    if cat == "executable" and ext not in EXEC_EXT and ext:
        fi.append(F("high", "Executable content hidden behind .%s" % ext, "", "fact"))
    return {"extension": ext, "detected_type": name, "detected_category": cat, "mismatch": mismatch, "findings": fi}


@tool("FIL-004", "file.entropy", "Shannon entropy of the whole file and per 4 KiB block (sampled for big files); high entropy suggests packing or encryption.",
      FP + ", block_size:int=4096", "size, entropy, block_max, block_avg, high_entropy_ratio, findings")
def file_entropy(p):
    path = os.path.realpath(os.path.expanduser(p["path"]))
    if not os.path.isfile(path):
        raise PhantomError("not_found", "file not found")
    size = os.path.getsize(path)
    if size > 32 * 1024 * 1024:
        raise PhantomError("too_large", "entropy tool limit is 32 MiB")
    bs = max(256, min(65536, p["block_size"]))
    data = open(path, "rb").read()
    blocks = [entropy(data[i:i + bs]) for i in range(0, len(data), bs) if len(data[i:i + bs]) >= min(bs, 256)]
    if not blocks:
        return {"size": size, "entropy": 0.0, "block_max": 0.0, "block_avg": 0.0, "high_entropy_ratio": 0.0, "findings": []}
    whole, hi = entropy(data), sum(b > 7.2 for b in blocks) / len(blocks)
    fi = []
    if whole > 7.5:
        fi.append(F("medium", "Very high overall entropy (%.2f/8): packed, encrypted or compressed" % whole, "Normal for archives and media.", "heuristic"))
    elif hi > 0.3 and whole > 6.8:
        fi.append(F("low", "Large share of high-entropy blocks (%.0f%%)" % (hi * 100), "", "heuristic"))
    return {"size": size, "entropy": round(whole, 4), "block_max": round(max(blocks), 4),
            "block_avg": round(sum(blocks) / len(blocks), 4), "high_entropy_ratio": round(hi, 4), "findings": fi}


SUSPICIOUS_STR = ["powershell", "-encodedcommand", "-enc ", "cmd.exe /c", "createremotethread",
                  "virtualallocex", "writeprocessmemory", "urldownloadtofile", "wscript.shell",
                  "mimikatz", "keylogger", "/bin/sh -i", "bash -i >&", "nc -e", "certutil -urlcache",
                  "regsvr32 /s", "rundll32", "schtasks /create", "net user /add", "invoke-expression"]


@tool("FIL-005", "file.strings", "Extract printable ASCII and UTF-16LE strings and report which suspicious command/API names appear.",
      FP + ", min_length:int=6, limit:int=500", "ascii_count, utf16_count, sample, suspicious, findings")
def file_strings(p):
    data = read_file(p["path"], MAX_FILE_BYTES)
    n = max(3, min(64, p["min_length"]))
    lim = max(1, min(5000, p["limit"]))
    asc = [m.group(0).decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % n, data)]
    u16 = [m.group(0).decode("utf-16le") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % n, data)]
    blob = "\n".join(asc + u16).lower()
    hits = sorted(k for k in SUSPICIOUS_STR if k in blob)
    fi = [F("medium" if len(hits) >= 3 else "low", "Strings referencing: " + ", ".join(hits[:8]),
            "Presence is a lead, not proof; admin tools use these too.", "heuristic")] if hits else []
    return {"ascii_count": len(asc), "utf16_count": len(u16), "sample": (asc + u16)[:lim],
            "suspicious": hits, "findings": fi}


_NOT_TLD = {"exe", "dll", "txt", "png", "jpg", "js", "css", "html", "json", "py", "so", "sys", "log",
            "dat", "bin", "pdf", "zip", "xml", "cfg", "ini", "md", "c", "h", "jar", "class", "tmp",
            "bat", "gif", "rb", "rs", "go", "sh", "pyc", "lib", "obj", "cpp", "ttf", "ico", "svg", "map"}


def defang(s):
    return s.replace("http", "hxxp").replace(".", "[.]")


@tool("FIL-006", "file.ioc_extract", "Extract indicators from a file: URLs, IPv4s, domains, emails, MD5/SHA1/SHA256 hashes and CVE IDs (optionally defanged).",
      FP + ", defanged:bool=false", "urls, ips, domains, emails, hashes, cves, counts")
def file_ioc(p):
    t = read_file(p["path"], 16 * 1024 * 1024).decode("latin-1")
    urls = sorted(set(m.rstrip(".,;)'\"") for m in re.findall(r"https?://[^\s\"'<>\\\]\x00]+", t, re.I)))[:500]
    ips = []
    for m in set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", t)):
        try:
            ipaddress.IPv4Address(m)
            ips.append(m)
        except ValueError:
            pass
    emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}", t)))[:500]
    doms = sorted({d.lower() for d in re.findall(r"\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b", t, re.I)
                   if d.lower().rsplit(".", 1)[-1] not in _NOT_TLD and not re.fullmatch(r"[\d.]+", d)})[:500]
    hashes = sorted(set(re.findall(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b", t)))[:500]
    cves = sorted(set(c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", t, re.I)))
    ips = sorted(ips)[:500]
    if p["defanged"]:
        urls, doms = [defang(x) for x in urls], [defang(x) for x in doms]
        ips = [x.replace(".", "[.]") for x in ips]
    return {"urls": urls, "ips": ips, "domains": doms, "emails": emails, "hashes": hashes, "cves": cves,
            "counts": {"urls": len(urls), "ips": len(ips), "domains": len(doms), "emails": len(emails),
                       "hashes": len(hashes), "cves": len(cves)}}


COMMON_SECTIONS = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata", ".bss",
                   ".tls", ".crt", ".didat", ".gfids", ".00cfg", ".xdata", ".code", ".init", ".fini"}
MACHINES = {0x14c: "x86", 0x8664: "x86-64", 0x1c0: "ARM", 0x1c4: "ARMv7 Thumb-2", 0xaa64: "ARM64", 0x200: "IA-64"}


@tool("FIL-007", "file.pe_analyze", "Parse a Windows PE header: machine, sections with entropy, ASLR/DEP/CFG flags, W+X sections, timestamp anomalies.",
      FP, "machine, is_dll, sections, aslr, dep, cfg, timestamp, entry_rva, findings")
def file_pe(p):
    d = read_file(p["path"], MAX_FILE_BYTES)
    if d[:2] != b"MZ" or len(d) < 64:
        raise PhantomError("bad_format", "not a PE file (no MZ header)")
    lfa = struct.unpack_from("<I", d, 0x3C)[0]
    if d[lfa:lfa + 4] != b"PE\0\0" or lfa + 24 > len(d):
        raise PhantomError("bad_format", "missing PE signature")
    machine, nsec, ts, _ps, _ns, optsz, chars = struct.unpack_from("<HHIIIHH", d, lfa + 4)
    opt = lfa + 24
    if opt + 72 > len(d):
        raise PhantomError("bad_format", "truncated optional header")
    magic = struct.unpack_from("<H", d, opt)[0]
    ep = struct.unpack_from("<I", d, opt + 16)[0]
    dllc = struct.unpack_from("<H", d, opt + 70)[0]
    secs, fi = [], []
    sec_off = opt + optsz
    for i in range(min(nsec, 96)):
        o = sec_off + i * 40
        if o + 40 > len(d):
            break
        name = d[o:o + 8].rstrip(b"\0").decode("latin-1")
        vsz, va, rsz, rptr = struct.unpack_from("<IIII", d, o + 8)
        sc = struct.unpack_from("<I", d, o + 36)[0]
        raw = d[rptr:rptr + rsz] if rptr < len(d) else b""
        ent = round(entropy(raw), 3) if len(raw) >= 256 else None
        secs.append({"name": name, "virtual_size": vsz, "raw_size": rsz, "entropy": ent,
                     "executable": bool(sc & 0x20000000), "writable": bool(sc & 0x80000000), "_va": va})
        if sc & 0x20000000 and sc & 0x80000000:
            fi.append(F("high", "Section %s is writable AND executable" % name, "", "fact"))
        if ent and ent > 7.2:
            fi.append(F("medium", "Section %s has high entropy (%.2f): packed/encrypted?" % (name, ent), "", "heuristic"))
        if name.lower() not in COMMON_SECTIONS and not name.startswith("/"):
            fi.append(F("low", "Non-standard section name %r" % name, "Some packers/compilers use custom names.", "heuristic"))
    aslr, dep, cfg = bool(dllc & 0x40), bool(dllc & 0x100), bool(dllc & 0x4000)
    is_dll = bool(chars & 0x2000)
    if not aslr:
        fi.append(F("medium", "ASLR (DYNAMIC_BASE) not enabled", "", "fact"))
    if not dep:
        fi.append(F("medium", "DEP/NX (NX_COMPAT) not enabled", "", "fact"))
    if ts == 0:
        fi.append(F("low", "Zero compile timestamp (stripped or reproducible build)", "", "fact"))
    elif ts > time.time() + 86400:
        fi.append(F("medium", "Compile timestamp is in the future", "", "fact"))
    host = next((s for s in secs if s["_va"] <= ep < s["_va"] + max(s["virtual_size"], s["raw_size"])), None)
    if host and not host["executable"]:
        fi.append(F("medium", "Entry point lies in non-executable section %s" % host["name"], "", "fact"))
    for s in secs:
        s.pop("_va")
    return {"machine": MACHINES.get(machine, hex(machine)), "is_dll": is_dll, "sections": secs, "aslr": aslr,
            "dep": dep, "cfg": cfg, "timestamp": ts, "entry_rva": ep, "pe32_plus": magic == 0x20b, "findings": fi}


ELF_MACH = {3: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64", 8: "MIPS", 0xf3: "RISC-V", 0x14: "PowerPC"}


@tool("FIL-008", "file.elf_analyze", "Parse an ELF header: class, endianness, type, machine, PIE, executable stack and RELRO protections.",
      FP, "bits, endian, type, machine, pie, nx_stack, relro, interpreter, findings")
def file_elf(p):
    d = read_file(p["path"], MAX_FILE_BYTES)
    if d[:4] != b"\x7fELF" or len(d) < 52:
        raise PhantomError("bad_format", "not an ELF file")
    bits = 64 if d[4] == 2 else 32
    e = "<" if d[5] == 1 else ">"
    etype, mach = struct.unpack_from(e + "HH", d, 16)
    if bits == 64:
        phoff = struct.unpack_from(e + "Q", d, 32)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", d, 54)
    else:
        phoff = struct.unpack_from(e + "I", d, 28)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", d, 42)
    nx, relro, interp = None, False, False
    for i in range(min(phnum, 256)):
        o = phoff + i * phentsize
        if o + 8 > len(d):
            break
        ptype = struct.unpack_from(e + "I", d, o)[0]
        flags = struct.unpack_from(e + "I", d, o + (4 if bits == 64 else 24))[0]
        if ptype == 0x6474e551:
            nx = not (flags & 1)
        elif ptype == 0x6474e552:
            relro = True
        elif ptype == 3:
            interp = True
    fi = []
    if nx is False:
        fi.append(F("high", "Executable stack (PT_GNU_STACK has X)", "", "fact"))
    elif nx is None:
        fi.append(F("medium", "No PT_GNU_STACK header: stack may default to executable", "", "fact"))
    if not relro:
        fi.append(F("low", "No RELRO segment", "", "fact"))
    pie = etype == 3 and interp
    if etype == 2:
        fi.append(F("low", "Non-PIE executable (fixed load address)", "", "fact"))
    return {"bits": bits, "endian": "little" if e == "<" else "big",
            "type": {1: "relocatable", 2: "executable", 3: "shared/PIE", 4: "core"}.get(etype, str(etype)),
            "machine": ELF_MACH.get(mach, hex(mach)), "pie": pie, "nx_stack": nx, "relro": relro,
            "interpreter": interp, "findings": fi}


@tool("FIL-009", "file.archive_inspect", "List a ZIP/TAR archive WITHOUT extracting: zip-bomb ratio, path traversal, symlinks, encrypted entries, executables inside.",
      FP, "format, entries, total_uncompressed, ratio, encrypted, suspicious_names, executables, findings")
def file_archive(p):
    path = os.path.realpath(os.path.expanduser(p["path"]))
    if not os.path.isfile(path):
        raise PhantomError("not_found", "file not found")
    names, total, comp, enc, links, fmt = [], 0, 0, False, 0, None
    if zipfile.is_zipfile(path):
        fmt = "zip"
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()[:20000]
            for i in infos:
                names.append(i.filename)
                total += i.file_size
                comp += i.compress_size
                enc = enc or bool(i.flag_bits & 1)
                if (i.external_attr >> 16) & 0o170000 == 0o120000:
                    links += 1
    elif tarfile.is_tarfile(path):
        fmt = "tar"
        with tarfile.open(path, "r:*") as t:
            for i, m in enumerate(t):
                if i >= 20000:
                    break
                names.append(m.name)
                total += m.size
                if m.issym() or m.islnk():
                    links += 1
        comp = os.path.getsize(path)
    else:
        raise PhantomError("bad_format", "not a ZIP or TAR archive")
    ratio = round(total / max(1, comp), 1)
    bad = [n for n in names if n.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", n) or ".." in re.split(r"[\\/]", n)]
    execs = [n for n in names if n.lower().rsplit(".", 1)[-1] in EXEC_EXT and "." in n]
    fi = []
    if bad:
        fi.append(F("high", "%d entries would escape the extraction directory (zip-slip)" % len(bad), bad[0][:80], "fact"))
    if ratio > 100 or total > 4 * 1024 ** 3:
        fi.append(F("high", "Zip-bomb indicators: ratio %.0f:1, %d bytes uncompressed" % (ratio, total), "", "fact"))
    if links:
        fi.append(F("medium", "%d symbolic/hard link entries" % links, "", "fact"))
    if enc:
        fi.append(F("low", "Encrypted entries: contents cannot be inspected (common malware-delivery trick)", "", "fact"))
    if execs:
        fi.append(F("medium", "%d executable/script entries inside" % len(execs), ", ".join(execs[:3]), "fact"))
    if len(names) >= 20000:
        fi.append(F("low", "Entry listing truncated at 20000", "", "fact"))
    return {"format": fmt, "entries": len(names), "total_uncompressed": total, "ratio": ratio, "encrypted": enc,
            "suspicious_names": bad[:20], "executables": execs[:50], "findings": fi}


@tool("FIL-010", "file.document_indicators", "Count risky features in PDF, OOXML, RTF and legacy OLE documents (JavaScript, auto-open, macros, external templates, embedded objects).",
      FP, "format, indicators, findings")
def file_doc(p):
    path = os.path.realpath(os.path.expanduser(p["path"]))
    d = read_file(path, MAX_FILE_BYTES)
    ind, fi = {}, []
    if d[:5] == b"%PDF-":
        fmt = "pdf"
        for k in ("JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "URI", "AcroForm", "RichMedia", "SubmitForm"):
            c = len(re.findall(rb"/" + k.encode() + rb"(?![A-Za-z])", d))
            if c:
                ind[k] = c
        if re.search(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}", d):
            ind["name_obfuscation"] = len(re.findall(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}", d))
        if ind.get("JavaScript") or ind.get("JS"):
            fi.append(F("high" if ind.get("OpenAction") or ind.get("AA") else "medium", "PDF contains JavaScript", "", "fact"))
        if ind.get("Launch"):
            fi.append(F("high", "PDF has a /Launch action", "", "fact"))
        if ind.get("EmbeddedFile"):
            fi.append(F("medium", "PDF embeds files", "", "fact"))
        if ind.get("name_obfuscation"):
            fi.append(F("medium", "PDF names use #-escapes (obfuscation)", "", "fact"))
    elif d[:4] == b"PK\x03\x04" and zipfile.is_zipfile(path):
        fmt = "ooxml"
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if any(n.lower().endswith("vbaproject.bin") for n in names):
                ind["vba_project"] = 1
                fi.append(F("high", "Contains a VBA macro project", "", "fact"))
            for n in names:
                if n.endswith(".rels") and z.getinfo(n).file_size < 1 << 20:
                    t = z.read(n).decode("utf-8", "replace")
                    ext = re.findall(r'Type="[^"]*/(\w+)"[^>]*TargetMode="External"', t) + \
                          re.findall(r'TargetMode="External"[^>]*Type="[^"]*/(\w+)"', t)
                    for e in ext:
                        ind["external_" + e] = ind.get("external_" + e, 0) + 1
            if any(n.startswith(("word/embeddings/", "xl/embeddings/")) for n in names):
                ind["embedded_objects"] = 1
                fi.append(F("medium", "Embedded OLE objects", "", "fact"))
            ct = z.read("[Content_Types].xml").decode("utf-8", "replace") if "[Content_Types].xml" in names else ""
            if "macroEnabled" in ct:
                ind["macro_enabled_type"] = 1
        if ind.get("external_attachedTemplate") or ind.get("external_oleObject"):
            fi.append(F("high", "Document loads external template/object (remote template injection pattern)", "", "fact"))
    elif d[:5] == b"{\\rtf":
        fmt = "rtf"
        for k in (b"\\objdata", b"\\objemb", b"\\objautlink", b"\\*\\template"):
            c = d.count(k)
            if c:
                ind[k.decode()] = c
        if ind:
            fi.append(F("high", "RTF embeds objects (frequent exploit carrier)", "", "fact"))
    elif d[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        fmt = "ole"
        for k in (b"_VBA_PROJECT", b"VBA", b"Macros", b"AutoOpen", b"Document_Open", b"Workbook_Open", b"Auto_Open"):
            c = d.count(k)
            if c:
                ind[k.decode()] = c
        if ind:
            fi.append(F("high" if any(k.startswith(("Auto", "Document_", "Workbook_")) for k in ind) else "medium",
                        "Legacy Office file with macro indicators", ", ".join(ind), "heuristic"))
    else:
        raise PhantomError("bad_format", "not a PDF, OOXML, RTF or OLE document")
    return {"format": fmt, "indicators": ind, "findings": fi}
