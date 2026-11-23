//! D-MOON PHANTOM core: reads one JSON object on stdin, writes one JSON object
//! on stdout. No network access, no file access, memory-safe Rust only.
//!
//! Operations:
//!   {"op":"normalize_url","url":"..."}      -> {"valid":bool,"normalized":..,"error":..}
//!   {"op":"validate_hostname","host":"..."} -> {"valid":bool,"reasons":[..]}

use serde_json::{json, Value};
use std::io::Read;

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~'
}

/// Uppercase percent-escapes and decode escapes of unreserved characters.
pub fn norm_pct(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                if is_unreserved(v) {
                    out.push(v);
                } else {
                    out.push(b'%');
                    out.push(b[i + 1].to_ascii_uppercase());
                    out.push(b[i + 2].to_ascii_uppercase());
                }
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

pub fn remove_dot_segments(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let segs: Vec<&str> = path.split('/').collect();
    let n = segs.len();
    let mut out: Vec<&str> = Vec::new();
    for (i, seg) in segs.iter().enumerate() {
        let last = i == n - 1;
        match *seg {
            "." => {
                if last {
                    out.push("");
                }
            }
            ".." => {
                if out.len() > 1 {
                    out.pop();
                }
                if last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

fn has_scheme(s: &str) -> bool {
    match s.find("://") {
        Some(i) if i > 0 => {
            let sch = &s[..i];
            sch.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false)
                && sch.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        }
        _ => false,
    }
}

fn default_port(scheme: &str) -> Option<u32> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        "ftp" => Some(21),
        _ => None,
    }
}

/// Returns (normalized URL, whether the host needs IDNA conversion).
pub fn normalize_url(raw: &str) -> Result<(String, bool), String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("empty URL".to_string());
    }
    if s.len() > 8192 {
        return Err("URL longer than 8192 characters".to_string());
    }
    let lower = s.to_ascii_lowercase();
    for p in ["javascript:", "data:", "vbscript:", "file:", "blob:"] {
        if lower.starts_with(p) {
            return Err(format!("non-network scheme: {}", p.trim_end_matches(':')));
        }
    }
    let full = if has_scheme(s) {
        s.to_string()
    } else if s.starts_with("//") {
        format!("http:{}", s)
    } else {
        format!("http://{}", s)
    };
    let (scheme, rest) = match full.split_once("://") {
        Some(x) => x,
        None => return Err("missing scheme separator".to_string()),
    };
    let scheme = scheme.to_ascii_lowercase();
    let end = rest
        .find(|c: char| c == '/' || c == '?' || c == '#' || c == '\\')
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    let tail = &rest[end..];
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (&authority[..i], &authority[i + 1..]),
        None => ("", authority),
    };
    let host: &str;
    let mut port: Option<&str> = None;
    if hostport.starts_with('[') {
        let e = match hostport.find(']') {
            Some(e) => e,
            None => return Err("unterminated IPv6 literal".to_string()),
        };
        host = &hostport[1..e];
        let rem = &hostport[e + 1..];
        if let Some(p) = rem.strip_prefix(':') {
            port = Some(p);
        } else if !rem.is_empty() {
            return Err("garbage after IPv6 literal".to_string());
        }
    } else if let Some(i) = hostport.rfind(':') {
        host = &hostport[..i];
        port = Some(&hostport[i + 1..]);
    } else {
        host = hostport;
    }
    let mut port_num: Option<u32> = None;
    if let Some(p) = port {
        if !p.is_empty() {
            match p.parse::<u32>() {
                Ok(n) if n <= 65535 && p.chars().all(|c| c.is_ascii_digit()) => port_num = Some(n),
                _ => return Err("invalid port".to_string()),
            }
        }
    }
    let host = host.to_lowercase();
    let host = host.trim_end_matches('.').to_string();
    if host.is_empty() {
        return Err("missing host".to_string());
    }
    let needs_idna = !host.is_ascii();

    // path / query (fragment is dropped)
    let tail = tail.split('#').next().unwrap_or("");
    let (path_raw, query_raw) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (tail, None),
    };
    let mut path = remove_dot_segments(&norm_pct(path_raw));
    if path.is_empty() {
        path = "/".to_string();
    }
    let mut out = format!("{}://", scheme);
    if !userinfo.is_empty() {
        out.push_str(userinfo);
        out.push('@');
    }
    if host.contains(':') {
        out.push_str(&format!("[{}]", host));
    } else {
        out.push_str(&host);
    }
    if let Some(n) = port_num {
        if default_port(&scheme) != Some(n) {
            out.push_str(&format!(":{}", n));
        }
    }
    out.push_str(&path);
    if let Some(q) = query_raw {
        if !q.is_empty() {
            out.push('?');
            out.push_str(&norm_pct(q));
        }
    }
    Ok((out, needs_idna))
}

pub fn validate_hostname(host: &str) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    let h = host.strip_suffix('.').unwrap_or(host);
    if h.is_empty() {
        return vec!["empty hostname".to_string()];
    }
    if h.len() > 253 {
        reasons.push("longer than 253 characters".to_string());
    }
    if !h.is_ascii() {
        reasons.push("non-ASCII hostname: convert to punycode first".to_string());
        return reasons;
    }
    let labels: Vec<&str> = h.split('.').collect();
    for lab in &labels {
        if lab.is_empty() {
            reasons.push("empty label".to_string());
        } else if lab.len() > 63 {
            reasons.push("label longer than 63 characters".to_string());
        } else {
            let ok_chars = lab
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            if !ok_chars || lab.starts_with('-') || lab.ends_with('-') {
                reasons.push(format!("invalid label {:?}", lab));
            }
        }
    }
    if let Some(last) = labels.last() {
        if !last.is_empty() && last.chars().all(|c| c.is_ascii_digit()) {
            reasons.push("numeric top-level label".to_string());
        }
    }
    reasons
}

fn handle(input: &Value) -> Value {
    match input.get("op").and_then(|v| v.as_str()) {
        Some("normalize_url") => {
            let url = input.get("url").and_then(|v| v.as_str()).unwrap_or("");
            match normalize_url(url) {
                Ok((n, idna)) => json!({"valid": true, "normalized": n, "needs_idna": idna, "error": null}),
                Err(e) => json!({"valid": false, "normalized": null, "needs_idna": false, "error": e}),
            }
        }
        Some("validate_hostname") => {
            let host = input.get("host").and_then(|v| v.as_str()).unwrap_or("");
            let reasons = validate_hostname(host);
            json!({"valid": reasons.is_empty(), "reasons": reasons})
        }
        Some(other) => json!({"error": format!("unknown op {:?}", other)}),
        None => json!({"error": "missing op"}),
    }
}

fn main() {
    let mut buf = String::new();
    if std::io::stdin().take(1_048_576).read_to_string(&mut buf).is_err() {
        println!("{}", json!({"error": "stdin is not valid UTF-8"}));
        std::process::exit(1);
    }
    match serde_json::from_str::<Value>(&buf) {
        Ok(v) => {
            let out = handle(&v);
            let failed = out.get("error").map(|e| !e.is_null()).unwrap_or(false) && out.get("valid").is_none();
            println!("{}", out);
            std::process::exit(if failed { 1 } else { 0 });
        }
        Err(e) => {
            println!("{}", json!({"error": format!("invalid JSON: {}", e)}));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_like_the_python_engine() {
        let (n, _) = normalize_url("HTTP://Example.COM:80/a/./b/../c?x=1#frag").unwrap();
        assert_eq!(n, "http://example.com/a/c?x=1");
        let (n, _) = normalize_url("example.com/%7euser/%2f").unwrap();
        assert_eq!(n, "http://example.com/~user/%2F");
        let (n, _) = normalize_url("https://a.test:8443").unwrap();
        assert_eq!(n, "https://a.test:8443/");
    }

    #[test]
    fn rejects_bad_input() {
        assert!(normalize_url("").is_err());
        assert!(normalize_url("javascript:alert(1)").is_err());
        assert!(normalize_url("http://a.test:99999/").is_err());
        assert!(normalize_url("http://[::1/").is_err());
    }

    #[test]
    fn dot_segments() {
        assert_eq!(remove_dot_segments("/a/b/../c"), "/a/c");
        assert_eq!(remove_dot_segments("/../x"), "/x");
        assert_eq!(remove_dot_segments("/a/."), "/a/");
    }

    #[test]
    fn hostnames() {
        assert!(validate_hostname("example.com").is_empty());
        assert!(!validate_hostname("-bad.com").is_empty());
        assert!(!validate_hostname("a..b").is_empty());
        assert!(!validate_hostname("example.123").is_empty());
    }
}
