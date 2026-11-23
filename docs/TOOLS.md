# D-MOON PHANTOM tool catalog

Total tools: **100**

Generated from the registry by `tools/gen_docs.py`. Do not edit by hand.

Permissions: `none` pure computation on supplied data, `file-read` reads a local file, `file-write` writes under `$PHANTOM_HOME`, `network` needs `--authorized`.

Finding basis: `fact` deterministic check on the input, `heuristic` rule of thumb, `intel` match in a feed you imported.

## URL & Phishing Intelligence (15)

### URL-001 `url.normalize`

Normalize a URL: lowercase host, punycode, default ports, dot segments, percent-encoding case.

- Permission: `none`   Language: python
- Inputs: `url:str, strip_fragment:bool?`  (`?` = optional)
- Outputs: `normalized, host, changes`

### URL-002 `url.parse_components`

Split a URL into scheme, userinfo, host parts, port, path, query pairs and fragment.

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `scheme, host, registrable_domain, subdomain, tld, is_ip, port, path, query_params, fragment, userinfo`

### URL-003 `url.shortener_detect`

Detect known URL-shortener hosts (destination is NOT resolved).

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings`

### URL-004 `url.suspicious_tld`

Flag top-level domains frequently abused in phishing (weak signal).

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings, tld`

### URL-005 `url.ip_host_detect`

Detect IP-literal hosts and decimal/hex/octal obfuscated IPs and decode them.

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings, decoded_ip`

### URL-006 `url.userinfo_trick`

Detect 'trusted.com@evil.com' style userinfo deception.

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings, real_host`

### URL-007 `url.idn_homograph`

Detect punycode, mixed-script and brand-lookalike (homograph) hostnames.

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings, scripts`

### URL-008 `url.brand_impersonation`

Detect brand names or one/two-edit typosquats on non-official domains (built-in brand list).

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings, registrable_domain`

### URL-009 `url.keyword_score`

Count credential/urgency keywords (English and Indonesian) in host, path and query.

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings, keywords`

### URL-010 `url.length_entropy`

Measure URL length and hostname randomness (Shannon entropy).

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings, length, host_entropy`

### URL-011 `url.structure_check`

Check scheme, port, subdomain depth and hyphen patterns.

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings, scheme, port`

### URL-012 `url.redirect_params`

Find query parameters that embed another URL (open-redirect/phishing relay pattern).

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings`

### URL-013 `url.encoding_obfuscation`

Detect double encoding, encoded separators, control characters and backslash tricks.

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `flagged, findings`

### URL-014 `url.phishing_score`

Aggregate all URL heuristics into one 0-100 phishing-likelihood score. Heuristic only; not verified intelligence.

- Permission: `none`   Language: python
- Inputs: `url:str`  (`?` = optional)
- Outputs: `score, label, findings, disclaimer`

### URL-015 `url.batch_triage`

Rank a list of URLs by phishing score (max 500) so the riskiest are reviewed first.

- Permission: `none`   Language: python
- Inputs: `urls:list, min_score:int?`  (`?` = optional)
- Outputs: `ranked, total, failed`

## Domain Intelligence (12)

### DOM-001 `domain.validate`

Validate hostname syntax (RFC 1035/1123 limits) and return its punycode form.

- Permission: `none`   Language: python
- Inputs: `domain:str`  (`?` = optional)
- Outputs: `valid, reasons, ascii`

### DOM-002 `domain.split`

Split a hostname into subdomain, second-level label, suffix and registrable domain (built-in suffix subset).

- Permission: `none`   Language: python
- Inputs: `domain:str`  (`?` = optional)
- Outputs: `subdomain, sld, suffix, registrable, note`

### DOM-003 `domain.idn_codec`

Convert a domain between Unicode and punycode and report scripts used.

- Permission: `none`   Language: python
- Inputs: `domain:str, mode:str?`  (`?` = optional)
- Outputs: `ascii, unicode, scripts, mixed_script`

### DOM-004 `domain.dga_score`

Estimate whether the second-level label looks algorithmically generated (heuristic, 0-100).

- Permission: `none`   Language: python
- Inputs: `domain:str`  (`?` = optional)
- Outputs: `score, label, reasons, findings`

### DOM-005 `domain.typosquat_variants`

Generate likely typosquat/lookalike variants of YOUR domain for defensive monitoring (no lookups performed).

- Permission: `none`   Language: python
- Inputs: `domain:str, limit:int?`  (`?` = optional)
- Outputs: `variants, count, truncated`

### DOM-006 `domain.similarity`

Compare two domains: edit distance, folded-skeleton equality, same label with different TLD.

- Permission: `none`   Language: python
- Inputs: `a:str, b:str`  (`?` = optional)
- Outputs: `edit_distance, similarity, skeleton_equal, same_label_other_tld, findings`

### DOM-007 `domain.tld_profile`

Classify the TLD (country-code, generic, sponsored) and note whether it is abuse-heavy.

- Permission: `none`   Language: python
- Inputs: `domain:str`  (`?` = optional)
- Outputs: `tld, type, abuse_heavy, findings`

### DOM-008 `domain.whois_parse`

Parse raw WHOIS text you supply: registrar, dates, nameservers, status; flag newly registered or expiring domains.

- Permission: `none`   Language: python
- Inputs: `text:str, now:str?`  (`?` = optional)
- Outputs: `registrar, created, expires, updated, age_days, days_to_expiry, nameservers, status, privacy_proxy, findings`

### DOM-009 `domain.lexical_profile`

Raw lexical features of the domain label: length, digits, vowels, consonant runs, hyphens, entropy.

- Permission: `none`   Language: python
- Inputs: `domain:str`  (`?` = optional)
- Outputs: `label, features, findings`

### DOM-010 `domain.subdomain_extract`

Extract subdomains of a target domain from any text (logs, CT exports) and flag exposure-prone names.

- Permission: `none`   Language: python
- Inputs: `domain:str, text:str`  (`?` = optional)
- Outputs: `subdomains, count, interesting, findings`

### DOM-011 `domain.disposable_check`

Check whether an email/domain belongs to a built-in list of disposable-mail providers.

- Permission: `none`   Language: python
- Inputs: `domain:str`  (`?` = optional)
- Outputs: `disposable, registrable, list_size, findings`

### DOM-012 `domain.risk_score`

Combine syntax, DGA, lexical, TLD and brand-lookalike checks into a 0-100 domain risk score (heuristic).

- Permission: `none`   Language: python
- Inputs: `domain:str`  (`?` = optional)
- Outputs: `score, label, findings, disclaimer`

## DNS Analysis (10)

### DNS-001 `dns.query`

Query one record type from a DNS server (UDP, TCP fallback). Network tool: needs authorized=true.

- Permission: `network`   Language: python
- Inputs: `name:str, rtype:str?, server:str?, port:int?, timeout:int?`  (`?` = optional)
- Outputs: `rcode, answers, authority, server, elapsed_ms, retried_over_tcp`

### DNS-002 `dns.packet_decode`

Decode a raw DNS response given as hex (offline), including compressed names.

- Permission: `none`   Language: python
- Inputs: `hex:str`  (`?` = optional)
- Outputs: `rcode, questions, answers, authority, additional, truncated`

### DNS-003 `dns.zone_parse`

Parse zone-file text (BIND style, $ORIGIN/$TTL, parentheses) into records.

- Permission: `none`   Language: python
- Inputs: `text:str, origin:str?`  (`?` = optional)
- Outputs: `records, count, by_type, warnings`

### DNS-004 `dns.spf_analyze`

Analyze an SPF TXT record: qualifiers, +all, lookup count (limit 10), ptr, broad ip4 ranges.

- Permission: `none`   Language: python
- Inputs: `record:str`  (`?` = optional)
- Outputs: `valid, mechanisms, lookup_mechanisms, all_qualifier, findings`

### DNS-005 `dns.dmarc_analyze`

Analyze a DMARC TXT record: policy strength, pct, subdomain policy, reporting URIs, alignment.

- Permission: `none`   Language: python
- Inputs: `record:str`  (`?` = optional)
- Outputs: `valid, tags, policy, findings`

### DNS-006 `dns.dkim_analyze`

Analyze a DKIM selector TXT record: key type, RSA key size, revoked key, testing flag, hash algorithms.

- Permission: `none`   Language: python
- Inputs: `record:str`  (`?` = optional)
- Outputs: `valid, key_type, key_bits, revoked, findings`

### DNS-007 `dns.caa_analyze`

Analyze CAA records (e.g. '0 issue "letsencrypt.org"'): who may issue, wildcard, iodef, critical flag.

- Permission: `none`   Language: python
- Inputs: `records:list`  (`?` = optional)
- Outputs: `parsed, issuers, findings`

### DNS-008 `dns.mx_analyze`

Analyze MX records ('10 mail.example.com.'): null MX, redundancy, IP-literal targets, priority ties.

- Permission: `none`   Language: python
- Inputs: `records:list`  (`?` = optional)
- Outputs: `parsed, null_mx, findings`

### DNS-009 `dns.ttl_analyze`

Review record TTLs for very low/high values and fast-flux-like patterns. records: [{name,type,ttl,data}].

- Permission: `none`   Language: python
- Inputs: `records:list`  (`?` = optional)
- Outputs: `stats, findings`

### DNS-010 `dns.takeover_hint`

Flag CNAMEs pointing at third-party hosting that is commonly claimable; combine with targets you know are NXDOMAIN.

- Permission: `none`   Language: python
- Inputs: `cnames:list, nxdomain_targets:list?`  (`?` = optional)
- Outputs: `checked, candidates, findings`

## TLS & SSL Inspection (10)

### TLS-001 `tls.cert_parse`

Parse a PEM X.509 certificate: subject, issuer, validity, SAN, key, signature algorithm.

- Permission: `none`   Language: python
- Inputs: `pem:str?, path:str?`  (`?` = optional)
- Outputs: `subject, issuer, not_before, not_after, san, key, signature_algorithm, serial, is_ca, self_signed`

### TLS-002 `tls.expiry_check`

Days until certificate expiry; flags expired, not-yet-valid and expiring-soon certificates.

- Permission: `none`   Language: python
- Inputs: `pem:str?, path:str?, warn_days:int?, now:str?`  (`?` = optional)
- Outputs: `days_left, expired, not_yet_valid, findings`

### TLS-003 `tls.hostname_match`

Check whether a hostname is covered by the certificate SAN (wildcards: one left-most label only).

- Permission: `none`   Language: python
- Inputs: `pem:str?, path:str?, hostname:str`  (`?` = optional)
- Outputs: `matches, matched_entry, san, findings`

### TLS-004 `tls.sigalg_check`

Flag MD5/SHA-1 based certificate signatures.

- Permission: `none`   Language: python
- Inputs: `pem:str?, path:str?`  (`?` = optional)
- Outputs: `algorithm, strength, findings`

### TLS-005 `tls.key_strength`

Evaluate public-key type and size (RSA bits / EC curve).

- Permission: `none`   Language: python
- Inputs: `pem:str?, path:str?`  (`?` = optional)
- Outputs: `type, bits, curve, findings`

### TLS-006 `tls.chain_analyze`

Analyze a PEM bundle: leaf first, issuer-to-subject linkage, self-signed root, missing intermediates.

- Permission: `none`   Language: python
- Inputs: `pem:str?, path:str?`  (`?` = optional)
- Outputs: `length, chain, linked, complete, findings`

### TLS-007 `tls.live_handshake`

Connect to host:port, report TLS version, cipher, verification result and certificate. Network tool: authorized=true.

- Permission: `network`   Language: python
- Inputs: `host:str, port:int?, timeout:int?, sni:str?`  (`?` = optional)
- Outputs: `protocol, cipher, verified, verify_error, certificate, pem, findings`

### TLS-008 `tls.protocol_policy`

Evaluate a negotiated protocol/cipher: legacy versions, CBC/RC4/3DES/NULL/EXPORT/anon, missing forward secrecy.

- Permission: `none`   Language: python
- Inputs: `protocol:str, cipher:str?`  (`?` = optional)
- Outputs: `acceptable, findings`

### TLS-009 `tls.fingerprint`

SHA-256/SHA-1/MD5 certificate fingerprints and SPKI SHA-256 (for pinning).

- Permission: `none`   Language: python
- Inputs: `pem:str?, path:str?`  (`?` = optional)
- Outputs: `sha256, sha1, md5, spki_sha256`

### TLS-010 `tls.lifetime_check`

Compare validity length with the 398-day public-CA limit (private CAs are exempt) and report age.

- Permission: `none`   Language: python
- Inputs: `pem:str?, path:str?, now:str?`  (`?` = optional)
- Outputs: `lifetime_days, over_398, age_days, findings`

## HTTP Security Analysis (12)

### HTP-001 `http.headers_audit`

Audit all security headers of a response (HSTS, CSP, framing, nosniff, referrer, permissions, cookies, CORS, disclosure, cache) and grade A-F.

- Permission: `none`   Language: python
- Inputs: `headers:str, https:bool?, sensitive:bool?, origin:str?`  (`?` = optional)
- Outputs: `grade, score, findings, headers_seen`

### HTP-002 `http.hsts_check`

Check Strict-Transport-Security max-age, includeSubDomains and preload eligibility.

- Permission: `none`   Language: python
- Inputs: `headers:str, https:bool?`  (`?` = optional)
- Outputs: `findings`

### HTP-003 `http.csp_analyze`

Analyze Content-Security-Policy for unsafe-inline/eval, wildcards and missing base-uri/object-src/frame-ancestors.

- Permission: `none`   Language: python
- Inputs: `headers:str`  (`?` = optional)
- Outputs: `findings`

### HTP-004 `http.framing_check`

Check clickjacking protection via X-Frame-Options and CSP frame-ancestors.

- Permission: `none`   Language: python
- Inputs: `headers:str`  (`?` = optional)
- Outputs: `findings`

### HTP-005 `http.content_type_check`

Check X-Content-Type-Options nosniff and Content-Type/charset.

- Permission: `none`   Language: python
- Inputs: `headers:str`  (`?` = optional)
- Outputs: `findings`

### HTP-006 `http.referrer_policy_check`

Evaluate the Referrer-Policy value for URL leakage.

- Permission: `none`   Language: python
- Inputs: `headers:str`  (`?` = optional)
- Outputs: `findings`

### HTP-007 `http.permissions_policy_check`

Check Permissions-Policy presence and over-broad feature grants.

- Permission: `none`   Language: python
- Inputs: `headers:str`  (`?` = optional)
- Outputs: `findings`

### HTP-008 `http.cookie_audit`

Audit every Set-Cookie: Secure, HttpOnly, SameSite, __Host-/__Secure- rules, lifetime.

- Permission: `none`   Language: python
- Inputs: `headers:str`  (`?` = optional)
- Outputs: `findings`

### HTP-009 `http.cors_check`

Check CORS headers for wildcard+credentials, null origin, reflected origin and missing Vary.

- Permission: `none`   Language: python
- Inputs: `headers:str, origin:str?`  (`?` = optional)
- Outputs: `findings`

### HTP-010 `http.disclosure_check`

Find version/technology disclosure and debug headers (Server, X-Powered-By, ...).

- Permission: `none`   Language: python
- Inputs: `headers:str`  (`?` = optional)
- Outputs: `findings`

### HTP-011 `http.cache_check`

Check Cache-Control for sensitive responses and cookie+public combinations.

- Permission: `none`   Language: python
- Inputs: `headers:str, sensitive:bool?`  (`?` = optional)
- Outputs: `findings`

### HTP-012 `http.fetch`

Fetch response headers (HEAD by default) with optional bounded redirect following. Network tool: authorized=true.

- Permission: `network`   Language: python
- Inputs: `url:str, method:str?, follow:bool?, max_redirects:int?, timeout:int?, verify_tls:bool?, max_body:int?`  (`?` = optional)
- Outputs: `status, final_url, headers_text, chain, body_bytes_read, tls_verified`

## IP & Network Intelligence (12)

### NET-001 `ip.classify`

Classify an IP: version, private/loopback/link-local/multicast/reserved/CGNAT/global, decode obfuscated notation.

- Permission: `none`   Language: python
- Inputs: `ip:str`  (`?` = optional)
- Outputs: `ip, version, scope, is_global, obfuscated, findings`

### NET-002 `ip.cidr_calc`

Network math for a CIDR: network, mask, broadcast, host range, address count.

- Permission: `none`   Language: python
- Inputs: `cidr:str`  (`?` = optional)
- Outputs: `network, netmask, broadcast, first_host, last_host, num_addresses, prefixlen, version`

### NET-003 `ip.range_match`

Check which of your CIDR ranges contain an IP (most specific first).

- Permission: `none`   Language: python
- Inputs: `ip:str, cidrs:list`  (`?` = optional)
- Outputs: `matches, matched`

### NET-004 `ip.reverse_pointer`

IP to reverse-DNS name (in-addr.arpa / ip6.arpa) and back.

- Permission: `none`   Language: python
- Inputs: `value:str`  (`?` = optional)
- Outputs: `direction, result`

### NET-005 `ip.prefix_lookup`

Longest-prefix match of an IP against a prefix table you supply (CSV: cidr,asn,org). Offline; no bundled data.

- Permission: `none`   Language: python
- Inputs: `ip:str, table:str`  (`?` = optional)
- Outputs: `matched, prefix, asn, org, rows_loaded`

### NET-006 `ip.blocklist_match`

Match IPs against a local blocklist (one IP/CIDR per line, # comments). The result is a local-list match, not live reputation.

- Permission: `none`   Language: python
- Inputs: `ips:list, blocklist:str`  (`?` = optional)
- Outputs: `hits, checked, findings`

### NET-007 `net.port_map`

Map port numbers to services and rate the risk of exposing them to the Internet.

- Permission: `none`   Language: python
- Inputs: `ports:list`  (`?` = optional)
- Outputs: `ports, findings`

### NET-008 `net.tcp_probe`

TCP connect check (no payload) for up to 20 ports on a host you are authorized to test. Network tool: authorized=true.

- Permission: `network`   Language: python
- Inputs: `host:str, ports:list, timeout:int?`  (`?` = optional)
- Outputs: `host, results, open_ports, findings`

### NET-009 `net.banner_parse`

Extract product/version from a service banner and flag known end-of-life branches (verify with vendor advisories).

- Permission: `none`   Language: python
- Inputs: `banner:str`  (`?` = optional)
- Outputs: `products, findings`

### NET-010 `ip.cidr_summarize`

Collapse a list of IPs/CIDRs into the minimal set of CIDR blocks.

- Permission: `none`   Language: python
- Inputs: `items:list`  (`?` = optional)
- Outputs: `summary, input_count, output_count`

### NET-011 `net.log_ip_extract`

Extract IPs from log text, count them, rank the top talkers and classify scope.

- Permission: `none`   Language: python
- Inputs: `text:str, top:int?`  (`?` = optional)
- Outputs: `unique, total, top, by_scope`

### NET-012 `net.request_burst_detect`

Find IPs that exceed N requests inside a time window in access-log text (defensive anomaly detection).

- Permission: `none`   Language: python
- Inputs: `text:str, threshold:int?, window_seconds:int?`  (`?` = optional)
- Outputs: `offenders, lines_parsed, findings`

## File Security Analysis (10)

### FIL-001 `file.hash`

Compute MD5, SHA-1, SHA-256 and SHA-512 of a file (streamed) for lookup or integrity checks.

- Permission: `none`   Language: python
- Inputs: `path:str, algorithms:list?`  (`?` = optional)
- Outputs: `size, hashes`

### FIL-002 `file.type_detect`

Identify the real file type from magic bytes instead of trusting the extension.

- Permission: `none`   Language: python
- Inputs: `path:str`  (`?` = optional)
- Outputs: `type, mime, category, size`

### FIL-003 `file.extension_check`

Compare the declared extension with the real type; detect double extensions, RTLO and executable disguises.

- Permission: `none`   Language: python
- Inputs: `path:str`  (`?` = optional)
- Outputs: `extension, detected_type, detected_category, mismatch, findings`

### FIL-004 `file.entropy`

Shannon entropy of the whole file and per 4 KiB block (sampled for big files); high entropy suggests packing or encryption.

- Permission: `none`   Language: python
- Inputs: `path:str, block_size:int?`  (`?` = optional)
- Outputs: `size, entropy, block_max, block_avg, high_entropy_ratio, findings`

### FIL-005 `file.strings`

Extract printable ASCII and UTF-16LE strings and report which suspicious command/API names appear.

- Permission: `none`   Language: python
- Inputs: `path:str, min_length:int?, limit:int?`  (`?` = optional)
- Outputs: `ascii_count, utf16_count, sample, suspicious, findings`

### FIL-006 `file.ioc_extract`

Extract indicators from a file: URLs, IPv4s, domains, emails, MD5/SHA1/SHA256 hashes and CVE IDs (optionally defanged).

- Permission: `none`   Language: python
- Inputs: `path:str, defanged:bool?`  (`?` = optional)
- Outputs: `urls, ips, domains, emails, hashes, cves, counts`

### FIL-007 `file.pe_analyze`

Parse a Windows PE header: machine, sections with entropy, ASLR/DEP/CFG flags, W+X sections, timestamp anomalies.

- Permission: `none`   Language: python
- Inputs: `path:str`  (`?` = optional)
- Outputs: `machine, is_dll, sections, aslr, dep, cfg, timestamp, entry_rva, findings`

### FIL-008 `file.elf_analyze`

Parse an ELF header: class, endianness, type, machine, PIE, executable stack and RELRO protections.

- Permission: `none`   Language: python
- Inputs: `path:str`  (`?` = optional)
- Outputs: `bits, endian, type, machine, pie, nx_stack, relro, interpreter, findings`

### FIL-009 `file.archive_inspect`

List a ZIP/TAR archive WITHOUT extracting: zip-bomb ratio, path traversal, symlinks, encrypted entries, executables inside.

- Permission: `none`   Language: python
- Inputs: `path:str`  (`?` = optional)
- Outputs: `format, entries, total_uncompressed, ratio, encrypted, suspicious_names, executables, findings`

### FIL-010 `file.document_indicators`

Count risky features in PDF, OOXML, RTF and legacy OLE documents (JavaScript, auto-open, macros, external templates, embedded objects).

- Permission: `none`   Language: python
- Inputs: `path:str`  (`?` = optional)
- Outputs: `format, indicators, findings`

## Email Security Analysis (8)

### EML-001 `email.address_validate`

Validate an email address (length limits, domain syntax, IDN) and flag disposable providers.

- Permission: `none`   Language: python
- Inputs: `address:str`  (`?` = optional)
- Outputs: `valid, local, domain, normalized, issues, findings`

### EML-002 `email.header_parse`

Parse raw email headers: decoded From/To/Subject/Date, Message-ID, Return-Path, Reply-To, hop count; flag missing basics.

- Permission: `none`   Language: python
- Inputs: `raw:str`  (`?` = optional)
- Outputs: `from, to, subject, date, message_id, return_path, reply_to, received_count, auth_results, findings`

### EML-003 `email.auth_results`

Parse Authentication-Results (spf/dkim/dmarc/arc) and flag failures or missing mechanisms.

- Permission: `none`   Language: python
- Inputs: `raw:str`  (`?` = optional)
- Outputs: `results, domains, findings`

### EML-004 `email.received_chain`

Analyze Received headers: hops, per-hop delay, out-of-order timestamps, long delays, hop count.

- Permission: `none`   Language: python
- Inputs: `raw:str`  (`?` = optional)
- Outputs: `hops, total_delay_seconds, findings`

### EML-005 `email.sender_mismatch`

Compare From, Return-Path and Reply-To domains and check display names that impersonate a brand or another address.

- Permission: `none`   Language: python
- Inputs: `raw:str`  (`?` = optional)
- Outputs: `from_address, from_domain, return_path_domain, reply_to_domain, display_name, findings`

### EML-006 `email.link_analyze`

Extract links from an HTML/text email body, compare visible text with the real target, and score each URL (never visited).

- Permission: `none`   Language: python
- Inputs: `body:str`  (`?` = optional)
- Outputs: `links, findings`

### EML-007 `email.attachment_risk`

Rate attachment file names (and optional content types) for dangerous extensions, double extensions and macro formats.

- Permission: `none`   Language: python
- Inputs: `filenames:list, content_types:list?`  (`?` = optional)
- Outputs: `attachments, findings`

### EML-008 `email.content_score`

Score email text for phishing language: urgency, credential requests, payment pressure, shouting, generic greeting (English + Indonesian).

- Permission: `none`   Language: python
- Inputs: `subject:str?, body:str`  (`?` = optional)
- Outputs: `score, label, signals, findings`

## Threat Intelligence (6)

### INT-001 `intel.ioc_classify`

Detect the type of each indicator (IPv4/IPv6/domain/URL/hash/email/CVE), accepting defanged input.

- Permission: `none`   Language: python
- Inputs: `iocs:list`  (`?` = optional)
- Outputs: `classified, counts`

### INT-002 `intel.defang_refang`

Defang indicators for safe sharing (hxxp, [.]) or restore them to normal form.

- Permission: `none`   Language: python
- Inputs: `text:str, mode:str?`  (`?` = optional)
- Outputs: `result, changed`

### INT-003 `intel.feed_import`

Import a local IOC list (lines: ioc[,label[,source]]) into PHANTOM's local feed store under a name you choose.

- Permission: `file-write`   Language: python
- Inputs: `path:str, name:str`  (`?` = optional)
- Outputs: `name, count, types, stored_at`

### INT-004 `intel.feed_lookup`

Look up indicators in your imported feeds. A match is a fact about YOUR feed, not an independent verdict.

- Permission: `file-read`   Language: python
- Inputs: `iocs:list, feed:str?`  (`?` = optional)
- Outputs: `matches, checked, feeds_searched, findings`

### INT-005 `intel.cvss_calc`

Compute the CVSS v3.0/v3.1 base score and severity from a vector string.

- Permission: `none`   Language: python
- Inputs: `vector:str`  (`?` = optional)
- Outputs: `base_score, severity, impact, exploitability, metrics`

### INT-006 `intel.attack_map`

Map free-text observations to candidate MITRE ATT&CK technique IDs using a built-in keyword table (heuristic leads, verify manually).

- Permission: `none`   Language: python
- Inputs: `text:str`  (`?` = optional)
- Outputs: `techniques, count, findings`

## Security Reporting (5)

### RPT-001 `report.build`

Assemble tool results into one report (severity totals, tool list, disclaimer) and optionally save it locally.

- Permission: `file-write`   Language: python
- Inputs: `title:str, results:list, target:str?, save:bool?`  (`?` = optional)
- Outputs: `id, title, created, summary, findings, tools, saved_to, disclaimer`

### RPT-002 `report.render_txt`

Render a report object as plain text.

- Permission: `none`   Language: python
- Inputs: `report:dict`  (`?` = optional)
- Outputs: `text`

### RPT-003 `report.render_html`

Render a report as a self-contained dark HTML page (all values escaped, no scripts, no external resources).

- Permission: `none`   Language: python
- Inputs: `report:dict`  (`?` = optional)
- Outputs: `html, bytes`

### RPT-004 `report.list`

List saved reports (newest first) with severity totals.

- Permission: `file-read`   Language: python
- Inputs: `limit:int?`  (`?` = optional)
- Outputs: `reports, total`

### RPT-005 `report.show`

Load a saved report by ID and return it as JSON, text or HTML.

- Permission: `file-read`   Language: python
- Inputs: `id:str, format:str?`  (`?` = optional)
- Outputs: `report, rendered`

