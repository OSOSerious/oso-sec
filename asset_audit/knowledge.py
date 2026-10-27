"""Knowledge base: curated CVE ranges, exposure probes, security headers.
All CVE entries carry version ranges — the 0-FP gate depends on it."""

CVE_MAP = {
    "wordpress": [
        {"cve": "CVE-2017-5487", "name": "WP REST API user enumeration", "from": "1.0", "to": "4.7.1", "sev": "MEDIUM"},
        {"cve": "CVE-2019-8942", "name": "WP core stored XSS via post slugs", "from": "1.0", "to": "5.0.0", "sev": "MEDIUM"},
        {"cve": "CVE-2019-8943", "name": "WP core directory traversal (media delete)", "from": "1.0", "to": "5.0.0", "sev": "HIGH"},
        {"cve": "CVE-2016-10033", "name": "PHPMailer RCE (bundled < WP 4.7.1)", "from": "1.0", "to": "4.7.0", "sev": "CRITICAL"},
        {"cve": "CVE-2015-5714", "name": "WP core XSS via shortcode", "from": "1.0", "to": "4.3.1", "sev": "MEDIUM"},
    ],
    "drupal": [
        {"cve": "CVE-2018-7600", "name": "Drupalgeddon2 — RCE", "from": "6.0", "to": "8.5.0", "sev": "CRITICAL"},
        {"cve": "CVE-2018-7602", "name": "Drupalgeddon3 — RCE", "from": "7.0", "to": "8.5.5", "sev": "CRITICAL"},
        {"cve": "CVE-2019-6340", "name": "Drupal core RCE via REST", "from": "8.0", "to": "8.6.9", "sev": "CRITICAL"},
    ],
    "joomla": [
        {"cve": "CVE-2015-8562", "name": "Joomla PHP object injection RCE", "from": "1.5", "to": "3.4.5", "sev": "CRITICAL"},
        {"cve": "CVE-2023-23752", "name": "Joomla unauth info disclosure", "from": "1.0", "to": "4.2.7", "sev": "HIGH"},
    ],
    "nginx": [
        {"cve": "CVE-2017-7529", "name": "nginx integer overflow info disclosure", "from": "1.0", "to": "1.13.2", "sev": "MEDIUM"},
        {"cve": "CVE-2021-23017", "name": "nginx DNS resolver off-by-one RCE", "from": "0.6.18", "to": "1.21.0", "sev": "HIGH"},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "name": "Apache path traversal/RCE (2.4.49)", "from": "2.4.49", "to": "2.4.49", "sev": "CRITICAL"},
        {"cve": "CVE-2021-42013", "name": "Apache path traversal/RCE (2.4.50)", "from": "2.4.50", "to": "2.4.50", "sev": "CRITICAL"},
    ],
    "php": [
        {"cve": "CVE-2019-11043", "name": "PHP-FPM underflow RCE", "from": "7.1", "to": "7.3.10", "sev": "CRITICAL"},
        {"cve": "CVE-2024-4577", "name": "PHP-CGI argument injection RCE", "from": "5.0", "to": "8.3.7", "sev": "CRITICAL"},
    ],
    "tomcat": [
        {"cve": "CVE-2017-12615", "name": "Tomcat PUT RCE", "from": "7.0.0", "to": "8.5.22", "sev": "CRITICAL"},
        {"cve": "CVE-2020-1938", "name": "Ghostcat — AJP file read", "from": "6.0", "to": "9.0.30", "sev": "HIGH"},
    ],
    "express": [
        {"cve": "CVE-2024-29041", "name": "Express open redirect", "from": "4.0.0", "to": "4.19.1", "sev": "MEDIUM"},
        {"cve": "CVE-2024-43796", "name": "Express XSS via response.redirect", "from": "4.0.0", "to": "4.20.0", "sev": "MEDIUM"},
    ],
    "nextjs": [
        {"cve": "CVE-2024-34351", "name": "Next.js SSRF via Server Actions", "from": "10.0.0", "to": "14.1.1", "sev": "HIGH"},
        {"cve": "CVE-2025-29927", "name": "Next.js middleware auth bypass", "from": "10.0.0", "to": "14.2.24", "sev": "HIGH"},
    ],
}

CONFIG_PROBES = [
    ("/.git/HEAD", "exposed .git directory (source disclosure)", lambda b: b.startswith("ref:")),
    # .env validator hardened 2026-10-27: Shopify/SPA catch-all routes return HTML
    # with '=' and 'KEY'/'PASS' in JS, tripping the old check. A real env file has
    # multiple KEY=VALUE lines and no HTML markup.
    ("/.env", "exposed .env file (credential disclosure)",
     lambda b: "<" not in b[:500].lstrip()
               and sum(1 for ln in b.splitlines() if "=" in ln and not ln.strip().startswith("#")) >= 3),
    ("/wp-config.php.bak", "WordPress config backup exposed", lambda b: "DB_" in b),
    ("/.htaccess.bak", "htaccess backup exposed", lambda b: "Rewrite" in b or "Auth" in b),
    ("/backup.zip", "backup archive in webroot", lambda b: b[:2] == "PK"),
    ("/server-status", "Apache server-status exposed", lambda b: "Apache Status" in b or "<title>Apache" in b),
]

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-content-type-options",
    "x-frame-options", "referrer-policy", "permissions-policy",
]

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
