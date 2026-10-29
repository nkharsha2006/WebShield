from urllib.parse import urlsplit


def check_local_url(url):
    """Accept only HTTP or HTTPS URLs on local lab hosts."""
    if not isinstance(url, str):
        raise TypeError("URL must be a string.")

    parsed = urlsplit(url)

    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port.") from exc

    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Only local lab URLs are permitted.")

    return parsed


def analyze_security_headers(url, status_code, headers):
    """
    Analyze HTTP response headers supplied by the caller.
    This function does not make network requests.
    """
    parsed = check_local_url(url)

    if not isinstance(status_code, int) or not 100 <= status_code <= 599:
        raise ValueError("Invalid HTTP status code.")

    normalized = {
        str(name).strip().lower(): str(value).strip() for name, value in headers.items()
    }

    findings = []

    def add_finding(title, severity, description, evidence, remediation):
        findings.append(
            {
                "title": title,
                "severity": severity,
                "affected_url": url,
                "description": description,
                "evidence": evidence,
                "remediation": remediation,
            }
        )

    if parsed.scheme != "https":
        add_finding(
            "HTTPS Not Used",
            "MEDIUM",
            "The target URL uses HTTP rather than HTTPS.",
            f"URL scheme: {parsed.scheme}",
            "Use HTTPS with a valid TLS certificate.",
        )

    if not normalized.get("content-security-policy"):
        add_finding(
            "Content Security Policy (CSP) Header Not Set",
            "MEDIUM",
            "The response does not contain a Content-Security-Policy header.",
            f"HTTP status: {status_code}",
            "Configure a suitable Content-Security-Policy header.",
        )

    if not normalized.get("x-content-type-options"):
        add_finding(
            "X-Content-Type-Options Header Missing",
            "LOW",
            "The response does not contain X-Content-Type-Options.",
            f"HTTP status: {status_code}",
            "Set X-Content-Type-Options: nosniff.",
        )

    csp = normalized.get("content-security-policy", "").lower()
    if not normalized.get("x-frame-options") and "frame-ancestors" not in csp:
        add_finding(
            "Missing Clickjacking Protection",
            "MEDIUM",
            "Neither X-Frame-Options nor CSP frame-ancestors was detected.",
            f"HTTP status: {status_code}",
            "Configure X-Frame-Options or a suitable CSP frame-ancestors directive.",
        )

    server = normalized.get("server", "")
    if server:
        add_finding(
            "Server Header Information Disclosure",
            "LOW",
            "The Server response header may disclose server details.",
            server,
            "Suppress unnecessary server identification information.",
        )

    # Treat each Set-Cookie header separately when the input supports it.
    cookie_headers = [
        str(value)
        for name, value in headers.items()
        if str(name).strip().lower() == "set-cookie"
    ]

    for cookie in cookie_headers:
        cookie_name = cookie.split("=", 1)[0].strip() or "unnamed cookie"
        attributes = {
            part.strip().lower().split("=", 1)[0] for part in cookie.split(";")[1:]
        }

        if parsed.scheme == "https" and "secure" not in attributes:
            add_finding(
                "Cookie Missing Secure Attribute",
                "MEDIUM",
                f"Cookie {cookie_name!r} lacks the Secure attribute.",
                cookie_name,
                "Set Secure on cookies that should only travel over HTTPS.",
            )

        if "httponly" not in attributes:
            add_finding(
                "Cookie Missing HttpOnly Attribute",
                "LOW",
                f"Cookie {cookie_name!r} lacks the HttpOnly attribute.",
                cookie_name,
                "Set HttpOnly when client-side JavaScript does not need the cookie.",
            )

        if "samesite" not in attributes:
            add_finding(
                "Cookie Missing SameSite Attribute",
                "LOW",
                f"Cookie {cookie_name!r} lacks the SameSite attribute.",
                cookie_name,
                "Choose an appropriate SameSite policy for the application.",
            )

    return {
        "target_url": url,
        "http_status": status_code,
        "findings_count": len(findings),
        "findings": findings,
        "note": (
            "These are configuration observations, not proof of exploitable "
            "vulnerabilities. Cookie checks inspect attribute presence only."
        ),
    }
