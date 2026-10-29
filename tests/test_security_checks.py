from app.security_checks import analyze_security_headers

TARGET_URL = "http://127.0.0.1:3000/"


def get_titles(result):
    return {finding["title"] for finding in result["findings"]}


def test_missing_security_headers_are_detected():
    """Missing security headers should produce the expected findings."""
    result = analyze_security_headers(
        url=TARGET_URL,
        status_code=200,
        headers={
            "Server": "TestServer/1.0",
            "Content-Type": "text/html",
        },
    )

    titles = get_titles(result)

    assert result["http_status"] == 200
    assert result["findings_count"] == len(result["findings"])
    assert "X-Content-Type-Options Header Missing" in titles
    assert "Content Security Policy (CSP) Header Not Set" in titles
    assert "Missing Clickjacking Protection" in titles


def test_x_content_type_options_header_is_recognized():
    """The checker should not report the header as missing when present."""
    result = analyze_security_headers(
        url=TARGET_URL,
        status_code=200,
        headers={
            "Server": "TestServer/1.0",
            "Content-Type": "text/html",
            "X-Content-Type-Options": "nosniff",
        },
    )

    titles = get_titles(result)

    assert "X-Content-Type-Options Header Missing" not in titles


def test_https_url_is_not_reported_as_http_only():
    """An HTTPS target should not receive the HTTP-only finding."""
    result = analyze_security_headers(
        url="https://127.0.0.1:3000/",
        status_code=200,
        headers={
            "Content-Type": "text/html",
            "X-Content-Type-Options": "nosniff",
        },
    )

    titles = get_titles(result)

    assert "HTTPS Not Used" not in titles
