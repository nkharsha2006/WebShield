
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from app.security_checks import analyze_security_headers


url = "http://127.0.0.1:3000/"

request = Request(
    url,
    method="GET",
    headers={"User-Agent": "WebShield-Local-Test/1.0"},
)

try:
    with urlopen(request, timeout=5) as response:
        status_code = response.status
        headers = response.headers

except HTTPError as exc:
    status_code = exc.code
    headers = exc.headers

except URLError as exc:
    raise SystemExit(
        f"Could not connect to the local test server: {exc.reason}"
    )

result = analyze_security_headers(
    url=url,
    status_code=status_code,
    headers=headers,
)

print("Target:", result["target_url"])
print("HTTP status:", result["http_status"])
print("Findings detected:", result["findings_count"])
print("Source: actual HTTP response headers")
print()

for finding in result["findings"]:
    print(f"[{finding['severity']}] {finding['title']}")
    print("  Evidence:", finding["evidence"])
    print("  Remediation:", finding["remediation"])
    print()
