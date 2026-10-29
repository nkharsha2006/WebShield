from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent a local target from redirecting the request elsewhere."""

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        return None


def check_local_connectivity(base_url: str) -> dict:
    """Check HTTP connectivity to a loopback-only lab target."""

    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return {
            "reachable": False,
            "http_status": None,
            "elapsed_ms": 0,
            "message": "Invalid URL or port.",
        }

    # Recheck the target at request time as a safety boundary.
    if (
        parsed.scheme not in {"http", "https"}
        or hostname not in {"localhost", "127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return {
            "reachable": False,
            "http_status": None,
            "elapsed_ms": 0,
            "message": "Only local lab URLs are permitted.",
        }

    request = Request(
        base_url,
        headers={"User-Agent": "WebShield-Connectivity-Check/1.0"},
        method="GET",
    )

    opener = build_opener(NoRedirectHandler())
    started = monotonic()

    try:
        with opener.open(request, timeout=5) as response:
            elapsed_ms = round((monotonic() - started) * 1000, 2)

            return {
                "reachable": True,
                "http_status": response.status,
                "elapsed_ms": elapsed_ms,
                "message": "Received an HTTP response from the local target.",
            }

    except HTTPError as exc:
        # An HTTP error such as 404 or 500 still proves that
        # an HTTP server responded.
        elapsed_ms = round((monotonic() - started) * 1000, 2)

        return {
            "reachable": True,
            "http_status": exc.code,
            "elapsed_ms": elapsed_ms,
            "message": (
                "The target responded with an HTTP error status. "
                "This is a connectivity result, not a vulnerability finding."
            ),
        }

    except URLError as exc:
        elapsed_ms = round((monotonic() - started) * 1000, 2)

        return {
            "reachable": False,
            "http_status": None,
            "elapsed_ms": elapsed_ms,
            "message": f"Connection failed: {exc.reason}",
        }

    except TimeoutError:
        elapsed_ms = round((monotonic() - started) * 1000, 2)

        return {
            "reachable": False,
            "http_status": None,
            "elapsed_ms": elapsed_ms,
            "message": "The local target did not respond within 5 seconds.",
        }

    except OSError as exc:
        elapsed_ms = round((monotonic() - started) * 1000, 2)

        return {
            "reachable": False,
            "http_status": None,
            "elapsed_ms": elapsed_ms,
            "message": f"Network or protocol error: {exc}",
        }
