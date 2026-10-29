
import logging
import os
from urllib.parse import urlsplit

import requests


logger = logging.getLogger(__name__)

DEFAULT_ZAP_URL = "https://127.0.0.1:8080"
REQUEST_TIMEOUT = 15

# Conservative limits for the local Juice Shop lab.
SPIDER_MAX_CHILDREN = 5
SPIDER_MAX_DEPTH = 5


class ZapClientError(RuntimeError):
    """Raised when a ZAP API request fails."""


class ZapClient:
    """Client for a local OWASP ZAP API instance."""

    def __init__(self):
        self.base_url = os.getenv(
            "ZAP_API_URL", DEFAULT_ZAP_URL
        ).rstrip("/")

        self.api_key = os.getenv("ZAP_API_KEY", "")

        verify_setting = os.getenv(
            "ZAP_API_VERIFY_TLS", "true"
        ).lower()

        if verify_setting not in {"true", "false"}:
            raise ZapClientError(
                "ZAP_API_VERIFY_TLS must be 'true' or 'false'."
            )

        self.verify_tls = verify_setting == "true"

        parsed = urlsplit(self.base_url)

        try:
            port = parsed.port
        except ValueError as exc:
            raise ZapClientError("Invalid ZAP API port.") from exc

        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or port is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ZapClientError(
                "ZAP API must use a local HTTP(S) address and explicit port."
            )

        if not self.api_key:
            raise ZapClientError(
                "ZAP_API_KEY environment variable is not set."
            )

        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = self.verify_tls

    def _get(self, component, section, operation, params=None):
        """Send a ZAP API request without exposing credentials in logs."""
        endpoint = (
            f"{self.base_url}/JSON/{component}/{section}/{operation}/"
        )

        request_params = dict(params or {})
        request_params["apikey"] = self.api_key

        try:
            response = self.session.get(
                endpoint,
                params=request_params,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )

            if not response.ok:
                # Never log the request URL: it can contain the API key.
                safe_body = response.text[:500]
                if self.api_key:
                    safe_body = safe_body.replace(
                        self.api_key, "[REDACTED]"
                    )

                logger.warning(
                    "ZAP HTTP error: endpoint=%s/%s/%s, status=%s, "
                    "response=%s",
                    component,
                    section,
                    operation,
                    response.status_code,
                    safe_body,
                )

                response.raise_for_status()

            data = response.json()

        except requests.RequestException as exc:
            # Do not use str(exc): HTTP errors can include the request URL.
            logger.warning(
                "ZAP request failed: endpoint=%s/%s/%s, error_type=%s",
                component,
                section,
                operation,
                type(exc).__name__,
            )

            raise ZapClientError(
                f"ZAP request failed for {component}/{section}/{operation}: "
                f"{type(exc).__name__}."
            ) from exc

        except ValueError as exc:
            logger.warning(
                "ZAP returned invalid JSON: endpoint=%s/%s/%s",
                component,
                section,
                operation,
            )

            raise ZapClientError(
                f"ZAP returned invalid JSON for "
                f"{component}/{section}/{operation}."
            ) from exc

        if not isinstance(data, dict):
            raise ZapClientError("Unexpected ZAP response format.")

        if "code" in data and "message" in data:
            error_code = str(data.get("code", "unknown"))[:100]
            error_message = str(
                data.get("message", "Unknown ZAP error")
            )[:500]

            if self.api_key:
                error_message = error_message.replace(
                    self.api_key, "[REDACTED]"
                )

            logger.warning(
                "ZAP API error: endpoint=%s/%s/%s, code=%s, message=%s",
                component,
                section,
                operation,
                error_code,
                error_message,
            )

            raise ZapClientError(
                f"ZAP API error at {component}/{section}/{operation}: "
                f"{error_code} - {error_message}"
            )

        return data

    @staticmethod
    def validate_target(base_url):
        """Accept only local HTTP(S) lab targets."""
        try:
            parsed = urlsplit(base_url)
            _ = parsed.port
        except (TypeError, ValueError) as exc:
            raise ZapClientError(
                "Invalid target URL or port."
            ) from exc

        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ZapClientError(
                "Only local lab targets are permitted."
            )

        return base_url

    @staticmethod
    def _scan_id(data):
        scan_id = data.get("scan")

        if scan_id is None or not str(scan_id).isdigit():
            raise ZapClientError(
                "ZAP did not return a valid scan ID."
            )

        return str(scan_id)

    def get_version(self):
        data = self._get("core", "view", "version")
        version = data.get("version")

        if not isinstance(version, str):
            raise ZapClientError(
                "ZAP did not return its version."
            )

        return version

    def start_spider(self, base_url):
        """Start a depth-limited, non-recursive Spider scan."""
        target = self.validate_target(base_url)

        data = self._get(
            "spider",
            "action",
            "scan",
            {
                "url": target,
                "maxChildren": SPIDER_MAX_CHILDREN,
                "maxDepth": SPIDER_MAX_DEPTH,
                "recurse": "false",
            },
        )

        return self._scan_id(data)

    def get_spider_status(self, scan_id):
        data = self._get(
            "spider",
            "view",
            "status",
            {"scanId": scan_id},
        )

        return self._progress(data)

    def start_active_scan(self, base_url):
        """Start an Active Scan on an explicitly permitted local target."""
        target = self.validate_target(base_url)

        data = self._get(
            "ascan",
            "action",
            "scan",
            {
                "url": target,
                "recurse": "false",
            },
        )

        return self._scan_id(data)

    def get_active_scan_status(self, scan_id):
        data = self._get(
            "ascan",
            "view",
            "status",
            {"scanId": scan_id},
        )

        return self._progress(data)

    @staticmethod
    def _progress(data):
        value = data.get("status")

        try:
            progress = int(value)
        except (TypeError, ValueError) as exc:
            raise ZapClientError(
                "ZAP returned an invalid scan progress value."
            ) from exc

        if not 0 <= progress <= 100:
            raise ZapClientError(
                "ZAP scan progress is out of range."
            )

        return progress

    def get_alerts(self, base_url=None, start=0, count=100):
        """Retrieve a page of ZAP alerts, optionally filtered by local target."""
        if start < 0 or count < 1 or count > 1000:
            raise ValueError(
                "Invalid alert pagination values."
            )

        params = {
            "start": start,
            "count": count,
        }

        if base_url is not None:
            params["baseurl"] = self.validate_target(base_url)

        data = self._get(
            "alert",
            "view",
            "alerts",
            params,
        )

        alerts = data.get("alerts")

        if not isinstance(alerts, list):
            raise ZapClientError(
                "ZAP did not return an alerts list."
            )

        return alerts

