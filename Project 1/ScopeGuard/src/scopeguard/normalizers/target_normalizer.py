import ipaddress
from urllib.parse import urlparse

from ..models.target import Target


class TargetNormalizer:
    """
    Normalize a concrete execution target.

    ScopeGuard accepts:
    - hostnames
    - HTTP/HTTPS URLs
    - IPv4 addresses
    - IPv6 addresses

    ScopeGuard does not accept:
    - wildcard targets
    - CIDR targets
    - hostname/path combinations
    """

    def normalize(self, raw_value: str) -> Target:
        if not isinstance(raw_value, str):
            raise ValueError("Target must be a string")

        value = raw_value.strip()

        if not value:
            raise ValueError("Target cannot be empty")

        if value.startswith("*."):
            raise ValueError("Wildcard targets are not supported")

        if self._looks_like_url(value):
            return Target(
                raw_value=raw_value,
                normalized_value=self._normalize_url(value),
                type="url",
            )

        if self._looks_like_ipv4(value):
            return Target(
                raw_value=raw_value,
                normalized_value=self._normalize_ip(
                    value,
                    expected_version=4,
                ),
                type="ipv4",
            )

        if self._looks_like_ipv6(value):
            return Target(
                raw_value=raw_value,
                normalized_value=self._normalize_ip(
                    value,
                    expected_version=6,
                ),
                type="ipv6",
            )

        if "/" in value:
            raise ValueError(
                "CIDR or path-based target is not supported"
            )

        return Target(
            raw_value=raw_value,
            normalized_value=self._normalize_hostname(value),
            type="hostname",
        )

    def _looks_like_url(self, value: str) -> bool:
        try:
            parsed = urlparse(value)
        except ValueError:
            return False

        return parsed.scheme.lower() in {
            "http",
            "https",
        }

    def _looks_like_ipv4(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False

        return address.version == 4

    def _looks_like_ipv6(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False

        return address.version == 6

    def _normalize_ip(
        self,
        value: str,
        *,
        expected_version: int,
    ) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(
                "Invalid IP address"
            ) from exc

        if address.version != expected_version:
            raise ValueError(
                f"Expected IPv{expected_version} address"
            )

        return str(address)

    def _normalize_url(self, value: str) -> str:
        try:
            parsed = urlparse(value)
        except ValueError as exc:
            raise ValueError("Invalid URL") from exc

        scheme = parsed.scheme.lower()

        if scheme not in {"http", "https"}:
            raise ValueError(
                "URL must use http or https"
            )

        if parsed.username is not None:
            raise ValueError(
                "URL credentials are not supported"
            )

        if parsed.password is not None:
            raise ValueError(
                "URL credentials are not supported"
            )

        hostname = parsed.hostname

        if hostname is None:
            raise ValueError(
                "URL must contain a hostname"
            )

        hostname = hostname.rstrip(".").lower()

        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(
                "URL contains an invalid port"
            ) from exc

        # Default HTTP ports are canonicalized away.
        if (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        ):
            port = None

        if ":" in hostname:
            netloc = (
                f"[{hostname}]"
                if port is None
                else f"[{hostname}]:{port}"
            )
        else:
            netloc = (
                hostname
                if port is None
                else f"{hostname}:{port}"
            )

        normalized = f"{scheme}://{netloc}"

        normalized += parsed.path

        if parsed.query:
            normalized += f"?{parsed.query}"

        if parsed.fragment:
            normalized += f"#{parsed.fragment}"

        return normalized

    def _normalize_hostname(self, value: str) -> str:
        normalized = value.strip().rstrip(".").lower()

        if not normalized:
            raise ValueError(
                "Hostname cannot be empty"
            )

        return normalized