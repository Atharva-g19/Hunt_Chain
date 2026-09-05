import ipaddress
from urllib.parse import urlparse

from ..models.target import Target


class TargetNormalizer:
    def normalize(self, raw_value: str) -> Target:
        if not isinstance(raw_value, str):
            raise ValueError(
                "Target must be a string"
            )

        value = raw_value.strip()

        if not value:
            raise ValueError(
                "Target cannot be empty"
            )

        if value.startswith("*."):
            raise ValueError(
                "Wildcard targets are not supported"
            )

        if "/" in value and not self._looks_like_url(value):
            raise ValueError(
                "CIDR or path-based target is not supported"
            )

        if self._looks_like_url(value):
            normalized = self._normalize_url(value)

            return Target(
                raw_value=raw_value,
                normalized_value=normalized,
                type="url",
            )

        if self._looks_like_ipv4(value):
            normalized = self._normalize_ipv4(value)

            return Target(
                raw_value=raw_value,
                normalized_value=normalized,
                type="ipv4",
            )

        if self._looks_like_ipv6(value):
            raise ValueError(
                "IPv6 targets are not supported in V1"
            )

        normalized = self._normalize_hostname(value)

        return Target(
            raw_value=raw_value,
            normalized_value=normalized,
            type="hostname",
        )

    def _looks_like_url(self, value: str) -> bool:
        parsed = urlparse(value)

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

    def _normalize_url(self, value: str) -> str:
        parsed = urlparse(value)

        scheme = parsed.scheme.lower()
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

        if port is None:
            netloc = hostname
        else:
            netloc = f"{hostname}:{port}"

        normalized = f"{scheme}://{netloc}"

        if parsed.path:
            normalized += parsed.path

        if parsed.query:
            normalized += f"?{parsed.query}"

        if parsed.fragment:
            normalized += f"#{parsed.fragment}"

        return normalized

    def _normalize_ipv4(self, value: str) -> str:
        address = ipaddress.ip_address(value)

        return str(address)

    def _normalize_hostname(self, value: str) -> str:
        return value.rstrip(".").lower()