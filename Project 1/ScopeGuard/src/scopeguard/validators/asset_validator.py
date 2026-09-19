import ipaddress
import re
from urllib.parse import urlparse

from ..models.asset_type import AssetType
from .errors import ScopeValidationError


_HOSTNAME_LABEL = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


class AssetValidator:
    def validate(self, asset) -> None:
        if asset is None:
            raise ScopeValidationError(
                "Asset cannot be None"
            )

        if asset.type == AssetType.HOSTNAME:
            self._validate_hostname(asset.value)

        elif asset.type == AssetType.HOST_WILDCARD:
            self._validate_host_wildcard(asset.value)

        elif asset.type == AssetType.URL:
            self._validate_url(asset.value)

        elif asset.type == AssetType.URL_PATH_WILDCARD:
            self._validate_url_path_wildcard(
                asset.value
            )

        elif asset.type == AssetType.IPV4:
            self._validate_ipv4(asset.value)

        elif asset.type == AssetType.IPV4_CIDR:
            self._validate_ipv4_cidr(asset.value)

        elif asset.type == AssetType.IPV6:
            self._validate_ipv6(asset.value)

        elif asset.type == AssetType.IPV6_CIDR:
            self._validate_ipv6_cidr(asset.value)

        else:
            raise ScopeValidationError(
                f"Unsupported asset type: {asset.type}"
            )

    def _validate_hostname(self, value: str) -> None:
        if not isinstance(value, str):
            raise ScopeValidationError(
                "Hostname must be a string"
            )

        value = value.strip()

        if not value:
            raise ScopeValidationError(
                "Hostname cannot be empty"
            )

        if "://" in value:
            raise ScopeValidationError(
                "Hostname must not contain a URL scheme"
            )

        if "/" in value:
            raise ScopeValidationError(
                "Hostname must not contain a path"
            )

        if ":" in value:
            raise ScopeValidationError(
                "Hostname must not contain a port"
            )

        if "*" in value:
            raise ScopeValidationError(
                "Hostname cannot contain wildcards"
            )

        value = value.rstrip(".")

        if len(value) > 253:
            raise ScopeValidationError(
                "Hostname is too long"
            )

        labels = value.split(".")

        if any(not label for label in labels):
            raise ScopeValidationError(
                "Hostname contains an empty label"
            )

        for label in labels:
            if len(label) > 63:
                raise ScopeValidationError(
                    "Hostname label is too long"
                )

            if not _HOSTNAME_LABEL.fullmatch(label):
                raise ScopeValidationError(
                    "Hostname contains invalid characters"
                )

    def _validate_host_wildcard(self, value: str) -> None:
        if not isinstance(value, str):
            raise ScopeValidationError(
                "Host wildcard must be a string"
            )

        value = value.strip()

        if not value.startswith("*."):
            raise ScopeValidationError(
                "Host wildcard must start with '*.'"
            )

        if value.count("*") != 1:
            raise ScopeValidationError(
                "Host wildcard can contain only one '*'"
            )

        hostname = value[2:]

        self._validate_hostname(hostname)

    def _validate_url(self, value: str) -> None:
        if not isinstance(value, str):
            raise ScopeValidationError(
                "URL must be a string"
            )

        try:
            parsed = urlparse(value)
        except ValueError as exc:
            raise ScopeValidationError(
                "Invalid URL"
            ) from exc

        if parsed.scheme.lower() not in {
            "http",
            "https",
        }:
            raise ScopeValidationError(
                "URL must use http or https"
            )

        if parsed.username is not None:
            raise ScopeValidationError(
                "URL credentials are not supported"
            )

        if parsed.password is not None:
            raise ScopeValidationError(
                "URL credentials are not supported"
            )

        if not parsed.netloc:
            raise ScopeValidationError(
                "URL must contain a hostname"
            )

        if "*" in value:
            raise ScopeValidationError(
                "URL cannot contain wildcards"
            )

        hostname = parsed.hostname

        if hostname is None:
            raise ScopeValidationError(
                "URL must contain a valid hostname"
            )

        if self._is_ipv6(hostname):
            pass
        else:
            self._validate_hostname(hostname)

        try:
            port = parsed.port
        except ValueError as exc:
            raise ScopeValidationError(
                "URL contains an invalid port"
            ) from exc

        if port is not None and not 1 <= port <= 65535:
            raise ScopeValidationError(
                "URL port must be between 1 and 65535"
            )

    def _validate_url_path_wildcard(
        self,
        value: str,
    ) -> None:
        if not isinstance(value, str):
            raise ScopeValidationError(
                "URL path wildcard must be a string"
            )

        if value.count("*") != 1:
            raise ScopeValidationError(
                "URL path wildcard can contain only one '*'"
            )

        if not value.endswith("/*"):
            raise ScopeValidationError(
                "URL path wildcard must end with '/*'"
            )

        base_value = value[:-1]

        self._validate_url(base_value)

        parsed = urlparse(base_value)

        if not parsed.path or parsed.path == "/":
            raise ScopeValidationError(
                "URL path wildcard requires a specific path"
            )

    def _validate_ipv4(self, value: str) -> None:
        try:
            address = ipaddress.ip_address(
                value.strip()
            )
        except ValueError as exc:
            raise ScopeValidationError(
                "Invalid IPv4 address"
            ) from exc

        if address.version != 4:
            raise ScopeValidationError(
                "Asset must be an IPv4 address"
            )

    def _validate_ipv4_cidr(self, value: str) -> None:
        if "/" not in value:
            raise ScopeValidationError(
                "IPv4 CIDR must contain a prefix length"
            )

        try:
            network = ipaddress.ip_network(
                value.strip(),
                strict=True,
            )
        except ValueError as exc:
            raise ScopeValidationError(
                "Invalid IPv4 CIDR"
            ) from exc

        if network.version != 4:
            raise ScopeValidationError(
                "Asset must be an IPv4 CIDR"
            )

    def _validate_ipv6(self, value: str) -> None:
        try:
            address = ipaddress.ip_address(
                value.strip()
            )
        except ValueError as exc:
            raise ScopeValidationError(
                "Invalid IPv6 address"
            ) from exc

        if address.version != 6:
            raise ScopeValidationError(
                "Asset must be an IPv6 address"
            )

    def _validate_ipv6_cidr(self, value: str) -> None:
        if "/" not in value:
            raise ScopeValidationError(
                "IPv6 CIDR must contain a prefix length"
            )

        try:
            network = ipaddress.ip_network(
                value.strip(),
                strict=True,
            )
        except ValueError as exc:
            raise ScopeValidationError(
                "Invalid IPv6 CIDR"
            ) from exc

        if network.version != 6:
            raise ScopeValidationError(
                "Asset must be an IPv6 CIDR"
            )

    def _is_ipv6(self, value: str) -> bool:
        try:
            return ipaddress.ip_address(
                value
            ).version == 6
        except ValueError:
            return False