import ipaddress
from urllib.parse import urlparse

from ..models.asset_type import AssetType
from .errors import ScopeValidationError


class AssetValidator:
    def validate(self, asset) -> None:
        if asset is None:
            raise ScopeValidationError("Asset cannot be None")

        if asset.type == AssetType.HOSTNAME:
            self._validate_hostname(asset.value)

        elif asset.type == AssetType.HOST_WILDCARD:
            self._validate_host_wildcard(asset.value)

        elif asset.type == AssetType.URL:
            self._validate_url(asset.value)

        elif asset.type == AssetType.URL_PATH_WILDCARD:
            self._validate_url_path_wildcard(asset.value)

        elif asset.type == AssetType.IPV4:
            self._validate_ipv4(asset.value)

        elif asset.type == AssetType.IPV4_CIDR:
            self._validate_ipv4_cidr(asset.value)

    def _validate_hostname(self, value: str) -> None:
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

        if value.endswith("."):
            value = value[:-1]

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

            if label.startswith("-") or label.endswith("-"):
                raise ScopeValidationError(
                    "Hostname label cannot start or end with '-'"
                )

            if not all(
                character.isalnum() or character == "-"
                for character in label
            ):
                raise ScopeValidationError(
                    "Hostname contains invalid characters"
                )

    def _validate_host_wildcard(self, value: str) -> None:
        if not value.startswith("*."):
            raise ScopeValidationError(
                "Host wildcard must start with '*.'"
            )

        hostname = value[2:]

        if "*" in hostname:
            raise ScopeValidationError(
                "Host wildcard can contain only one '*'"
            )

        self._validate_hostname(hostname)

    def _validate_url(self, value: str) -> None:
        parsed = urlparse(value)

        if parsed.scheme not in ("http", "https"):
            raise ScopeValidationError(
                "URL must use http or https"
            )

        if not parsed.netloc:
            raise ScopeValidationError(
                "URL must contain a hostname"
            )

        if "*" in value:
            raise ScopeValidationError(
                "URL cannot contain wildcards"
            )

        if parsed.hostname is None:
            raise ScopeValidationError(
                "URL must contain a valid hostname"
            )

        self._validate_hostname(parsed.hostname)

    def _validate_url_path_wildcard(self, value: str) -> None:
        if "*" not in value:
            raise ScopeValidationError(
                "URL path wildcard must contain '*'"
            )

        if value.count("*") != 1:
            raise ScopeValidationError(
                "URL path wildcard can contain only one '*'"
            )

        if not value.endswith("/*"):
            raise ScopeValidationError(
                "URL path wildcard must end with '/*'"
            )

        parsed = urlparse(value[:-1])

        if parsed.scheme not in ("http", "https"):
            raise ScopeValidationError(
                "URL must use http or https"
            )

        if not parsed.netloc:
            raise ScopeValidationError(
                "URL must contain a hostname"
            )

        if parsed.hostname is None:
            raise ScopeValidationError(
                "URL must contain a valid hostname"
            )

        self._validate_hostname(parsed.hostname)

        if not parsed.path or parsed.path == "/":
            raise ScopeValidationError(
                "URL path wildcard requires a specific path"
            )

    def _validate_ipv4(self, value: str) -> None:
        try:
            address = ipaddress.ip_address(value)
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
                value,
                strict=True
            )
        except ValueError as exc:
            raise ScopeValidationError(
                "Invalid IPv4 CIDR"
            ) from exc

        if network.version != 4:
            raise ScopeValidationError(
                "Asset must be an IPv4 CIDR"
            )