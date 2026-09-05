import ipaddress
from urllib.parse import urlparse

from ..models.asset_type import AssetType
from .errors import ScopeValidationError


class TargetValidator:
    def validate(self, target) -> None:
        if target is None:
            raise ScopeValidationError(
                "Target cannot be None"
            )

        if not target.raw_value:
            raise ScopeValidationError(
                "Target raw value cannot be empty"
            )

        if not target.normalized_value:
            raise ScopeValidationError(
                "Target normalized value cannot be empty"
            )

        if target.type not in {
            AssetType.HOSTNAME.value,
            AssetType.HOST_WILDCARD.value,
            AssetType.URL.value,
            AssetType.URL_PATH_WILDCARD.value,
            AssetType.IPV4.value,
        }:
            raise ScopeValidationError(
                f"Unsupported target type: {target.type}"
            )

        if target.type == AssetType.HOSTNAME.value:
            self._validate_hostname(
                target.normalized_value
            )

        elif target.type == AssetType.HOST_WILDCARD.value:
            self._validate_host_wildcard(
                target.normalized_value
            )

        elif target.type == AssetType.URL.value:
            self._validate_url(
                target.normalized_value
            )

        elif target.type == AssetType.URL_PATH_WILDCARD.value:
            self._validate_url_path_wildcard(
                target.normalized_value
            )

        elif target.type == AssetType.IPV4.value:
            self._validate_ipv4(
                target.normalized_value
            )

    def _validate_hostname(self, value: str) -> None:
        if "://" in value:
            raise ScopeValidationError(
                "Hostname target must not contain a URL scheme"
            )

        if "/" in value:
            raise ScopeValidationError(
                "Hostname target must not contain a path"
            )

        if value.endswith("."):
            value = value[:-1]

        labels = value.split(".")

        if any(not label for label in labels):
            raise ScopeValidationError(
                "Hostname target contains an empty label"
            )

        for label in labels:
            if len(label) > 63:
                raise ScopeValidationError(
                    "Hostname target label is too long"
                )

            if label.startswith("-") or label.endswith("-"):
                raise ScopeValidationError(
                    "Hostname target label cannot start or end with '-'"
                )

            if not all(
                character.isalnum() or character == "-"
                for character in label
            ):
                raise ScopeValidationError(
                    "Hostname target contains invalid characters"
                )

    def _validate_host_wildcard(self, value: str) -> None:
        if not value.startswith("*."):
            raise ScopeValidationError(
                "Host wildcard target must start with '*.'"
            )

        hostname = value[2:]

        if "*" in hostname:
            raise ScopeValidationError(
                "Host wildcard target can contain only one '*'"
            )

        self._validate_hostname(hostname)

    def _validate_url(self, value: str) -> None:
        try:
            parsed = urlparse(value)
        except ValueError as exc:
            raise ScopeValidationError(
                "Invalid URL target"
            ) from exc

        if parsed.scheme not in ("http", "https"):
            raise ScopeValidationError(
                "URL target must use http or https"
            )

        if not parsed.netloc:
            raise ScopeValidationError(
                "URL target must contain a hostname"
            )

        if "*" in value:
            raise ScopeValidationError(
                "URL target cannot contain wildcards"
            )

        if parsed.hostname is None:
            raise ScopeValidationError(
                "URL target must contain a valid hostname"
            )

        self._validate_hostname(parsed.hostname)

        try:
            parsed.port
        except ValueError as exc:
            raise ScopeValidationError(
                "URL target contains an invalid port"
            ) from exc

    def _validate_url_path_wildcard(self, value: str) -> None:
        if "*" not in value:
            raise ScopeValidationError(
                "URL path wildcard target must contain '*'"
            )

        if value.count("*") != 1:
            raise ScopeValidationError(
                "URL path wildcard target can contain only one '*'"
            )

        if not value.endswith("/*"):
            raise ScopeValidationError(
                "URL path wildcard target must end with '/*'"
            )

        parsed = urlparse(value[:-1])

        if parsed.scheme not in ("http", "https"):
            raise ScopeValidationError(
                "URL target must use http or https"
            )

        if not parsed.netloc:
            raise ScopeValidationError(
                "URL target must contain a hostname"
            )

        if parsed.hostname is None:
            raise ScopeValidationError(
                "URL target must contain a valid hostname"
            )

        self._validate_hostname(parsed.hostname)

        if not parsed.path or parsed.path == "/":
            raise ScopeValidationError(
                "URL path wildcard target requires a specific path"
            )

        try:
            parsed.port
        except ValueError as exc:
            raise ScopeValidationError(
                "URL target contains an invalid port"
            ) from exc

    def _validate_ipv4(self, value: str) -> None:
        try:
            address = ipaddress.ip_address(
                value.strip()
            )
        except ValueError as exc:
            raise ScopeValidationError(
                "Invalid IPv4 target"
            ) from exc

        if address.version != 4:
            raise ScopeValidationError(
                "Target must be an IPv4 address"
            )