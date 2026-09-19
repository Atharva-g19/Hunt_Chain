import ipaddress
from urllib.parse import urlparse

from ..models.asset_type import AssetType


class SpecificityCalculator:
    def calculate(
        self,
        asset_type: AssetType,
        asset_value: str,
    ) -> int:
        if asset_type == AssetType.HOSTNAME:
            return 100

        if asset_type == AssetType.HOST_WILDCARD:
            return 50

        if asset_type == AssetType.URL:
            return 100

        if asset_type == AssetType.URL_PATH_WILDCARD:
            return 50 + self._url_path_depth(
                asset_value
            )

        if asset_type == AssetType.IPV4:
            return 100

        if asset_type == AssetType.IPV4_CIDR:
            return self._cidr_prefix_length(
                asset_value
            )

        if asset_type == AssetType.IPV6:
            return 100

        if asset_type == AssetType.IPV6_CIDR:
            return self._cidr_prefix_length(
                asset_value
            )

        return 0

    def _url_path_depth(
        self,
        value: str,
    ) -> int:
        parsed = urlparse(value)

        path = parsed.path

        if path.endswith("/*"):
            path = path[:-2]

        path = path.rstrip("/")

        if not path:
            return 0

        return len(
            [
                segment
                for segment in path.split("/")
                if segment
            ]
        )

    def _cidr_prefix_length(
        self,
        value: str,
    ) -> int:
        try:
            network = ipaddress.ip_network(
                value.strip(),
                strict=True,
            )
        except ValueError:
            return 0

        return network.prefixlen
