from urllib.parse import urlparse

from ..models.asset_type import AssetType


class SpecificityCalculator:
    def calculate(self, asset_type: AssetType, asset_value: str) -> int:
        if asset_type == AssetType.HOSTNAME:
            return 100

        if asset_type == AssetType.HOST_WILDCARD:
            return 50

        if asset_type == AssetType.URL:
            return 100

        if asset_type == AssetType.URL_PATH_WILDCARD:
            return 50 + self._url_path_depth(asset_value)

        if asset_type == AssetType.IPV4:
            return 100

        if asset_type == AssetType.IPV4_CIDR:
            return self._cidr_specificity(asset_value)

        return 0

    def _url_path_depth(self, value: str) -> int:
        parsed = urlparse(value)

        path = parsed.path

        if path.endswith("/*"):
            path = path[:-2]

        path = path.rstrip("/")

        if not path or path == "/":
            return 0

        segments = [
            segment
            for segment in path.split("/")
            if segment
        ]

        return len(segments)

    def _cidr_specificity(self, value: str) -> int:
        try:
            prefix_length = int(value.rsplit("/", 1)[1])
        except (ValueError, IndexError):
            return 0

        return prefix_length