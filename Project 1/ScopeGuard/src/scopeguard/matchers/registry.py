from ..models.asset_type import AssetType
from .hostname_matcher import HostnameMatcher
from .host_wildcard_matcher import HostWildcardMatcher
from .ipv4_cidr_matcher import IPv4CIDRMatcher
from .ipv4_matcher import IPv4Matcher
from .ipv6_cidr_matcher import IPv6CIDRMatcher
from .ipv6_matcher import IPv6Matcher
from .url_matcher import UrlMatcher
from .url_path_wildcard_matcher import UrlPathWildcardMatcher


class MatcherRegistry:
    def __init__(self) -> None:
        self._matchers = {
            AssetType.HOSTNAME: HostnameMatcher(),
            AssetType.HOST_WILDCARD: HostWildcardMatcher(),
            AssetType.URL: UrlMatcher(),
            AssetType.URL_PATH_WILDCARD: (
                UrlPathWildcardMatcher()
            ),
            AssetType.IPV4: IPv4Matcher(),
            AssetType.IPV4_CIDR: IPv4CIDRMatcher(),
            AssetType.IPV6: IPv6Matcher(),
            AssetType.IPV6_CIDR: IPv6CIDRMatcher(),
        }

    def get(self, asset_type: AssetType):
        return self._matchers.get(asset_type)