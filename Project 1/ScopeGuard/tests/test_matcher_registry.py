from scopeguard.matchers.hostname_matcher import HostnameMatcher
from scopeguard.matchers.host_wildcard_matcher import HostWildcardMatcher
from scopeguard.matchers.ipv4_cidr_matcher import IPv4CIDRMatcher
from scopeguard.matchers.ipv4_matcher import IPv4Matcher
from scopeguard.matchers.registry import MatcherRegistry
from scopeguard.matchers.url_matcher import UrlMatcher
from scopeguard.matchers.url_path_wildcard_matcher import (
    UrlPathWildcardMatcher,
)
from scopeguard.models.asset_type import AssetType


def test_hostname_matcher_is_registered():
    registry = MatcherRegistry()

    matcher = registry.get(AssetType.HOSTNAME)

    assert isinstance(matcher, HostnameMatcher)


def test_host_wildcard_matcher_is_registered():
    registry = MatcherRegistry()

    matcher = registry.get(AssetType.HOST_WILDCARD)

    assert isinstance(matcher, HostWildcardMatcher)


def test_url_matcher_is_registered():
    registry = MatcherRegistry()

    matcher = registry.get(AssetType.URL)

    assert isinstance(matcher, UrlMatcher)


def test_url_path_wildcard_matcher_is_registered():
    registry = MatcherRegistry()

    matcher = registry.get(AssetType.URL_PATH_WILDCARD)

    assert isinstance(matcher, UrlPathWildcardMatcher)


def test_ipv4_matcher_is_registered():
    registry = MatcherRegistry()

    matcher = registry.get(AssetType.IPV4)

    assert isinstance(matcher, IPv4Matcher)


def test_ipv4_cidr_matcher_is_registered():
    registry = MatcherRegistry()

    matcher = registry.get(AssetType.IPV4_CIDR)

    assert isinstance(matcher, IPv4CIDRMatcher)


def test_registry_returns_none_for_unknown_type():
    registry = MatcherRegistry()

    matcher = registry.get("unknown")

    assert matcher is None


def test_registry_returns_same_matcher_instance():
    registry = MatcherRegistry()

    first = registry.get(AssetType.HOSTNAME)
    second = registry.get(AssetType.HOSTNAME)

    assert first is second