from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from hunt_chain_recon.providers.base import (
    ProviderError,
    ProviderErrorType,
    ProviderResult,
    ProviderStatus,
)
from hunt_chain_recon.providers.discovery.base import DiscoveryProvider


class _HTMLDiscoveryParser(HTMLParser):
    """Extract URLs, resources, forms, and srcset values from HTML."""

    URL_ATTRIBUTES = {
        ("a", "href"),
        ("area", "href"),
        ("link", "href"),
        ("script", "src"),
        ("img", "src"),
        ("iframe", "src"),
        ("frame", "src"),
        ("source", "src"),
        ("video", "src"),
        ("audio", "src"),
        ("object", "data"),
        ("embed", "src"),
        ("track", "src"),
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[tuple[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self.srcsets: list[str] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        tag = tag.lower()

        attributes = {
            key.lower(): value
            for key, value in attrs
            if key
        }

        for element, attribute in self.URL_ATTRIBUTES:
            if tag != element:
                continue

            value = attributes.get(attribute)

            if value:
                self.urls.append(
                    (
                        value.strip(),
                        f"html:{element}:{attribute}",
                    )
                )

        if tag == "img":
            srcset = attributes.get("srcset")
            if srcset:
                self.srcsets.append(srcset)

        if tag == "form":
            self._current_form = {
                "action": (
                    attributes.get("action") or ""
                ).strip(),
                "method": (
                    attributes.get("method") or "GET"
                ).upper(),
                "parameters": [],
            }

            self.forms.append(self._current_form)

        if self._current_form is not None and tag in {
            "input",
            "textarea",
            "select",
        }:
            name = attributes.get("name")

            if name:
                self._current_form["parameters"].append(
                    {
                        "name": name,
                        "tag": tag,
                        "type": attributes.get("type"),
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


class WebDiscoveryProvider(DiscoveryProvider):
    """
    Real HTTP web-discovery provider for authorized Project 2 targets.

    The provider performs discovery only. It does not perform vulnerability
    testing or exploitation.
    """

    DEFAULT_TIMEOUT = 10
    DEFAULT_MAX_PAGES = 50
    DEFAULT_MAX_BODY_BYTES = 2_000_000

    AUXILIARY_PATHS = (
        "/robots.txt",
        "/sitemap.xml",
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/api/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/swagger/v1/swagger.json",
        "/v3/api-docs",
        "/api/v3/api-docs",
        "/docs/openapi.json",
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
    )

    JS_PATTERNS = (
        re.compile(
            r"""(?:fetch|axios\.(?:get|post|put|patch|delete|head|options))
            \s*\(\s*["']([^"']+)["']""",
            re.IGNORECASE | re.VERBOSE,
        ),
        re.compile(
            r"""XMLHttpRequest[\s\S]{0,300}?\.open
            \s*\(\s*["']([A-Z]+)["']\s*,\s*["']([^"']+)["']""",
            re.IGNORECASE | re.VERBOSE,
        ),
        re.compile(
            r"""(?:location\.(?:href|assign|replace))
            \s*(?:=|\()\s*["']([^"']+)["']""",
            re.IGNORECASE | re.VERBOSE,
        ),
        re.compile(
            r"""(?:path|route|url|to)\s*:\s*["']([^"']+)["']""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""["']((?:/api|/graphql|/v\d+)(?:/[^"'<>\\\s]*)?)["']""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:new\s+WebSocket|WebSocket)
            \s*\(\s*["']([^"']+)["']""",
            re.IGNORECASE | re.VERBOSE,
        ),
    )

    REQUEST_STRING_PATTERN = re.compile(
        r"""(?i)\b(?:fetch|axios|request|http\.get|http\.post)\b
        [\s\S]{0,300}?["']([^"']+)["']""",
        re.VERBOSE,
    )

    QUOTED_URL_PATTERN = re.compile(
        r"""["']((?:https?://|/)[^"'<>\\\s]{1,1000})["']"""
    )

    def __init__(
        self,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ) -> None:
        if timeout <= 0:
            raise ValueError(
                "timeout must be greater than zero"
            )

        if max_pages <= 0:
            raise ValueError(
                "max_pages must be greater than zero"
            )

        if max_body_bytes < 1024:
            raise ValueError(
                "max_body_bytes must be at least 1024"
            )

        self._timeout = timeout
        self._max_pages = max_pages
        self._max_body_bytes = max_body_bytes

    @property
    def name(self) -> str:
        return "web"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return (
            "html_link_discovery",
            "form_discovery",
            "script_discovery",
            "resource_discovery",
            "javascript_route_discovery",
            "websocket_discovery",
            "robots_discovery",
            "sitemap_discovery",
            "openapi_discovery",
            "swagger_discovery",
            "graphql_discovery",
        )

    def discover(
        self,
        target: Any,
    ) -> ProviderResult[dict[str, Any]]:
        if not isinstance(target, str):
            return self._failed_result(
                "Discovery target must be a string."
            )

        seed = self._normalize_seed(target)

        if seed is None:
            return self._failed_result(
                "Target must be a valid HTTP or HTTPS URL."
            )

        observations: list[dict[str, Any]] = []
        errors: list[ProviderError] = []

        queue: list[str] = [seed]
        queued: set[str] = {seed}
        visited: set[str] = set()

        while queue and len(visited) < self._max_pages:
            current_url = queue.pop(0)

            if current_url in visited:
                continue

            visited.add(current_url)

            try:
                status_code, headers, body = self._fetch(
                    current_url
                )
            except urllib.error.URLError as exc:
                errors.append(
                    ProviderError(
                        type=ProviderErrorType.NETWORK_ERROR,
                        message=(
                            f"Failed to fetch {current_url}: "
                            f"{exc}"
                        ),
                        retryable=True,
                        details={"url": current_url},
                    )
                )
                continue
            except TimeoutError as exc:
                errors.append(
                    ProviderError(
                        type=ProviderErrorType.TIMEOUT,
                        message=(
                            f"Timed out fetching {current_url}: "
                            f"{exc}"
                        ),
                        retryable=True,
                        details={"url": current_url},
                    )
                )
                continue
            except Exception as exc:
                errors.append(
                    ProviderError(
                        type=ProviderErrorType.EXECUTION_ERROR,
                        message=(
                            f"Failed to fetch {current_url}: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                        retryable=False,
                        details={"url": current_url},
                    )
                )
                continue

            observations.append(
                self._make_observation(
                    url=current_url,
                    source="web:page",
                    parent_url=None,
                    method="GET",
                )
            )

            body_text = self._decode_body(body)

            content_type = headers.get(
                "Content-Type",
                "",
            ).lower()

            if (
                "text/html" in content_type
                or "application/xhtml" in content_type
                or self._looks_like_html(body_text)
            ):
                discovered_urls, forms = self._extract_html(
                    current_url,
                    body_text,
                )

                observations.extend(forms)

                for raw_url, source in discovered_urls:
                    normalized = self._normalize_url(
                        current_url,
                        raw_url,
                    )

                    if normalized is None:
                        continue

                    if not self._allowed_candidate(
                        seed,
                        normalized,
                    ):
                        continue

                    observations.append(
                        self._make_observation(
                            url=normalized,
                            source=source,
                            parent_url=current_url,
                            method="GET",
                        )
                    )

                    if (
                        normalized not in visited
                        and normalized not in queued
                        and self._crawlable(normalized)
                    ):
                        queue.append(normalized)
                        queued.add(normalized)

            for (
                raw_url,
                method,
                source,
            ) in self._extract_javascript_urls(
                body_text
            ):
                normalized = self._normalize_url(
                    current_url,
                    raw_url,
                )

                if normalized is None:
                    continue

                if not self._allowed_candidate(
                    seed,
                    normalized,
                ):
                    continue

                observations.append(
                    self._make_observation(
                        url=normalized,
                        source=source,
                        parent_url=current_url,
                        method=method,
                    )
                )

                if (
                    normalized not in visited
                    and normalized not in queued
                    and self._crawlable(normalized)
                ):
                    queue.append(normalized)
                    queued.add(normalized)

        observations.extend(
            self._discover_auxiliary_urls(seed)
        )

        observations = self._deduplicate_observations(
            observations
        )

        if not observations:
            status = ProviderStatus.FAILED
        elif errors:
            status = ProviderStatus.PARTIAL
        else:
            status = ProviderStatus.SUCCESS

        return ProviderResult(
            status=status,
            observations=observations,
            errors=errors,
            provider=self.name,
            version=self.version,
            metadata={
                "seed": seed,
                "pages_visited": len(visited),
                "observations": len(observations),
                "max_pages": self._max_pages,
                "max_body_bytes": self._max_body_bytes,
            },
        )

    def execute(
        self,
        context: Any,
    ) -> ProviderResult[dict[str, Any]]:
        if isinstance(context, str):
            return self.discover(context)

        target_value: Any = None

        target_accessor = getattr(
            context,
            "target",
            None,
        )

        if callable(target_accessor):
            target_value = target_accessor()
        elif isinstance(target_accessor, str):
            target_value = target_accessor

        if target_value is None:
            config = getattr(
                context,
                "config",
                None,
            )

            config_target = getattr(
                config,
                "target",
                None,
            )

            target_value = getattr(
                config_target,
                "value",
                None,
            )

        return self.discover(target_value)

    def _failed_result(
        self,
        message: str,
    ) -> ProviderResult[dict[str, Any]]:
        return ProviderResult(
            status=ProviderStatus.FAILED,
            observations=[],
            errors=[
                ProviderError(
                    type=ProviderErrorType.CONFIGURATION_ERROR,
                    message=message,
                    retryable=False,
                )
            ],
            provider=self.name,
            version=self.version,
            metadata={},
        )

    def _make_observation(
        self,
        *,
        url: str,
        source: str,
        parent_url: str | None,
        method: str,
    ) -> dict[str, Any]:
        """
        Build the discovery observation expected by AssetProcessingStage.

        Required downstream fields:
            value -> string
            type  -> string

        Web-specific information is retained alongside them.
        """

        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"Unable to extract hostname from URL: {url}")

        query_parameters = {
            key: values
            for key, values in parse_qs(
                parsed.query,
                keep_blank_values=True,
            ).items()
        }

        normalized_method = (
            method.strip().upper()
            if isinstance(method, str)
            and method.strip()
            else "GET"
        )

        return {
            "value": hostname,
            "type": "HOSTNAME",
            "source": source,
            "url": url,
            "parent_url": parent_url,
            "method": method.upper(),
            "query_parameters": query_parameters or {},
}

    def _extract_html(
        self,
        base_url: str,
        body: str,
    ) -> tuple[
        list[tuple[str, str]],
        list[dict[str, Any]],
    ]:
        parser = _HTMLDiscoveryParser()

        try:
            parser.feed(body)
            parser.close()
        except Exception:
            return [], []

        urls: list[tuple[str, str]] = []

        for raw_url, source in parser.urls:
            raw_url = raw_url.strip()

            if not raw_url:
                continue

            if raw_url.startswith(
                (
                    "#",
                    "javascript:",
                    "mailto:",
                    "tel:",
                    "data:",
                    "blob:",
                )
            ):
                continue

            urls.append(
                (
                    raw_url,
                    source,
                )
            )

        for srcset in parser.srcsets:
            for candidate in self._parse_srcset(srcset):
                urls.append(
                    (
                        candidate,
                        "html:srcset",
                    )
                )

        forms: list[dict[str, Any]] = []

        for form in parser.forms:
            action = (
                form.get("action")
                or base_url
            )

            normalized = self._normalize_url(
                base_url,
                action,
            )

            if normalized is None:
                continue

            forms.append(
                self._make_observation(
                    url=normalized,
                    source="html:form:action",
                    parent_url=base_url,
                    method=form.get(
                        "method",
                        "GET",
                    ),
                )
            )

        return urls, forms

    @staticmethod
    def _parse_srcset(
        srcset: str,
    ) -> list[str]:
        results: list[str] = []

        for candidate in srcset.split(","):
            candidate = candidate.strip()

            if not candidate:
                continue

            parts = candidate.split()

            if parts:
                results.append(parts[0])

        return results

    def _extract_javascript_urls(
        self,
        body: str,
    ) -> list[tuple[str, str, str]]:
        results: list[
            tuple[str, str, str]
        ] = []

        for index, pattern in enumerate(
            self.JS_PATTERNS
        ):
            for match in pattern.finditer(body):
                groups = match.groups()

                if not groups:
                    continue

                if (
                    index == 1
                    and len(groups) >= 2
                ):
                    method = (
                        groups[0].strip().upper()
                    )
                    raw_url = groups[1]
                    source = "javascript:xhr"
                else:
                    raw_url = groups[-1]

                    if index == 0:
                        source = "javascript:request"
                    elif index == 2:
                        source = "javascript:location"
                    elif index == 3:
                        source = "javascript:route"
                    elif index == 4:
                        source = "javascript:api"
                    elif index == 5:
                        source = "javascript:websocket"
                    else:
                        source = "javascript:string"

                    method = "GET"

                raw_url = raw_url.strip()

                if not raw_url:
                    continue

                if raw_url.startswith(
                    (
                        "javascript:",
                        "data:",
                        "mailto:",
                        "tel:",
                    )
                ):
                    continue

                results.append(
                    (
                        raw_url,
                        method,
                        source,
                    )
                )

        for match in self.REQUEST_STRING_PATTERN.finditer(
            body
        ):
            raw_url = match.group(1).strip()

            if not raw_url:
                continue

            if raw_url.startswith(
                (
                    "javascript:",
                    "data:",
                    "mailto:",
                    "tel:",
                )
            ):
                continue

            results.append(
                (
                    raw_url,
                    "GET",
                    "javascript:request",
                )
            )

        for match in self.QUOTED_URL_PATTERN.finditer(
            body
        ):
            raw_url = match.group(1).strip()

            if not raw_url:
                continue

            results.append(
                (
                    raw_url,
                    "GET",
                    "javascript:string",
                )
            )

        seen: set[
            tuple[str, str, str]
        ] = set()

        result: list[
            tuple[str, str, str]
        ] = []

        for item in results:
            if item in seen:
                continue

            seen.add(item)
            result.append(item)

        return result

    def _discover_auxiliary_urls(
        self,
        seed: str,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        parsed = urlparse(seed)

        root = urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                "",
                "",
                "",
                "",
            )
        ).rstrip("/")

        robots_url = f"{root}/robots.txt"

        try:
            _, _, body = self._fetch(
                robots_url
            )

            robots_text = self._decode_body(body)

            results.append(
                self._make_observation(
                    url=robots_url,
                    source="robots:robots.txt",
                    parent_url=seed,
                    method="GET",
                )
            )

            for line in robots_text.splitlines():
                if ":" not in line:
                    continue

                key, value = line.split(
                    ":",
                    1,
                )

                if key.strip().lower() != "sitemap":
                    continue

                sitemap = value.strip()

                if not sitemap:
                    continue

                normalized = self._normalize_url(
                    robots_url,
                    sitemap,
                )

                if normalized is None:
                    continue

                if not self._allowed_candidate(
                    seed,
                    normalized,
                ):
                    continue

                results.append(
                    self._make_observation(
                        url=normalized,
                        source="robots:sitemap",
                        parent_url=robots_url,
                        method="GET",
                    )
                )

        except Exception:
            pass

        sitemap_url = f"{root}/sitemap.xml"

        try:
            _, _, body = self._fetch(
                sitemap_url
            )

            sitemap_text = self._decode_body(body)

            results.append(
                self._make_observation(
                    url=sitemap_url,
                    source="sitemap:sitemap.xml",
                    parent_url=seed,
                    method="GET",
                )
            )

            for location in re.findall(
                r"<loc>\s*(.*?)\s*</loc>",
                sitemap_text,
                flags=re.IGNORECASE
                | re.DOTALL,
            ):
                normalized = self._normalize_url(
                    sitemap_url,
                    location.strip(),
                )

                if normalized is None:
                    continue

                if not self._allowed_candidate(
                    seed,
                    normalized,
                ):
                    continue

                results.append(
                    self._make_observation(
                        url=normalized,
                        source="sitemap:loc",
                        parent_url=sitemap_url,
                        method="GET",
                    )
                )

        except Exception:
            pass

        for path in self.AUXILIARY_PATHS:
            url = f"{root}{path}"

            try:
                status, headers, body = self._fetch(url)
            except Exception:
                continue

            body_text = self._decode_body(body)

            content_type = headers.get(
                "Content-Type",
                "",
            ).lower()

            if status < 400:
                source = (
                    "graphql:path"
                    if path.endswith("/graphql")
                    else "auxiliary:path"
                )

                results.append(
                    self._make_observation(
                        url=url,
                        source=source,
                        parent_url=seed,
                        method="GET",
                    )
                )

            if (
                "json" in content_type
                or body_text.lstrip().startswith("{")
            ):
                results.extend(
                    self._extract_openapi_urls(
                        url,
                        body_text,
                    )
                )

            if (
                path.endswith(
                    (
                        ".yaml",
                        ".yml",
                    )
                )
                or "yaml" in content_type
            ):
                results.extend(
                    self._extract_openapi_yaml_urls(
                        url,
                        body_text,
                    )
                )

            if self._looks_like_graphql(
                body_text
            ):
                results.append(
                    self._make_observation(
                        url=url,
                        source="graphql:detected",
                        parent_url=seed,
                        method="GET",
                    )
                )

        return results

    def _extract_openapi_urls(
        self,
        source_url: str,
        body: str,
    ) -> list[dict[str, Any]]:
        try:
            document = json.loads(body)
        except (
            json.JSONDecodeError,
            TypeError,
        ):
            return []

        if not isinstance(
            document,
            dict,
        ):
            return []

        results: list[dict[str, Any]] = []

        paths = document.get("paths")

        if isinstance(paths, dict):
            for path in paths:
                if not isinstance(
                    path,
                    str,
                ):
                    continue

                normalized = self._normalize_url(
                    source_url,
                    path,
                )

                if normalized is None:
                    continue

                results.append(
                    self._make_observation(
                        url=normalized,
                        source="openapi:path",
                        parent_url=source_url,
                        method="GET",
                    )
                )

        servers = document.get("servers")

        if isinstance(
            servers,
            list,
        ):
            for server in servers:
                if not isinstance(
                    server,
                    dict,
                ):
                    continue

                server_url = server.get("url")

                if not isinstance(
                    server_url,
                    str,
                ):
                    continue

                normalized = self._normalize_url(
                    source_url,
                    server_url,
                )

                if normalized is None:
                    continue

                results.append(
                    self._make_observation(
                        url=normalized,
                        source="openapi:server",
                        parent_url=source_url,
                        method="GET",
                    )
                )

        return results

    def _extract_openapi_yaml_urls(
        self,
        source_url: str,
        body: str,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        in_paths = False

        for raw_line in body.splitlines():
            stripped = raw_line.strip()

            if stripped == "paths:":
                in_paths = True
                continue

            if not in_paths:
                continue

            if (
                raw_line
                and not raw_line.startswith(
                    (
                        " ",
                        "\t",
                    )
                )
                and stripped.endswith(":")
            ):
                in_paths = False
                continue

            if stripped.startswith("/"):
                path = stripped.rstrip(":")

                normalized = self._normalize_url(
                    source_url,
                    path,
                )

                if normalized is None:
                    continue

                results.append(
                    self._make_observation(
                        url=normalized,
                        source="openapi:yaml:path",
                        parent_url=source_url,
                        method="GET",
                    )
                )

        return results

    @staticmethod
    def _looks_like_graphql(
        body: str,
    ) -> bool:
        lowered = body.lower()

        return any(
            indicator in lowered
            for indicator in (
                "graphql",
                "__schema",
                "__typename",
                "query ",
                "mutation ",
                "subscription ",
            )
        )

    def _fetch(
        self,
        url: str,
    ) -> tuple[
        int,
        dict[str, str],
        bytes,
    ]:
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "Hunt-Chain-Recon/2.0",
                "Accept": (
                    "text/html,"
                    "application/xhtml+xml,"
                    "application/json,"
                    "application/xml,"
                    "text/xml,"
                    "text/javascript,"
                    "application/javascript,"
                    "*/*;q=0.8"
                ),
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self._timeout,
            ) as response:
                body = response.read(
                    self._max_body_bytes
                )

                headers = {
                    str(key): str(value)
                    for key, value in response.headers.items()
                }

                return (
                    int(response.status),
                    headers,
                    body,
                )

        except urllib.error.HTTPError as error:
            body = error.read(
                self._max_body_bytes
            )

            headers = {
                str(key): str(value)
                for key, value in error.headers.items()
            }

            return (
                int(error.code),
                headers,
                body,
            )

    @staticmethod
    def _decode_body(
        body: bytes,
    ) -> str:
        return body.decode(
            "utf-8",
            errors="replace",
        ) if body else ""

    @staticmethod
    def _looks_like_html(
        body: str,
    ) -> bool:
        lowered = body[:4096].lower()

        return (
            "<html" in lowered
            or "<head" in lowered
            or "<body" in lowered
            or "<a " in lowered
            or "<script" in lowered
        )

    @classmethod
    def _normalize_seed(
        cls,
        target: str,
    ) -> str | None:
        return cls._normalize_url(
            target,
            target,
        )

    @staticmethod
    def _normalize_url(
        base_url: str,
        value: str,
    ) -> str | None:
        if not isinstance(
            value,
            str,
        ):
            return None

        value = value.strip()

        if not value:
            return None

        if value.startswith(
            (
                "#",
                "javascript:",
                "mailto:",
                "tel:",
                "data:",
                "blob:",
            )
        ):
            return None

        try:
            absolute = urljoin(
                base_url,
                value,
            )

            parsed = urlparse(absolute)

            if parsed.scheme.lower() not in {
                "http",
                "https",
            }:
                return None

            if not parsed.hostname:
                return None

            hostname = parsed.hostname.lower()
            port = parsed.port

            netloc = (
                hostname
                if port is None
                else f"{hostname}:{port}"
            )

            return urlunparse(
                (
                    parsed.scheme.lower(),
                    netloc,
                    parsed.path or "/",
                    "",
                    parsed.query,
                    "",
                )
            )

        except (
            ValueError,
            TypeError,
        ):
            return None

    @classmethod
    def _allowed_candidate(
        cls,
        seed: str,
        candidate: str,
    ) -> bool:
        return (
            cls._same_origin(
                seed,
                candidate,
            )
            and cls._within_seed_path(
                seed,
                candidate,
            )
        )

    @staticmethod
    def _default_port(
        scheme: str,
    ) -> int:
        return (
            443
            if scheme.lower() == "https"
            else 80
        )

    @classmethod
    def _same_origin(
        cls,
        first: str,
        second: str,
    ) -> bool:
        first_parsed = urlparse(first)
        second_parsed = urlparse(second)

        if (
            first_parsed.scheme.lower()
            != second_parsed.scheme.lower()
        ):
            return False

        if (
            (first_parsed.hostname or "").lower()
            != (second_parsed.hostname or "").lower()
        ):
            return False

        first_port = (
            first_parsed.port
            or cls._default_port(
                first_parsed.scheme
            )
        )

        second_port = (
            second_parsed.port
            or cls._default_port(
                second_parsed.scheme
            )
        )

        return first_port == second_port

    @staticmethod
    def _within_seed_path(
        seed: str,
        candidate: str,
    ) -> bool:
        seed_path = (
            urlparse(seed).path
            or "/"
        )

        candidate_path = (
            urlparse(candidate).path
            or "/"
        )

        if seed_path == "/":
            return True

        seed_path = seed_path.rstrip("/")

        return (
            candidate_path == seed_path
            or candidate_path.startswith(
                seed_path + "/"
            )
        )

    @staticmethod
    def _crawlable(
        url: str,
    ) -> bool:
        path = urlparse(url).path.lower()

        return not path.endswith(
            (
                ".css",
                ".js",
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".ico",
                ".webp",
                ".woff",
                ".woff2",
                ".ttf",
                ".eot",
                ".pdf",
                ".zip",
                ".gz",
                ".tar",
                ".mp3",
                ".mp4",
                ".avi",
                ".mov",
                ".webm",
            )
        )

    @staticmethod
    def _deduplicate_observations(
        observations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Deduplicate web discovery observations.

    URL identity is based on the actual discovered URL, not the asset
    hostname. This prevents different paths on the same host from being
    collapsed into a single observation.
        """
        seen: set[tuple[str, str, str, str]] = set()
        result: list[dict[str, Any]] = []

        for observation in observations:
            observation_type = observation.get("type")

            if not isinstance(observation_type, str):
                continue

            method = str(
                observation.get("method", "GET")
            ).upper()

            source = str(
                observation.get("source", "web")
            )

            url = observation.get("url")

            if isinstance(url, str) and url.strip():
                identity_url = url.strip()
            else:
                value = observation.get("value")

                if not isinstance(value, str) or not value.strip():
                    continue

                identity_url = value.strip()

            identity = (
                observation_type,
                method,
                identity_url,
                source,
            )

            if identity in seen:
                continue

            seen.add(identity)
            result.append(observation)

        return result