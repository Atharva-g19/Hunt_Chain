"""Typed configuration models for Hunt_Chain Project 2."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TargetConfig(BaseModel):
    """Target definition supplied to a reconnaissance run."""

    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1)
    type: Literal["DOMAIN", "HOSTNAME", "IP_ADDRESS"]


class AuthorizationConfig(BaseModel):
    """Configuration required to obtain an authorization decision."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1)
    reference: str = Field(min_length=1)
    scope_file: str | None = None


class ExecutionConfig(BaseModel):
    """Controls how reconnaissance is allowed to execute."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["active", "passive_only"] = "active"


class CertificateTransparencyConfig(BaseModel):
    """Configuration for certificate-transparency discovery."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class DiscoveryProvidersConfig(BaseModel):
    """Configuration for individual discovery providers."""

    model_config = ConfigDict(extra="allow")

    certificate_transparency: CertificateTransparencyConfig = Field(
        default_factory=CertificateTransparencyConfig
    )


class DiscoveryConfig(BaseModel):
    """Asset discovery configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    providers: DiscoveryProvidersConfig = Field(
        default_factory=DiscoveryProvidersConfig
    )


class WildcardDNSConfig(BaseModel):
    """Configuration for wildcard DNS detection."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class DanglingCNAMEConfig(BaseModel):
    """Configuration for potential dangling CNAME detection."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class DNSConfig(BaseModel):
    """DNS resolution and analysis configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    record_types: list[Literal["A", "AAAA", "CNAME"]] = Field(
        default_factory=lambda: ["A", "AAAA", "CNAME"]
    )
    timeout_seconds: float = Field(default=5.0, gt=0)
    wildcard_detection: WildcardDNSConfig = Field(
        default_factory=WildcardDNSConfig
    )
    dangling_cname_detection: DanglingCNAMEConfig = Field(
        default_factory=DanglingCNAMEConfig
    )


class PolitenessConfig(BaseModel):
    """Network politeness and request-rate controls."""

    model_config = ConfigDict(extra="forbid")

    concurrency: int = Field(default=5, ge=1)
    requests_per_second: float = Field(default=2.0, gt=0)
    timeout_seconds: float = Field(default=10.0, gt=0)


class HTTPResponseConfig(BaseModel):
    """Controls which HTTP response information is collected."""

    model_config = ConfigDict(extra="forbid")

    collect_headers: bool = True
    collect_body_hash: bool = True


class HTTPConfig(BaseModel):
    """HTTP and HTTPS probing configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True

    schemes: list[Literal["http", "https"]] = Field(
        default_factory=lambda: ["http", "https"]
    )

    ports: list[int] = Field(
        default_factory=lambda: [80, 443],
        description=(
            "Explicit HTTP service ports to probe. "
            "These are configured service locations, not a port scan."
        ),
    )

    timeout_seconds: float = Field(default=10.0, gt=0)
    follow_redirects: bool = True
    max_redirects: int = Field(default=5, ge=0)
    verify_tls: bool = True

    response: HTTPResponseConfig = Field(
        default_factory=HTTPResponseConfig
    )


class ResponseHashConfig(BaseModel):
    """Configuration for deterministic response hashing."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    algorithm: Literal["sha256"] = "sha256"


class FingerprintingConfig(BaseModel):
    """Configuration for response fingerprinting."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True

    response_hash: ResponseHashConfig = Field(
        default_factory=ResponseHashConfig
    )


class TechnologyConfig(BaseModel):
    """Technology fingerprinting configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class ProviderIdentificationConfig(BaseModel):
    """Configuration for infrastructure provider identification."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class InfrastructureConfig(BaseModel):
    """Infrastructure and shared-IP intelligence configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    shared_ip_detection: bool = True

    provider_identification: ProviderIdentificationConfig = Field(
        default_factory=ProviderIdentificationConfig
    )


class JSONOutputConfig(BaseModel):
    """JSON output configuration."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["v1"] = "v1"


class OutputFormatsConfig(BaseModel):
    """Output format selection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    json_output: bool = Field(default=True, alias="json")
    report: bool = True


class OutputConfig(BaseModel):
    """Reconnaissance output configuration."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    directory: str = "./output"

    formats: OutputFormatsConfig = Field(
        default_factory=OutputFormatsConfig
    )

    json_output: JSONOutputConfig = Field(
        default_factory=JSONOutputConfig,
        alias="json",
    )


class LoggingConfig(BaseModel):
    """Application logging configuration."""

    model_config = ConfigDict(extra="forbid")

    level: Literal[
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    ] = "INFO"

    file: str = "./logs/recon.log"


class ReconConfig(BaseModel):
    """Complete Project 2 reconnaissance configuration."""

    model_config = ConfigDict(extra="forbid")

    target: TargetConfig
    authorization: AuthorizationConfig

    execution: ExecutionConfig = Field(
        default_factory=ExecutionConfig
    )

    discovery: DiscoveryConfig = Field(
        default_factory=DiscoveryConfig
    )

    dns: DNSConfig = Field(
        default_factory=DNSConfig
    )

    politeness: PolitenessConfig = Field(
        default_factory=PolitenessConfig
    )

    http: HTTPConfig = Field(
        default_factory=HTTPConfig
    )

    fingerprinting: FingerprintingConfig = Field(
        default_factory=FingerprintingConfig
    )

    technology: TechnologyConfig = Field(
        default_factory=TechnologyConfig
    )

    infrastructure: InfrastructureConfig = Field(
        default_factory=InfrastructureConfig
    )

    output: OutputConfig = Field(
        default_factory=OutputConfig
    )

    logging: LoggingConfig = Field(
        default_factory=LoggingConfig
    )