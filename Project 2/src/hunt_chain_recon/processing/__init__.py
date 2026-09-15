"""Processing package for Hunt_Chain Project 2.

Processing transforms provider observations into consistent,
correlated reconnaissance intelligence.

Current V1 processing components:

- AssetNormalizer:
    Converts raw discovery observations into canonical Asset models.

- AssetDeduplicator:
    Consolidates equivalent canonical assets while preserving
    provenance.

- WildcardDNSAnalyzer:
    Analyzes controlled DNS probe observations for wildcard DNS
    behavior without performing network activity.

- DanglingCNAMEAnalyzer:
    Identifies potential dangling CNAME conditions from DNS
    observations without confirming DNS takeover.

- InfrastructureAnalyzer:
    Performs deterministic shared-IP infrastructure analysis.

Processing components do not perform authorization decisions or
network activity.
"""

from hunt_chain_recon.processing.dangling_cname import (
    DanglingCNAMEAnalysisError,
    DanglingCNAMEAnalyzer,
)
from hunt_chain_recon.processing.deduplication import (
    AssetDeduplicator,
    DeduplicationError,
)
from hunt_chain_recon.processing.infrastructure import (
    InfrastructureAnalysisError,
    InfrastructureAnalysisResult,
    InfrastructureAnalyzer,
)
from hunt_chain_recon.processing.normalization import (
    AssetNormalizer,
    NormalizationError,
)
from hunt_chain_recon.processing.wildcard import (
    WildcardAnalysisError,
    WildcardAnalysisResult,
    WildcardDNSAnalyzer,
    WildcardProbe,
)

__all__ = [
    "AssetDeduplicator",
    "AssetNormalizer",
    "DanglingCNAMEAnalysisError",
    "DanglingCNAMEAnalyzer",
    "DeduplicationError",
    "InfrastructureAnalysisError",
    "InfrastructureAnalysisResult",
    "InfrastructureAnalyzer",
    "NormalizationError",
    "WildcardAnalysisError",
    "WildcardAnalysisResult",
    "WildcardDNSAnalyzer",
    "WildcardProbe",
]