"""Potential dangling CNAME analysis for Hunt_Chain Project 2.

This module analyzes already-collected DNS observations to identify
conditions consistent with a potentially dangling CNAME.

It does not:
- perform DNS queries,
- perform network activity,
- confirm DNS takeover,
- perform exploitation,
- declare a vulnerability,
- create attack-surface relationships.

A potential dangling CNAME is represented as a reconnaissance Indicator.
Confirmation and exploitation belong to later Hunt_Chain projects.
"""

from __future__ import annotations

from uuid import UUID

from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.indicators import (
    Indicator,
    IndicatorConfidence,
    IndicatorStatus,
    IndicatorType,
)


class DanglingCNAMEAnalysisError(Exception):
    """Raised when dangling-CNAME analysis receives invalid input."""


class DanglingCNAMEAnalyzer:
    """Analyze CNAME observations for potential dangling targets.

    V1 uses a conservative rule:

    A potential dangling CNAME indicator is produced only when:

    1. The input is a valid DNSObservation.
    2. The observation contains exactly one CNAME record.
    3. The supplied resolution result for that CNAME target is
       UNRESOLVED.
    4. A valid asset UUID is supplied.

    UNRESOLVED is treated as evidence requiring review. TIMEOUT and ERROR
    are deliberately not treated as proof that a CNAME target is dangling.
    """

    def analyze(
        self,
        cname_observation: DNSObservation,
        target_resolution_status: DNSResolutionStatus,
        asset_id: UUID | None,
    ) -> Indicator | None:
        """Analyze one CNAME observation.

        Args:
            cname_observation:
                DNS observation containing the source hostname and CNAME.
            target_resolution_status:
                Resolution status obtained from a separate lookup of the
                CNAME target.
            asset_id:
                UUID of the source hostname asset.

        Returns:
            A potential dangling-CNAME Indicator, or ``None`` when the
            evidence is insufficient or does not indicate a potential
            dangling target.

        Raises:
            DanglingCNAMEAnalysisError:
                If the input is malformed or ambiguous.
        """
        if not isinstance(
            cname_observation,
            DNSObservation,
        ):
            raise DanglingCNAMEAnalysisError(
                "cname_observation must be a DNSObservation."
            )

        if not isinstance(
            target_resolution_status,
            DNSResolutionStatus,
        ):
            try:
                target_resolution_status = DNSResolutionStatus(
                    target_resolution_status
                )
            except (TypeError, ValueError) as exc:
                raise DanglingCNAMEAnalysisError(
                    "target_resolution_status must be a valid "
                    "DNSResolutionStatus."
                ) from exc

        if asset_id is None:
            raise DanglingCNAMEAnalysisError(
                "asset_id is required for dangling-CNAME analysis."
            )

        if not isinstance(asset_id, UUID):
            raise DanglingCNAMEAnalysisError(
                "asset_id must be a UUID."
            )

        cname_records = cname_observation.cname_records()

        if not cname_records:
            raise DanglingCNAMEAnalysisError(
                "DNS observation must contain a CNAME record."
            )

        if len(cname_records) != 1:
            raise DanglingCNAMEAnalysisError(
                "DNS observation must contain exactly one CNAME record."
            )

        if target_resolution_status is not DNSResolutionStatus.UNRESOLVED:
            return None

        cname_record = cname_records[0]

        hostname = (
            cname_observation.hostname
            .strip()
            .lower()
            .rstrip(".")
        )

        target = (
            cname_record.value
            .strip()
            .lower()
            .rstrip(".")
        )

        evidence = [
            (
                f"Hostname {hostname} has a CNAME record "
                f"pointing to {target}."
            ),
            (
                f"CNAME target {target} produced an "
                f"UNRESOLVED DNS result."
            ),
        ]

        return Indicator(
            asset_id=asset_id,
            type=IndicatorType.POTENTIAL_DANGLING_CNAME,
            status=IndicatorStatus.NEEDS_REVIEW,
            confidence=IndicatorConfidence.MEDIUM,
            title="Potential dangling CNAME",
            description=(
                f"Hostname {hostname} points to CNAME target {target}, "
                "which was observed as unresolved. This requires manual "
                "review and does not confirm DNS takeover."
            ),
            evidence=evidence,
            source_ids=[cname_observation.id],
            metadata={
                "cname_target": target,
                "target_resolution_status": (
                    target_resolution_status.value
                ),
                "confirmation_required": True,
            },
        )