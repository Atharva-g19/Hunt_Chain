from __future__ import annotations

from pathlib import Path

from hunt_chain_recon.models.attack_surface import AttackSurface


class ReportGenerationError(Exception):
    """Raised when the human-readable report cannot be generated."""


class ReconReportGenerator:
    """Generate the deterministic human-readable Project 2 report."""

    def generate(
        self,
        attack_surface: AttackSurface,
    ) -> str:
        """Generate a deterministic report from an AttackSurface."""

        if not isinstance(attack_surface, AttackSurface):
            raise TypeError("Expected AttackSurface instance")

        try:
            return self._build_report(attack_surface)

        except TypeError:
            raise

        except Exception as exc:
            raise ReportGenerationError(
                "Failed to generate reconnaissance report"
            ) from exc

    def _build_report(
        self,
        attack_surface: AttackSurface,
    ) -> str:
        run = attack_surface.run
        target = attack_surface.target
        authorization = attack_surface.authorization
        execution = attack_surface.execution

        # Project 2 models may expose these as either Enum values
        # or plain strings. Support both without changing the models.
        target_type = getattr(
            target.type,
            "value",
            target.type,
        )

        execution_mode = getattr(
            execution.mode,
            "value",
            execution.mode,
        )

        run_status = getattr(
            run.status,
            "value",
            run.status,
        )

        lines: list[str] = [
            "HUNT_CHAIN PROJECT 2",
            "RECONNAISSANCE & ATTACK SURFACE REPORT",
            "=" * 60,
            "",
            "TARGET",
            "-" * 60,
            f"Target                 : {target.value}",
            f"Target Type            : {target_type}",
            f"Schema Version : {attack_surface.schema_version}",
            "",
            "AUTHORIZATION",
            "-" * 60,
            f"Provider               : {authorization.provider}",
            f"Reference              : {authorization.reference}",
            "",
            "EXECUTION",
            "-" * 60,
            f"Execution Mode         : {execution_mode}",
            f"Run Status             : {run_status}",
            f"Run ID                 : {run.id}",
            "",
            "SUMMARY",
            "-" * 60,
            f"Assets                 : {len(attack_surface.assets)}",
            (
                "DNS Observations       : "
                f"{len(attack_surface.dns_observations)}"
            ),
            f"Services               : {len(attack_surface.services)}",
            f"Endpoints              : {len(attack_surface.endpoints)}",
            (
                "Technologies           : "
                f"{len(attack_surface.technologies)}"
            ),
            f"Indicators             : {len(attack_surface.indicators)}",
            (
                "Relationships          : "
                f"{len(attack_surface.relationships)}"
            ),
            "",
            "OBSERVATIONS",
            "-" * 60,
        ]

        self._append_section(
            lines,
            "Assets",
            attack_surface.assets,
            "No assets observed.",
        )

        self._append_section(
            lines,
            "DNS Observations",
            attack_surface.dns_observations,
            "No DNS observations recorded.",
        )

        self._append_section(
            lines,
            "Service Observations",
            attack_surface.services,
            "No service observations recorded.",
        )

        self._append_section(
            lines,
            "Endpoints",
            attack_surface.endpoints,
            "No endpoints recorded.",
        )

        self._append_section(
            lines,
            "HTTP Observations",
            attack_surface.http_observations,
            "No HTTP observations recorded.",
        )

        self._append_section(
            lines,
            "Technologies",
            attack_surface.technologies,
            "No technologies identified.",
        )

        self._append_section(
            lines,
            "Reconnaissance Indicators",
            attack_surface.indicators,
            "No reconnaissance indicators recorded.",
        )

        self._append_section(
            lines,
            "Relationships",
            attack_surface.relationships,
            "No relationships recorded.",
        )

        lines.extend(
            [
                "",
                "DISCLAIMER",
                "-" * 60,
                (
                    "This document contains reconnaissance observations "
                    "and attack-surface intelligence only. It does not "
                    "constitute a vulnerability confirmation."
                ),
                "",
                "END OF REPORT",
                "=" * 60,
                "",
            ]
        )

        return "\n".join(lines)

    @staticmethod
    def _append_section(
        lines: list[str],
        title: str,
        items: list[object],
        empty_message: str,
    ) -> None:
        """Append a deterministic collection section."""

        lines.extend(
            [
                "",
                title,
                "-" * 40,
            ]
        )

        if not items:
            lines.append(empty_message)
            return

        for index, item in enumerate(
            items,
            start=1,
        ):
            try:
                serialized = item.model_dump(
                    mode="json",
                    exclude_none=True,
                )

            except AttributeError:
                serialized = str(item)

            lines.append(
                f"{index}. {serialized}"
            )

    def write(
        self,
        attack_surface: AttackSurface,
        output_path: str | Path,
    ) -> str:
        """Generate and write the human-readable report."""

        if not isinstance(attack_surface, AttackSurface):
            raise TypeError("Expected AttackSurface instance")

        output_path = Path(output_path)

        try:
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            output_path.write_text(
                self.generate(attack_surface),
                encoding="utf-8",
            )

        except TypeError:
            raise

        except OSError as exc:
            raise ReportGenerationError(
                f"Failed to write report: {output_path}"
            ) from exc

        return str(output_path)