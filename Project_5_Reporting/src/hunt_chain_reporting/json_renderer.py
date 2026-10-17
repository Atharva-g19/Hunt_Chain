from __future__ import annotations

import json
from .models import ReportData


def render_json_report(report_data: ReportData, indent: int = 2) -> str:
    """Render full machine-readable JSON bug bounty report."""
    return json.dumps(
        report_data.to_dict(),
        indent=indent,
        ensure_ascii=False,
    )
