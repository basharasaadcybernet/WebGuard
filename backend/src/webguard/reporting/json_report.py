"""Deterministic JSON serialization for the public report contract."""

from __future__ import annotations

import json

from webguard.reporting.models import ReportDocument


class JsonReportRenderer:
    """Serialize a report without terminal formatting or runtime-only objects."""

    def render(self, report: ReportDocument) -> str:
        content = json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        # Keep standalone JSON safe if a consumer later embeds it into an HTML document.
        return (
            content.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") + "\n"
        )
