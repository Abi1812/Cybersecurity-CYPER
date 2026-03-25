from __future__ import annotations

import json
from dataclasses import asdict
from typing import Iterable

from .model import CoverageNote, Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.title))

def render_text(findings: list[Finding], coverage: list[CoverageNote]) -> str:
    ordered = _sort_findings(findings)

    lines: list[str] = []
    lines.append("Cybersecurity Defense System by CYPER Report")
    lines.append("="*60)
    lines.append(f"Total findings: {len(ordered)}")
    lines.append("=" * 60)
    lines.append("")

    if ordered:
        lines.append("Findings")
        lines.append("-"*60)
        for f in ordered:
            lines.append(f"[{f.severity.upper()}] {f.title}")
            lines.append(f"  ID: {f.finding_id}")
            lines.append(f"  Detail: {f.detail}")

            if f.evidence:
                lines.append(f"  Evidence: {json.dumps(f.evidence, ensure_ascii=True)}")
            if f.remediation:
                lines.append(f"  Remediation: {f.remediation}")
            if f.tags:
                lines.append(f"  Tags: {', '.join(f.tags)}")
            lines.append("")
    else:
        lines.append("No findings detected")
        lines.append("")


    if coverage:
        lines.append("Coverage notes")
        lines.append("-"*60)
        for note in coverage:
            lines.append(f"- {note.area}: {note.detail}")

    lines.append("=" * 60)
    return "\n".join(lines).strip() + "\n"

def render_json(findings: list[Finding], coverage: list[CoverageNote]) -> str:
    payload = {
        "findings": [asdict(f) for f in _sort_findings(findings)],
        "coverage": [asdict(c) for c in coverage]
    }
    return json.dumps(payload, indent=2)
