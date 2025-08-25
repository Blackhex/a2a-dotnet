#!/usr/bin/env python3
"""
Convert an A2A TCK JSON compliance report into a readable Markdown report.

Usage:
  python tck_json_to_md.py -i path/to/report.json [-o path/to/report.md]

If -o is omitted, writes alongside the input with .md extension.
If input is '-' reads JSON from stdin; if output is '-' writes to stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def _safe_get(d: Dict[str, Any], path: Iterable[str], default: Any = None) -> Any:
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _md_escape_inline(text: str) -> str:
    return text.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def _format_header(title: str, level: int = 2) -> str:
    level = max(1, min(level, 6))
    return f"{'#' * level} {title}\n"


def _format_kv_block(pairs: List[Tuple[str, Any]]) -> str:
    lines = []
    for k, v in pairs:
        if isinstance(v, bool):
            v = "Yes" if v else "No"
        lines.append(f"- {k}: {v}")
    return "\n".join(lines) + "\n"


def _format_table(headers: List[str], rows: List[List[Any]]) -> str:
    h = " | ".join(headers)
    sep = " | ".join(["---"] * len(headers))
    body = [" | ".join(_md_escape_inline(str(cell)) for cell in row) for row in rows]
    return "\n".join([h, sep, *body]) + "\n"


def render_markdown(report: Dict[str, Any]) -> str:
    lines: List[str] = []

    # Title and timestamp
    ts = _safe_get(report, ["timestamp"]) or datetime.utcnow().isoformat()
    title = "A2A TCK Compliance Report"
    lines.append(_format_header(title, 1))
    lines.append(f"Generated: {ts}\n")

    # Summary
    summary: Dict[str, Any] = report.get("summary", {})
    badge = summary.get("compliance_badge")
    compliant = summary.get("compliant")
    level = summary.get("compliance_level")
    score = summary.get("overall_score")

    lines.append(_format_header("Summary", 2))
    pairs = []
    if badge:
        pairs.append(("Badge", badge))
    if compliant is not None:
        pairs.append(("Compliant", compliant))
    if level:
        pairs.append(("Compliance Level", level))
    if score is not None:
        pairs.append(("Overall Score", score))
    if pairs:
        lines.append(_format_kv_block(pairs))

    # Categories
    categories: Dict[str, Any] = report.get("categories", {})
    if categories:
        lines.append(_format_header("Categories", 2))
        for name, data in categories.items():
            section_title = name.capitalize()
            lines.append(_format_header(section_title, 3))
            desc = data.get("description")
            impact = data.get("impact")
            status = data.get("status")
            if desc:
                lines.append(f"{desc}\n")
            # Compliance numbers table
            comp = data.get("compliance", {})
            headers = [
                "Total",
                "Passed",
                "Failed",
                "Skipped",
                "XFailed",
                "Testable",
                "Success %",
                "Failure %",
                "Status",
            ]
            rows = [
                [
                    comp.get("total", 0),
                    comp.get("passed", 0),
                    comp.get("failed", 0),
                    comp.get("skipped", 0),
                    comp.get("xfailed", 0),
                    comp.get("testable", 0),
                    comp.get("success_rate", 0.0),
                    comp.get("failure_rate", 0.0),
                    status or "",
                ]
            ]
            lines.append(_format_table(headers, rows))
            if impact:
                lines.append(f"Impact: {impact}\n")

            failures = data.get("failures") or []
            if failures:
                lines.append(_format_header("Failures", 4))
                lines.append(f"<details>")
                lines.append(f"<summary>Show {len(failures)} failure(s)</summary>")
                lines.append("")
                for i, failure in enumerate(failures, start=1):
                    test_name = failure.get("test") or "(unnamed test)"
                    lines.append(f"- {i}. {test_name}")
                    # Sub-details
                    sub_pairs = []
                    if failure.get("specification_reference"):
                        sub_pairs.append(("Spec", failure["specification_reference"]))
                    if failure.get("impact"):
                        sub_pairs.append(("Impact", failure["impact"]))
                    if failure.get("fix_suggestion"):
                        sub_pairs.append(("Suggestion", failure["fix_suggestion"]))
                    if sub_pairs:
                        for k, v in sub_pairs:
                            lines.append(f"  - {k}: {_md_escape_inline(str(v))}")
                    # Error message as code block
                    if failure.get("error_message"):
                        lines.append("  Error message:")
                        lines.append(
                            "\n".join(
                                [
                                    "",
                                    "  ```text",
                                    *[
                                        "  " + ln
                                        for ln in str(
                                            failure["error_message"]
                                        ).splitlines()
                                    ],
                                    "  ```",
                                    "",
                                ]
                            )
                        )
                lines.append("</details>")
                lines.append("")

    # Recommendations
    recs = report.get("recommendations") or []
    if recs:
        lines.append(_format_header("Recommendations", 2))
        for r in recs:
            lines.append(f"- {r}")
        lines.append("")

    # Next steps
    next_steps = report.get("next_steps") or []
    if next_steps:
        lines.append(_format_header("Next steps", 2))
        for step in next_steps:
            lines.append(f"- {step}")
        lines.append("")

    # Capability analysis (optional)
    cap = report.get("capability_analysis")
    agent_card = report.get("agent_card")

    # Only show capability analysis section if there's meaningful content
    if (isinstance(cap, dict) and cap) or (isinstance(agent_card, dict) and agent_card):
        lines.append(_format_header("Capability Analysis", 2))

        # Agent card information
        if isinstance(agent_card, dict) and agent_card:
            lines.append("### Agent Card\n")
            headers = ["Property", "Value"]
            rows = []
            
            # Add rows in a logical order with better formatting
            if agent_card.get("name"):
                rows.append(["Name", agent_card["name"]])
            if agent_card.get("description"):
                rows.append(["Description", agent_card["description"]])
            if agent_card.get("url"):
                rows.append(["URL", agent_card["url"]])
            if agent_card.get("version"):
                rows.append(["Version", agent_card["version"]])
            if agent_card.get("protocolVersion"):
                rows.append(["Protocol Version", agent_card["protocolVersion"]])
            if agent_card.get("provider"):
                rows.append(["Provider", agent_card["provider"]])
            if agent_card.get("documentationUrl"):
                rows.append(["Documentation URL", agent_card["documentationUrl"]])
            if agent_card.get("iconUrl"):
                rows.append(["Icon URL", agent_card["iconUrl"]])
            if agent_card.get("preferredTransport"):
                rows.append(["Preferred Transport", agent_card["preferredTransport"]])
            
            # Capabilities section
            capabilities = agent_card.get("capabilities", {})
            if capabilities:
                for key, value in capabilities.items():
                    if key == "extensions" and isinstance(value, list):
                        formatted_value = ", ".join(value) if value else "None"
                    elif isinstance(value, bool):
                        formatted_value = "Yes" if value else "No"
                    else:
                        formatted_value = str(value)
                    rows.append([f"Capability: {key}", formatted_value])
            
            # Input/Output modes
            input_modes = agent_card.get("defaultInputModes", [])
            if input_modes:
                rows.append(["Default Input Modes", ", ".join(input_modes)])
            
            output_modes = agent_card.get("defaultOutputModes", [])
            if output_modes:
                rows.append(["Default Output Modes", ", ".join(output_modes)])
            
            # Skills
            skills = agent_card.get("skills", [])
            if skills:
                rows.append(["Skills", ", ".join(skills)])
            
            # Additional interfaces
            additional_interfaces = agent_card.get("additionalInterfaces", [])
            if additional_interfaces:
                rows.append(["Additional Interfaces", ", ".join(additional_interfaces)])
            
            # Boolean flags
            if "supportsAuthenticatedExtendedCard" in agent_card:
                rows.append(["Supports Authenticated Extended Card", "Yes" if agent_card["supportsAuthenticatedExtendedCard"] else "No"])
            
            # Security information (if present)
            security_schemes = agent_card.get("securitySchemes")
            if security_schemes is not None:
                rows.append(["Security Schemes", json.dumps(security_schemes)])
            
            security = agent_card.get("security")
            if security is not None:
                rows.append(["Security", json.dumps(security)])
            
            lines.append(_format_table(headers, rows))

        # Capability analysis
        if isinstance(cap, dict) and cap:
            declared = cap.get("declared")
            issues = cap.get("issues") or []
            recommendations = cap.get("recommendations") or []

            if declared:
                lines.append("### Declared Capabilities\n")
                headers = ["Capability", "Value"]
                rows = [[k, json.dumps(v)] for k, v in declared.items()]
                lines.append(_format_table(headers, rows))

            if issues:
                lines.append("### Issues\n")
                for issue in issues:
                    lines.append(f"- {issue}")
                lines.append("")

            if recommendations:
                lines.append("### Recommendations\n")
                for rec in recommendations:
                    lines.append(f"- {rec}")
                lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Convert A2A TCK JSON report to Markdown")
    p.add_argument(
        "-i", "--input", required=True, help="Input JSON file path or '-' for stdin"
    )
    p.add_argument("-o", "--output", help="Output Markdown file path or '-' for stdout")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    # Read JSON
    try:
        if args.input == "-":
            report = json.load(sys.stdin)
            in_path = None
        else:
            in_path = Path(args.input)
            with in_path.open("r", encoding="utf-8") as f:
                report = json.load(f)
    except FileNotFoundError:
        print(f"Input not found: {args.input}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in {args.input}: {e}", file=sys.stderr)
        return 2

    md = render_markdown(report)

    # Write Markdown
    out_target = args.output
    if not out_target:
        if in_path is None:
            out_target = "-"
        else:
            out_target = str(in_path.with_suffix(".md"))

    if out_target == "-":
        sys.stdout.write(md)
    else:
        out_path = Path(out_target)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(md, encoding="utf-8")
        print(f"Markdown written to: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
