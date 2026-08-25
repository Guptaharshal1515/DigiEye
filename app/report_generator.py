import json
import os
from collections import Counter
from datetime import datetime, timezone

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _safe_text(value):
    if value is None:
        return ""
    return str(value)


def _severity_order(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    return order.get(_safe_text(sev).lower(), 5)


def generate_report(
    findings,
    target,
    task_id,
    output_dir,
    summary=None,
):
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).isoformat()
    findings = findings or []
    summary = summary or {}

    severity_counts = Counter(_safe_text(f.get("severity", "unknown")).lower() for f in findings)
    severity_counts = {
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
        "info": severity_counts.get("info", 0),
        "unknown": severity_counts.get("unknown", 0),
    }

    affected_files = sorted({
        _safe_text(f.get("file", "")).strip()
        for f in findings
        if _safe_text(f.get("file", "")).strip()
    })

    tool_distribution = Counter()
    for finding in findings:
        sources = finding.get("tool_sources") or []
        if isinstance(sources, str):
            sources = [sources]
        for source in sources:
            source_name = _safe_text(source).strip().lower()
            if source_name:
                tool_distribution[source_name] += 1

    tool_exec = summary.get("tool_execution", {}) if isinstance(summary.get("tool_execution"), dict) else {}
    tools_attempted = list(tool_exec.get("tools_attempted", []) or [])
    tools_succeeded = list(tool_exec.get("tools_succeeded", []) or [])
    tools_failed = list(tool_exec.get("tools_failed", []) or [])
    tools_unavailable = list(tool_exec.get("tools_unavailable", []) or [])
    tool_execution_details = list(tool_exec.get("tool_execution_details", []) or [])

    tools_used = sorted(set(tools_succeeded) | set(tool_distribution.keys()))

    patches = summary.get("patches", []) if isinstance(summary.get("patches", []), list) else []
    verification_results = (
        summary.get("verification_results", [])
        if isinstance(summary.get("verification_results", []), list)
        else []
    )
    confidence = float(summary.get("confidence", 0.0) or 0.0)
    errors = summary.get("errors", []) if isinstance(summary.get("errors", []), list) else []
    warnings = summary.get("warnings", []) if isinstance(summary.get("warnings", []), list) else []

    if not tools_attempted:
        status = "incomplete"
    elif tools_failed and not tools_succeeded:
        status = "failed"
    elif tools_unavailable and not tools_succeeded:
        status = "unavailable"
    elif tools_failed or tools_unavailable:
        status = "partial"
    else:
        status = "success"

    report_data = {
        "schema_version": "1.1.0",
        "task_id": task_id,
        "target": target,
        "timestamp": timestamp,
        "assessment_type": summary.get("assessment_type", "code_sast"),
        "status": status,
        "findings": sorted(findings, key=lambda f: _severity_order(f.get("severity"))),
        "severity_counts": severity_counts,
        "affected_files": affected_files,
        "tools_attempted": sorted(set(tools_attempted)),
        "tools_used": tools_used,
        "tools_succeeded": sorted(set(tools_succeeded)),
        "tools_failed": sorted(set(tools_failed)),
        "tools_unavailable": sorted(set(tools_unavailable)),
        "tool_execution_details": tool_execution_details,
        "tool_distribution": dict(tool_distribution),
        "patches": patches,
        "verification_results": verification_results,
        "confidence": confidence,
        "errors": errors,
        "warnings": warnings,
    }

    json_path = os.path.join(output_dir, f"{task_id}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    pdf_path = os.path.join(output_dir, f"{task_id}.pdf")

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    title = ParagraphStyle("ReportTitle", parent=styles["Title"], alignment=TA_CENTER, fontSize=22, spaceAfter=18)
    heading = ParagraphStyle("Heading", parent=styles["Heading2"], fontSize=14, spaceBefore=10, spaceAfter=6)
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9, leading=12)

    story = []

    
    story.append(Paragraph("AI_KAVACH Code Security Report", title))
    story.append(Paragraph(f"<b>Task ID:</b> {task_id}", body))
    story.append(Paragraph(f"<b>Target:</b> {_safe_text(target)}", body))
    story.append(Paragraph(f"<b>Generated:</b> {timestamp}", body))
    story.append(Paragraph(f"<b>Assessment Type:</b> {report_data['assessment_type']}", body))
    story.append(Spacer(1, 16))

    
    story.append(Paragraph("Executive Summary", heading))
    story.append(
        Paragraph(
            (
                f"Total findings: <b>{len(findings)}</b>. "
                f"Confidence: <b>{confidence:.2f}</b>. "
                f"Affected files: <b>{len(affected_files)}</b>."
            ),
            body,
        )
    )

    
    story.append(Paragraph("Severity Summary", heading))
    sev_table = Table(
        [["Severity", "Count"]] + [[k.title(), str(v)] for k, v in severity_counts.items()],
        colWidths=[200, 100],
    )
    sev_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )
    story.append(sev_table)
    story.append(Spacer(1, 8))

    
    if sum(severity_counts.values()) > 0:
        story.append(Paragraph("Severity Distribution", heading))
        d = Drawing(440, 220)
        chart = VerticalBarChart()
        chart.x = 40
        chart.y = 35
        chart.height = 145
        chart.width = 330
        labels = ["Critical", "High", "Medium", "Low", "Info"]
        chart.data = [[
            severity_counts["critical"],
            severity_counts["high"],
            severity_counts["medium"],
            severity_counts["low"],
            severity_counts["info"],
        ]]
        chart.categoryAxis.categoryNames = labels
        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueStep = 1
        d.add(chart)
        story.append(d)

    
    if sum(tool_distribution.values()) > 0:
        story.append(Paragraph("Tool Source Distribution", heading))
        pie = Pie()
        pie.x = 120
        pie.y = 20
        pie.width = 220
        pie.height = 180
        pie.data = list(tool_distribution.values())
        pie.labels = [k for k in tool_distribution.keys()]
        d2 = Drawing(440, 220)
        d2.add(pie)
        story.append(d2)

    
    story.append(PageBreak())
    story.append(Paragraph("Findings", heading))
    if not findings:
        if tools_succeeded:
            story.append(Paragraph("No findings detected by the executed tools.", body))
        elif tools_attempted and (tools_failed or tools_unavailable):
            story.append(Paragraph("No findings reported because tool execution was partial/failed. See tool status sections.", body))
        else:
            story.append(Paragraph("No findings were reported because no tools were executed.", body))
    else:
        ordered_findings = sorted(findings, key=lambda f: _severity_order(f.get("severity")))
        for index, finding in enumerate(ordered_findings, 1):
            story.append(Paragraph(f"{index}. {_safe_text(finding.get('type', 'Unknown'))}", heading))
            details = [
                ["Severity", _safe_text(finding.get("severity", "unknown"))],
                ["File", _safe_text(finding.get("file", ""))],
                ["Line", _safe_text(finding.get("line", ""))],
                ["CWE", _safe_text(finding.get("cwe", ""))],
                ["OWASP", _safe_text(finding.get("owasp", ""))],
                ["Tool Sources", ", ".join(finding.get("tool_sources", []) or [])],
            ]
            t = Table(details, colWidths=[110, 380])
            t.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(t)
            story.append(Spacer(1, 6))

            
            story.append(Paragraph("Evidence", body))
            story.append(Paragraph(_safe_text(finding.get("evidence", "N/A")), body))

            
            story.append(Paragraph("Remediation", body))
            story.append(Paragraph(_safe_text(finding.get("remediation", "N/A")), body))

            story.append(Spacer(1, 10))

    
    story.append(Paragraph("Patch Status", heading))
    if patches:
        ptable = Table([["Patch", "Status"]] + [[_safe_text(p.get("id", "patch")), _safe_text(p.get("status", "unknown"))] for p in patches], colWidths=[250, 120])
        ptable.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
        story.append(ptable)
    else:
        story.append(Paragraph("No patch actions recorded.", body))

    
    story.append(Paragraph("Verification Status", heading))
    if verification_results:
        vtable = Table([["Finding/Check", "Result"]] + [[_safe_text(v.get("id", "check")), _safe_text(v.get("status", "unknown"))] for v in verification_results], colWidths=[250, 120])
        vtable.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
        story.append(vtable)
    else:
        story.append(Paragraph("Not verified.", body))

    
    story.append(Paragraph("Tools Used", heading))
    story.append(Paragraph(", ".join(tools_used) if tools_used else "No tools recorded.", body))

    story.append(Paragraph("Tool Execution Status", heading))
    story.append(Paragraph(f"Status: {status}", body))
    story.append(Paragraph(f"Attempted: {', '.join(sorted(set(tools_attempted))) if tools_attempted else 'None'}", body))
    story.append(Paragraph(f"Succeeded: {', '.join(sorted(set(tools_succeeded))) if tools_succeeded else 'None'}", body))
    story.append(Paragraph(f"Failed: {', '.join(sorted(set(tools_failed))) if tools_failed else 'None'}", body))
    story.append(Paragraph(f"Unavailable: {', '.join(sorted(set(tools_unavailable))) if tools_unavailable else 'None'}", body))

    if affected_files:
        story.append(Paragraph("Affected Files", heading))
        ftable = Table([["File"]] + [[f] for f in affected_files], colWidths=[500])
        ftable.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
        story.append(ftable)

    
    story.append(Paragraph("Limitations and Confidence", heading))
    if warnings:
        story.append(Paragraph("Warnings:", body))
        for warning in warnings:
            story.append(Paragraph(f"- {_safe_text(warning)}", body))
    if errors:
        story.append(Paragraph("Errors:", body))
        for err in errors:
            story.append(Paragraph(f"- {_safe_text(err)}", body))
    if not warnings and not errors:
        story.append(Paragraph("No additional execution limitations were reported.", body))

    story.append(Paragraph(f"Final confidence: {_safe_text(confidence)}", body))

    doc.build(story)

    return {
        "status": "success",
        "json_path": json_path,
        "pdf_path": pdf_path,
        "finding_count": len(findings),
    }
