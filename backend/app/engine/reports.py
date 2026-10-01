import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from backend.app.core.logging import redact_secrets


class ReportGenerator:
    """
    Generates structured JSON and professional, printable HTML compliance audit reports.
    """

    def generate_json_report(
        self,
        assessment_data: Dict[str, Any],
        host_data: Dict[str, Any],
        findings_data: List[Dict[str, Any]],
        drift_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        report = {
            "meta": {
                "generator": "PSV Linux Security Auditor v1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "assessment_id": assessment_data.get("id"),
                "profile": assessment_data.get("profile_id"),
            },
            "host": {
                "id": host_data.get("id"),
                "name": host_data.get("name"),
                "hostname": host_data.get("hostname"),
                "os": f"{host_data.get('os_distribution', 'Linux')} {host_data.get('os_version', '')}",
                "environment": host_data.get("environment"),
            },
            "executive_summary": {
                "compliance_score": assessment_data.get("compliance_score", 0.0),
                "total_rules": assessment_data.get("total_rules", 0),
                "passed_rules": assessment_data.get("passed_rules", 0),
                "failed_rules": assessment_data.get("failed_rules", 0),
                "warn_rules": assessment_data.get("warn_rules", 0),
                "unknown_rules": assessment_data.get("unknown_rules", 0),
                "severity_breakdown": {
                    "critical": assessment_data.get("critical_count", 0),
                    "high": assessment_data.get("high_count", 0),
                    "medium": assessment_data.get("medium_count", 0),
                    "low": assessment_data.get("low_count", 0),
                }
            },
            "findings": findings_data,
            "drift_summary": drift_data or {}
        }
        # Deep secret redaction
        serialized = json.dumps(report)
        cleaned = redact_secrets(serialized)
        return json.loads(cleaned)

    def generate_html_report(
        self,
        assessment_data: Dict[str, Any],
        host_data: Dict[str, Any],
        findings_data: List[Dict[str, Any]],
        drift_data: Optional[Dict[str, Any]] = None
    ) -> str:
        score = assessment_data.get("compliance_score", 0.0)
        host_name = html.escape(str(host_data.get("name", "Unknown Host")))
        hostname = html.escape(str(host_data.get("hostname", "Unknown Hostname")))
        os_info = html.escape(f"{host_data.get('os_distribution', 'Linux')} {host_data.get('os_version', '')}")
        gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        findings_rows = []
        for f in findings_data:
            sev = f.get("severity", "INFO")
            badge_color = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6",
                "INFO": "#64748b"
            }.get(sev, "#64748b")

            findings_rows.append(f"""
            <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 12px; font-weight: 600;"><span style="background: {badge_color}; color: white; padding: 3px 8px; border-radius: 4px; font-size: 11px;">{sev}</span></td>
                <td style="padding: 12px; font-family: monospace; font-size: 13px;">{html.escape(str(f.get("rule_id", "")))}</td>
                <td style="padding: 12px;"><strong>{html.escape(str(f.get("title", "")))}</strong><br/><small style="color: #64748b;">{html.escape(str(f.get("rationale", "")))}</small></td>
                <td style="padding: 12px; font-family: monospace; font-size: 12px; color: #dc2626;">{html.escape(str(f.get("actual_value", "")))}</td>
                <td style="padding: 12px; font-family: monospace; font-size: 12px; color: #16a34a;">{html.escape(str(f.get("expected_value", "")))}</td>
                <td style="padding: 12px; font-size: 12px;">{html.escape(str(f.get("remediation_guidance", "")))}</td>
            </tr>
            """)

        html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PSV Security Audit Report - {host_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1e293b; background: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 1100px; margin: 0 auto; background: #ffffff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #0f172a; padding-bottom: 20px; margin-bottom: 30px; }}
        .brand {{ font-size: 24px; font-weight: 800; color: #0f172a; letter-spacing: -0.5px; }}
        .score-box {{ text-align: center; background: #f1f5f9; padding: 20px 30px; border-radius: 8px; }}
        .score-val {{ font-size: 42px; font-weight: 900; color: {"#16a34a" if score >= 80 else ("#eab308" if score >= 60 else "#dc2626")}; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 30px 0; }}
        .stat-card {{ background: #f8fafc; padding: 16px; border-radius: 6px; border-left: 4px solid #0284c7; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background: #0f172a; color: #ffffff; text-align: left; padding: 12px; font-size: 12px; text-transform: uppercase; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="brand">PSV Linux Security Auditor</div>
                <div style="color: #64748b; margin-top: 4px;">Host Security Audit & Compliance Assessment</div>
                <div style="font-size: 12px; color: #94a3b8; margin-top: 8px;">Generated: {gen_time}</div>
            </div>
            <div class="score-box">
                <div class="score-val">{score:.1f}%</div>
                <div style="font-size: 12px; text-transform: uppercase; font-weight: 600; color: #64748b;">Compliance Score</div>
            </div>
        </div>

        <h3>Host Metadata</h3>
        <p><strong>Name:</strong> {host_name} &nbsp;|&nbsp; <strong>Hostname:</strong> {hostname} &nbsp;|&nbsp; <strong>OS:</strong> {os_info} &nbsp;|&nbsp; <strong>Profile:</strong> {html.escape(str(assessment_data.get("profile_id", "Default")))}</p>

        <div class="stats-grid">
            <div class="stat-card" style="border-color: #ef4444;">
                <div style="font-size: 11px; text-transform: uppercase; color: #64748b;">Critical Findings</div>
                <div style="font-size: 24px; font-weight: bold; color: #ef4444;">{assessment_data.get("critical_count", 0)}</div>
            </div>
            <div class="stat-card" style="border-color: #f97316;">
                <div style="font-size: 11px; text-transform: uppercase; color: #64748b;">High Findings</div>
                <div style="font-size: 24px; font-weight: bold; color: #f97316;">{assessment_data.get("high_count", 0)}</div>
            </div>
            <div class="stat-card" style="border-color: #eab308;">
                <div style="font-size: 11px; text-transform: uppercase; color: #64748b;">Medium Findings</div>
                <div style="font-size: 24px; font-weight: bold; color: #eab308;">{assessment_data.get("medium_count", 0)}</div>
            </div>
            <div class="stat-card" style="border-color: #16a34a;">
                <div style="font-size: 11px; text-transform: uppercase; color: #64748b;">Passed Rules</div>
                <div style="font-size: 24px; font-weight: bold; color: #16a34a;">{assessment_data.get("passed_rules", 0)} / {assessment_data.get("total_rules", 0)}</div>
            </div>
        </div>

        <h3>Detailed Security Findings ({len(findings_data)})</h3>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Rule ID</th>
                    <th>Title & Description</th>
                    <th>Observed</th>
                    <th>Expected</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {''.join(findings_rows) if findings_rows else '<tr><td colspan="6" style="padding: 24px; text-align: center; color: #16a34a; font-weight: bold;">No active vulnerabilities detected!</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>"""
        return redact_secrets(html_out)


report_generator = ReportGenerator()
