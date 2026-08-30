from __future__ import annotations

from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString

from src.models.schemas import RiskReport, Severity


def generate_junit(report: RiskReport) -> str:
    findings = report.evidence.findings
    failures = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    errors = sum(1 for f in findings if f.severity == Severity.MEDIUM)

    decision = report.decision.value if hasattr(report.decision, "value") else report.decision
    risk_level = report.risk_level.value if hasattr(report.risk_level, "value") else report.risk_level

    testsuites = Element("testsuites")
    testsuite = SubElement(testsuites, "testsuite", {
        "name": "risk-analysis",
        "tests": str(max(len(findings), 1)),
        "failures": str(failures),
        "errors": str(errors),
        "time": "0",
    })
    SubElement(testsuite, "properties").extend([
        _prop("change_id", report.change_id),
        _prop("risk_level", risk_level),
        _prop("risk_score", str(report.risk_score)),
        _prop("decision", decision),
        _prop("environment", report.evidence.environment),
        _prop("timestamp", report.timestamp),
    ])

    if not findings:
        tc = SubElement(testsuite, "testcase", {
            "name": "no-findings",
            "classname": "risk-analysis",
            "time": "0",
        })
    else:
        for finding in findings:
            sev = finding.severity if isinstance(finding.severity, Severity) else Severity(finding.severity)
            tc = SubElement(testsuite, "testcase", {
                "name": f"{finding.rule_id}: {finding.resource}",
                "classname": f"risk-analysis.{finding.rule_id}",
                "time": "0",
            })
            if sev in (Severity.CRITICAL, Severity.HIGH):
                fail = SubElement(tc, "failure", {
                    "message": finding.finding,
                    "type": sev.value,
                })
                parts = [finding.finding]
                if finding.remediation:
                    parts.append(f"Remediation: {finding.remediation}")
                if finding.compliance:
                    parts.append(f"Compliance: {', '.join(finding.compliance)}")
                fail.text = "\n".join(parts)
            elif sev == Severity.MEDIUM:
                err = SubElement(tc, "error", {
                    "message": finding.finding,
                    "type": sev.value,
                })
                err.text = finding.finding

    raw = tostring(testsuites, encoding="unicode", xml_declaration=False)
    dom = parseString(f'<?xml version="1.0" encoding="UTF-8"?>{raw}')
    return dom.toprettyxml(indent="  ").split("\n", 1)[1]


def _prop(name: str, value: str) -> Element:
    el = Element("property", {"name": name, "value": value})
    return el


def write_junit(report: RiskReport, path: str) -> None:
    xml = generate_junit(report)
    with open(path, "w") as f:
        f.write(xml)
