from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.analyzer.orchestrator import ChangeAnalyzer
from src.config import load_config
from src.models.schemas import Decision, RiskLevel, Severity
from src.notifications.sns import RiskNotifier
from src.storage.dynamodb import RiskReportStore
from src.storage.s3 import EvidenceStore

console = Console()

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}

DECISION_COLORS = {
    "BLOCK": "bold red",
    "REVIEW": "yellow",
    "APPROVE": "green",
}


def _read_file(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        console.print(f"[red]File not found: {path}[/red]")
        sys.exit(1)


@click.group()
def cli() -> None:
    """Production Change Risk Analyzer — Detect risky infrastructure changes before deployment."""
    pass


@cli.command()
@click.option("--before", type=click.Path(exists=True), default=None, help="Path to the before (current) template")
@click.option("--after", type=click.Path(exists=True), required=True, help="Path to the after (proposed) template")
@click.option("--environment", default="development", help="Target environment (e.g., production, staging)")
@click.option("--no-ai", is_flag=True, default=False, help="Skip AI analysis (deterministic rules only)")
@click.option("--save", is_flag=True, default=False, help="Save report to DynamoDB")
@click.option("--save-evidence", is_flag=True, default=False, help="Save evidence to S3")
@click.option("--notify", is_flag=True, default=False, help="Send SNS notification for HIGH/CRITICAL")
@click.option("--json-output", is_flag=True, default=False, help="Output raw JSON instead of formatted report")
@click.option("--format", "output_format", type=click.Choice(["rich", "json", "sarif", "markdown", "junit"]), default="rich", help="Output format")
@click.option("--output-file", type=click.Path(), default=None, help="Write output to file instead of stdout")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Path to risk-analyzer.yaml config file")
@click.option("--source", type=click.Choice(["auto", "cloudformation", "terraform", "changeset"]), default="auto", help="Input source type (auto-detected by default)")
@click.option("--policies", "policies_path", type=click.Path(exists=True), default=None, help="Path to policies YAML for policy-as-code evaluation")
def analyze(
    before: str | None,
    after: str,
    environment: str,
    no_ai: bool,
    save: bool,
    save_evidence: bool,
    notify: bool,
    json_output: bool,
    output_format: str,
    output_file: str | None,
    config_path: str | None,
    source: str,
    policies_path: str | None,
) -> None:
    """Analyze an infrastructure change for risks.

    Supports CloudFormation templates (YAML/JSON), Terraform plan JSON
    (output of 'terraform show -json'), and AWS CloudFormation ChangeSets.
    Source type is auto-detected by default.
    """
    after_template = _read_file(after)
    before_template = _read_file(before) if before else None

    if json_output:
        output_format = "json"

    config = load_config(config_path)
    if config.ai.enabled is False:
        no_ai = True

    analyzer = ChangeAnalyzer(use_ai=not no_ai, config=config)

    with console.status("[bold cyan]Analyzing infrastructure change..."):
        report = analyzer.analyze(
            after_template=after_template,
            before_template=before_template,
            environment=environment,
            source=source,
        )

    if policies_path:
        from src.policy.engine import PolicyEngine, PolicyContext
        policy_engine = PolicyEngine.from_yaml(policies_path)
        policy_ctx = PolicyContext.from_report(report, environment=environment)
        policy_results = policy_engine.evaluate(policy_ctx)
        new_decision, policy_results = policy_engine.apply_decision(
            policy_results,
            report.decision.value if hasattr(report.decision, "value") else report.decision,
        )
        report.policy_results = [r.to_dict() for r in policy_results if r.matched]
        if new_decision != (report.decision.value if hasattr(report.decision, "value") else report.decision):
            from src.models.schemas import Decision as _Decision
            report.decision = _Decision(new_decision)
            matched_policies = [r for r in policy_results if r.matched]
            if matched_policies:
                console.print(f"[yellow]Policy override: {matched_policies[0].policy_name} — {matched_policies[0].reason}[/yellow]")

    _emit_output(report, output_format, output_file)

    if save:
        try:
            store = RiskReportStore()
            store.save_report(report)
            console.print("[green]Report saved to DynamoDB[/green]")
        except Exception as e:
            console.print(f"[red]Failed to save report: {e}[/red]")

    if save_evidence:
        try:
            ev_store = EvidenceStore()
            key = ev_store.save_evidence(report.evidence)
            ev_store.save_templates(report.change_id, before_template, after_template)
            console.print(f"[green]Evidence saved to S3: {key}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to save evidence: {e}[/red]")

    if notify:
        try:
            notifier = RiskNotifier()
            sent = notifier.notify(report)
            if sent:
                console.print("[green]SNS notification sent[/green]")
        except Exception as e:
            console.print(f"[red]Failed to send notification: {e}[/red]")

    sys.exit(0 if report.decision == Decision.APPROVE else 1)


def _emit_output(report, output_format: str, output_file: str | None) -> None:
    if output_format == "json":
        text = json.dumps(report.to_dict(), indent=2, default=str)
        if output_file:
            with open(output_file, "w") as f:
                f.write(text)
        else:
            click.echo(text)
    elif output_format == "sarif":
        from src.output.sarif import generate_sarif, write_sarif
        if output_file:
            write_sarif(report, output_file)
            console.print(f"[green]SARIF report written to {output_file}[/green]")
        else:
            click.echo(json.dumps(generate_sarif(report), indent=2, default=str))
    elif output_format == "markdown":
        from src.output.markdown import generate_markdown, write_markdown
        if output_file:
            write_markdown(report, output_file)
            console.print(f"[green]Markdown report written to {output_file}[/green]")
        else:
            click.echo(generate_markdown(report))
    elif output_format == "junit":
        from src.output.junit import generate_junit, write_junit
        if output_file:
            write_junit(report, output_file)
            console.print(f"[green]JUnit report written to {output_file}[/green]")
        else:
            click.echo(generate_junit(report))
    else:
        _print_report(report)


@cli.command()
@click.argument("change_id")
def report(change_id: str) -> None:
    """Retrieve a stored risk report by change ID."""
    store = RiskReportStore()
    r = store.get_report(change_id)
    if not r:
        console.print(f"[red]Report not found: {change_id}[/red]")
        sys.exit(1)
    _print_report(r)


@cli.command("list")
@click.option("--environment", default=None, help="Filter by environment")
@click.option("--risk-level", default=None, type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]))
@click.option("--limit", default=20, help="Max results")
def list_reports(environment: str | None, risk_level: str | None, limit: int) -> None:
    """List recent risk reports."""
    store = RiskReportStore()
    items = store.list_reports(environment=environment, risk_level=risk_level, limit=limit)

    if not items:
        console.print("[yellow]No reports found.[/yellow]")
        return

    table = Table(title="Risk Reports")
    table.add_column("Change ID", style="cyan")
    table.add_column("Timestamp")
    table.add_column("Environment")
    table.add_column("Risk Level")
    table.add_column("Score")
    table.add_column("Decision")

    for item in items:
        rl = item.get("risk_level", "")
        dec = item.get("decision", "")
        table.add_row(
            item.get("change_id", ""),
            item.get("timestamp", "")[:19],
            item.get("environment", ""),
            f"[{RISK_COLORS.get(rl, '')}]{rl}[/]",
            str(item.get("risk_score", "")),
            f"[{DECISION_COLORS.get(dec, '')}]{dec}[/]",
        )

    console.print(table)


def _print_report(report) -> None:
    rl = report.risk_level.value if hasattr(report.risk_level, "value") else report.risk_level
    dec = report.decision.value if hasattr(report.decision, "value") else report.decision

    console.print()
    console.print(Panel(
        f"[{RISK_COLORS.get(rl, '')}]{rl}[/] — Risk Score: {report.risk_score}/100 — Decision: [{DECISION_COLORS.get(dec, '')}]{dec}[/]",
        title=f"Risk Report: {report.change_id}",
        subtitle=f"Environment: {report.evidence.environment} | {report.timestamp[:19]}",
    ))

    if report.evidence.changes:
        table = Table(title="Resource Changes")
        table.add_column("Resource", style="cyan")
        table.add_column("Type")
        table.add_column("Change")
        for ch in report.evidence.changes:
            ct = ch.change_type.value if hasattr(ch.change_type, "value") else ch.change_type
            color = {"CREATE": "green", "MODIFY": "yellow", "DELETE": "red"}.get(ct, "")
            table.add_row(ch.resource_id, ch.resource_type, f"[{color}]{ct}[/]")
        console.print(table)

    if report.evidence.findings:
        table = Table(title="Rule Findings")
        table.add_column("Rule", style="cyan")
        table.add_column("Severity")
        table.add_column("Resource")
        table.add_column("Finding")
        for f in report.evidence.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            table.add_row(
                f.rule_id,
                f"[{RISK_COLORS.get(sev, '')}]{sev}[/]",
                f.resource,
                f.finding[:80],
            )
        console.print(table)

    if report.score_breakdown and report.score_breakdown.contributions:
        sb = report.score_breakdown
        table = Table(title="Score Breakdown")
        table.add_column("Category", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Bar")
        table.add_column("Top Findings")
        for c in sb.contributions:
            bar_len = min(c.score, 30)
            bar = "█" * bar_len
            color = "red" if c.score >= 25 else "yellow" if c.score >= 15 else "green"
            top = c.findings[0][:60] if c.findings else ""
            if len(c.findings) > 1:
                top += f" (+{len(c.findings) - 1} more)"
            table.add_row(c.category, str(c.score), f"[{color}]{bar}[/]", top)
        table.add_row("", "", "", "", end_section=True)
        table.add_row("[bold]Total[/]", f"[bold]{sb.total_score}/100[/]", "", f"[bold]{sb.decision}[/]")
        console.print(table)

    if report.blast_radius and report.blast_radius.total_affected > 0:
        br = report.blast_radius
        br_color = RISK_COLORS.get(br.severity, "")
        lines = [f"[{br_color}]{br.severity}[/] — {br.total_affected} resources affected"]
        for rid in br.changed_resources:
            deps = br.graph.get(rid, [])
            if deps:
                lines.append(f"  {rid} (changed)")
                for d in deps[:5]:
                    marker = "├──" if d != deps[-1] else "└──"
                    lines.append(f"    {marker} {d}")
                if len(deps) > 5:
                    lines.append(f"    └── ...and {len(deps) - 5} more")
            else:
                lines.append(f"  {rid} (changed, no dependents)")
        console.print(Panel("\n".join(lines), title="Blast Radius"))

    if report.rollback_risk and report.rollback_risk.resource_risks:
        rb = report.rollback_risk
        rb_color = RISK_COLORS.get(rb.overall_risk, "")
        table = Table(title=f"Rollback Risk: [{rb_color}]{rb.overall_risk}[/]")
        table.add_column("Resource", style="cyan")
        table.add_column("Change")
        table.add_column("Risk")
        table.add_column("Reason")
        for r in rb.resource_risks:
            r_color = RISK_COLORS.get(r.rollback_risk, "")
            table.add_row(
                r.resource_id,
                r.change_type,
                f"[{r_color}]{r.rollback_risk}[/]",
                r.reason[:60],
            )
        console.print(table)

    ai = report.ai_analysis
    if ai.explanation:
        console.print(Panel(ai.explanation, title="AI Analysis — Explanation"))
    if ai.blast_radius:
        console.print(Panel(ai.blast_radius, title="Blast Radius"))
    if ai.operational_impact:
        console.print(Panel(ai.operational_impact, title="Operational Impact"))
    if ai.remediation:
        console.print(Panel(ai.remediation, title="Recommended Remediation"))
    if ai.facts:
        console.print(Panel("\n".join(f"  FACT: {f}" for f in ai.facts), title="Facts (Verified)"))
    if ai.inferences:
        console.print(Panel("\n".join(f"  INFERENCE: {i}" for i in ai.inferences), title="Inferences (AI-derived)"))

    console.print()


@cli.command("subscribe")
@click.argument("email")
def subscribe(email: str) -> None:
    """Subscribe an email to risk alert notifications."""
    import boto3
    import os
    topic_arn = os.environ.get("RISK_ANALYZER_SNS_TOPIC", "")
    if not topic_arn:
        console.print("[red]RISK_ANALYZER_SNS_TOPIC not set[/red]")
        sys.exit(1)
    sns = boto3.client("sns")
    sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint=email)
    console.print(f"[green]Subscription request sent to {email}[/green]")
    console.print("[yellow]Check your email and confirm the subscription.[/yellow]")


@cli.command("dashboard")
@click.option("--name", default="RiskAnalyzer", help="Dashboard name")
def create_cw_dashboard(name: str) -> None:
    """Create or update the CloudWatch dashboard."""
    from src.observability.dashboard import create_dashboard
    with console.status("[bold cyan]Creating CloudWatch dashboard..."):
        url = create_dashboard(dashboard_name=name)
    console.print(f"[green]Dashboard created:[/green] {url}")


@cli.command("trending")
@click.option("--limit", default=20, help="Number of recent reports")
def trending(limit: int) -> None:
    """Show risk trends from historical reports."""
    store = RiskReportStore()
    items = store.list_reports(limit=limit)
    items.sort(key=lambda r: r.get("timestamp", ""), reverse=True)

    if not items:
        console.print("[yellow]No reports found.[/yellow]")
        return

    from collections import Counter
    risk_counts = Counter(i.get("risk_level", "UNKNOWN") for i in items)
    dec_counts = Counter(i.get("decision", "UNKNOWN") for i in items)
    env_counts = Counter(i.get("environment", "unknown") for i in items)
    scores = [i.get("risk_score", 0) for i in items]

    console.print()
    console.print(Panel(
        f"Reports: {len(items)} | "
        f"Avg Score: {sum(scores)/len(scores):.0f} | "
        f"Max Score: {max(scores)} | "
        f"Block Rate: {dec_counts.get('BLOCK', 0)/len(items)*100:.0f}%",
        title="Risk Trends",
    ))

    table = Table(title="Risk Level Distribution")
    table.add_column("Level")
    table.add_column("Count", justify="right")
    table.add_column("Percentage", justify="right")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = risk_counts.get(level, 0)
        pct = count / len(items) * 100
        color = RISK_COLORS.get(level, "")
        table.add_row(f"[{color}]{level}[/]", str(count), f"{pct:.0f}%")
    console.print(table)

    table = Table(title="Decision Distribution")
    table.add_column("Decision")
    table.add_column("Count", justify="right")
    for dec in ["BLOCK", "REVIEW", "APPROVE"]:
        count = dec_counts.get(dec, 0)
        color = DECISION_COLORS.get(dec, "")
        table.add_row(f"[{color}]{dec}[/]", str(count))
    console.print(table)

    table = Table(title="By Environment")
    table.add_column("Environment")
    table.add_column("Count", justify="right")
    for env, count in env_counts.most_common():
        table.add_row(env, str(count))
    console.print(table)


@cli.command("eval")
@click.option("--scenarios", default=None, help="Path to scenarios JSON file")
@click.option("--ai", is_flag=True, default=False, help="Include AI analysis in evaluation")
@click.option("--json-output", is_flag=True, default=False, help="Output raw JSON")
@click.option("--verbose", is_flag=True, default=False, help="Verbose output")
def run_eval(scenarios: str | None, ai: bool, json_output: bool, verbose: bool) -> None:
    """Run evaluation scenarios against the analyzer."""
    from src.evaluation.runner import run_evaluation

    with console.status("[bold cyan]Running evaluation scenarios..."):
        summary = run_evaluation(scenarios_path=scenarios, use_ai=ai, verbose=verbose)

    if json_output:
        click.echo(json.dumps(summary.to_dict(), indent=2, default=str))
        return

    console.print()
    console.print(Panel(
        f"Pass Rate: [{'green' if summary.pass_rate == 100 else 'red'}]{summary.pass_rate}%[/] "
        f"({summary.passed}/{summary.total})",
        title="Evaluation Results",
    ))

    table = Table(title="Accuracy Metrics")
    table.add_column("Metric")
    table.add_column("Score", justify="right")
    table.add_row("Risk Level Accuracy", f"{summary.risk_level_accuracy}%")
    table.add_row("Decision Accuracy", f"{summary.decision_accuracy}%")
    table.add_row("Rule Detection Accuracy", f"{summary.rule_detection_accuracy}%")
    if summary.avg_ai_quality > 0:
        table.add_row("AI Quality Score", f"{summary.avg_ai_quality}/100")
    table.add_row("Avg Duration", f"{summary.avg_duration_ms:.0f}ms")
    console.print(table)

    table = Table(title="Scenario Results")
    table.add_column("ID", style="cyan")
    table.add_column("Description")
    table.add_column("Status")
    table.add_column("Expected")
    table.add_column("Actual")
    table.add_column("Rules")

    for r in summary.results:
        status = "[green]PASS[/]" if r.passed else "[red]FAIL[/]"
        expected = f"{r.expected_risk_level}/{r.expected_decision}"
        actual = f"{r.actual_risk_level}/{r.actual_decision}"
        rules_info = ""
        if r.missing_rules:
            rules_info += f"[red]missing: {','.join(r.missing_rules)}[/] "
        if r.extra_rules:
            rules_info += f"[yellow]extra: {','.join(r.extra_rules)}[/]"
        if not rules_info:
            rules_info = "[green]OK[/]"
        table.add_row(r.scenario_id, r.description[:50], status, expected, actual, rules_info)

    console.print(table)
    sys.exit(0 if summary.pass_rate == 100 else 1)


if __name__ == "__main__":
    cli()
