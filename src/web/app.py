from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.analyzer.orchestrator import ChangeAnalyzer
from src.models.schemas import Decision
from src.notifications.sns import RiskNotifier
from src.storage.dynamodb import RiskReportStore
from src.storage.s3 import EvidenceStore

BASE_DIR = Path(__file__).parent
app = FastAPI(title="Production Change Risk Analyzer", version="1.0.0")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

_store: RiskReportStore | None = None
_evidence_store: EvidenceStore | None = None
_notifier: RiskNotifier | None = None


def _get_store() -> RiskReportStore:
    global _store
    if _store is None:
        _store = RiskReportStore()
    return _store


def _get_evidence_store() -> EvidenceStore:
    global _evidence_store
    if _evidence_store is None:
        _evidence_store = EvidenceStore()
    return _evidence_store


def _get_notifier() -> RiskNotifier:
    global _notifier
    if _notifier is None:
        _notifier = RiskNotifier()
    return _notifier


def _get_workshop_url() -> str:
    return os.environ.get("WORKSHOP_URL", "")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    store = _get_store()
    reports = store.list_reports(limit=50)
    reports.sort(key=lambda r: r.get("timestamp", ""), reverse=True)

    stats = _compute_stats(reports)
    return templates.TemplateResponse(request, "dashboard.html", {
        "reports": reports,
        "stats": stats,
    })


@app.get("/analyze", response_class=HTMLResponse)
async def analyze_form(request: Request):
    return templates.TemplateResponse(request, "analyze.html", {})


@app.post("/analyze", response_class=HTMLResponse)
async def analyze_submit(
    request: Request,
    after_template: UploadFile = File(...),
    before_template: UploadFile = File(None),
    environment: str = Form("development"),
    use_ai: bool = Form(True),
):
    after_content = (await after_template.read()).decode("utf-8")
    before_content = None
    if before_template and before_template.filename:
        before_content = (await before_template.read()).decode("utf-8")

    analyzer = ChangeAnalyzer(use_ai=use_ai)
    try:
        report = analyzer.analyze(
            after_template=after_content,
            before_template=before_content,
            environment=environment,
        )
    except Exception as e:
        return templates.TemplateResponse(request, "analyze.html", {
            "error": str(e),
        })

    try:
        store = _get_store()
        store.save_report(report)
    except Exception:
        pass

    try:
        ev_store = _get_evidence_store()
        ev_store.save_evidence(report.evidence)
        if before_content:
            ev_store.save_templates(report.change_id, before_content, after_content)
        else:
            ev_store.save_templates(report.change_id, None, after_content)
    except Exception:
        pass

    if report.decision != Decision.APPROVE:
        try:
            _get_notifier().notify(report)
        except Exception:
            pass

    return templates.TemplateResponse(request, "report.html", {
        "report": report.to_dict(),
        "report_obj": report,
    })


@app.get("/report/{change_id}", response_class=HTMLResponse)
async def view_report(request: Request, change_id: str):
    store = _get_store()
    report = store.get_report(change_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {change_id} not found")
    return templates.TemplateResponse(request, "report.html", {
        "report": report.to_dict(),
        "report_obj": report,
    })


@app.get("/api/reports")
async def api_list_reports(
    environment: str | None = None,
    risk_level: str | None = None,
    limit: int = 50,
):
    store = _get_store()
    reports = store.list_reports(environment=environment, risk_level=risk_level, limit=limit)
    return JSONResponse(content=reports)


@app.get("/api/reports/{change_id}")
async def api_get_report(change_id: str):
    store = _get_store()
    report = store.get_report(change_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {change_id} not found")
    return JSONResponse(content=report.to_dict())


@app.post("/api/analyze")
async def api_analyze(
    after_template: UploadFile = File(...),
    before_template: UploadFile = File(None),
    environment: str = Form("development"),
    use_ai: bool = Form(True),
):
    after_content = (await after_template.read()).decode("utf-8")
    before_content = None
    if before_template and before_template.filename:
        before_content = (await before_template.read()).decode("utf-8")

    analyzer = ChangeAnalyzer(use_ai=use_ai)
    report = analyzer.analyze(
        after_template=after_content,
        before_template=before_content,
        environment=environment,
    )

    try:
        _get_store().save_report(report)
    except Exception:
        pass

    try:
        ev_store = _get_evidence_store()
        ev_store.save_evidence(report.evidence)
    except Exception:
        pass

    if report.decision != Decision.APPROVE:
        try:
            _get_notifier().notify(report)
        except Exception:
            pass

    return JSONResponse(content=report.to_dict())


@app.get("/api/fixture/{name}")
async def api_fixture(name: str):
    import re
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise HTTPException(status_code=400, detail="Invalid fixture name")
    fixture_dir = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "templates"
    filepath = fixture_dir / f"{name}.yaml"
    if not filepath.exists():
        raise HTTPException(status_code=404, detail=f"Fixture {name} not found")
    from fastapi.responses import FileResponse
    return FileResponse(filepath, media_type="text/yaml")


@app.get("/api/stats")
async def api_stats():
    store = _get_store()
    reports = store.list_reports(limit=200)
    return JSONResponse(content=_compute_stats(reports))


def _compute_stats(reports: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(reports)
    by_risk = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_decision = {"BLOCK": 0, "REVIEW": 0, "APPROVE": 0}
    by_env = {}

    for r in reports:
        rl = r.get("risk_level", "LOW")
        if rl in by_risk:
            by_risk[rl] += 1
        dec = r.get("decision", "APPROVE")
        if dec in by_decision:
            by_decision[dec] += 1
        env = r.get("environment", "unknown")
        by_env[env] = by_env.get(env, 0) + 1

    return {
        "total": total,
        "by_risk_level": by_risk,
        "by_decision": by_decision,
        "by_environment": by_env,
        "block_rate": round(by_decision["BLOCK"] / total * 100, 1) if total else 0,
    }
