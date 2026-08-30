from __future__ import annotations

import os
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "templates"


@pytest.fixture
def templates_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def secure_baseline(templates_dir: Path) -> str:
    return (templates_dir / "secure_baseline.yaml").read_text()


@pytest.fixture
def dangerous_changes(templates_dir: Path) -> str:
    return (templates_dir / "dangerous_changes.yaml").read_text()


@pytest.fixture
def minor_changes(templates_dir: Path) -> str:
    return (templates_dir / "minor_changes.yaml").read_text()


@pytest.fixture
def new_stack(templates_dir: Path) -> str:
    return (templates_dir / "new_stack.yaml").read_text()
