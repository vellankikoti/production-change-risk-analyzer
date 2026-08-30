"""Tests for AWS CloudFormation ChangeSet parsing and analysis."""
from __future__ import annotations

import json
import os

import pytest

from src.models.schemas import ChangeType
from src.parser.changeset import is_changeset, parse_changeset


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "changeset")


def _load_fixture(name: str) -> str:
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return f.read()


class TestIsChangeset:
    def test_valid_changeset(self):
        assert is_changeset(_load_fixture("modify_replace.json"))

    def test_changes_array_directly(self):
        arr = '[{"ResourceChange": {"Action": "Add", "LogicalResourceId": "X", "ResourceType": "AWS::S3::Bucket"}}]'
        assert is_changeset(arr)

    def test_cloudformation_template(self):
        assert not is_changeset('{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}')

    def test_terraform_plan(self):
        assert not is_changeset('{"resource_changes": [], "format_version": "1.2"}')

    def test_empty(self):
        assert not is_changeset("")

    def test_yaml(self):
        assert not is_changeset("AWSTemplateFormatVersion: '2010-09-09'")


class TestParseChangeset:
    def test_parses_all_changes(self):
        changes, meta = parse_changeset(_load_fixture("modify_replace.json"))
        assert len(changes) == 5

    def test_action_mapping(self):
        changes, _ = parse_changeset(_load_fixture("modify_replace.json"))
        by_id = {c.resource_id: c for c in changes}

        assert by_id["NewBucket"].change_type == ChangeType.CREATE
        assert by_id["OldLambda"].change_type == ChangeType.DELETE
        assert by_id["AppDatabase"].change_type == ChangeType.MODIFY
        assert by_id["AppSecurityGroup"].change_type == ChangeType.MODIFY

    def test_replacement_tracking(self):
        changes, meta = parse_changeset(_load_fixture("modify_replace.json"))
        replacements = meta.get("replacements", {})
        assert "AppDatabase" in replacements
        assert replacements["AppDatabase"] == "True"
        assert "WebServer" in replacements
        assert replacements["WebServer"] == "Conditional"
        assert "AppSecurityGroup" not in replacements

    def test_metadata_fields(self):
        _, meta = parse_changeset(_load_fixture("modify_replace.json"))
        assert meta["changeset_name"] == "my-changeset"
        assert meta["stack_name"] == "my-stack"
        assert meta["status"] == "CREATE_COMPLETE"
        assert meta["total_changes"] == 5
        assert meta["has_replacements"] is True
        assert meta["replacement_count"] == 2

    def test_changed_properties_tracked(self):
        changes, _ = parse_changeset(_load_fixture("modify_replace.json"))
        db = next(c for c in changes if c.resource_id == "AppDatabase")
        props = db.after.get("_changed_properties", [])
        assert "Engine" in props
        assert "DBInstanceClass" in props

    def test_replacement_in_after_props(self):
        changes, _ = parse_changeset(_load_fixture("modify_replace.json"))
        db = next(c for c in changes if c.resource_id == "AppDatabase")
        assert db.after.get("_replacement") == "True"

    def test_physical_resource_id_preserved(self):
        changes, _ = parse_changeset(_load_fixture("modify_replace.json"))
        db = next(c for c in changes if c.resource_id == "AppDatabase")
        assert db.after.get("_physical_resource_id") == "my-database-instance"

    def test_resource_types_preserved(self):
        changes, _ = parse_changeset(_load_fixture("modify_replace.json"))
        types = {c.resource_type for c in changes}
        assert "AWS::RDS::DBInstance" in types
        assert "AWS::EC2::SecurityGroup" in types
        assert "AWS::S3::Bucket" in types
        assert "AWS::Lambda::Function" in types

    def test_direct_array_input(self):
        arr = json.dumps([{
            "ResourceChange": {
                "Action": "Add",
                "LogicalResourceId": "TestBucket",
                "ResourceType": "AWS::S3::Bucket",
            }
        }])
        changes, meta = parse_changeset(arr)
        assert len(changes) == 1
        assert changes[0].resource_id == "TestBucket"
        assert changes[0].change_type == ChangeType.CREATE
        assert meta.get("changeset_id") is None


class TestChangesetEndToEnd:
    """Full pipeline: ChangeSet → ChangeAnalyzer → RiskReport."""

    def test_changeset_analysis(self):
        from src.analyzer.orchestrator import ChangeAnalyzer

        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False)
        cs = _load_fixture("modify_replace.json")
        report = analyzer.analyze(after_template=cs, source="changeset")

        assert report.evidence.metadata.get("source") == "changeset"
        assert report.evidence.metadata.get("stack_name") == "my-stack"
        assert len(report.evidence.changes) == 5

    def test_changeset_auto_detection(self):
        from src.analyzer.orchestrator import ChangeAnalyzer

        analyzer = ChangeAnalyzer(use_ai=False, emit_metrics=False)
        cs = _load_fixture("modify_replace.json")
        report = analyzer.analyze(after_template=cs, source="auto")

        assert report.evidence.metadata.get("source") == "changeset"
