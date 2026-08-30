from __future__ import annotations

import pytest

from src.analyzer.blast_radius import _find_refs_in_value, build_dependency_graph, compute_blast_radius
from src.models.schemas import ChangeType, ResourceChange


def _make_change(resource_id: str, resource_type: str = "AWS::EC2::Instance") -> ResourceChange:
    return ResourceChange(
        resource_id=resource_id,
        resource_type=resource_type,
        change_type=ChangeType.MODIFY,
        before={"Tag": "old"},
        after={"Tag": "new"},
    )


class TestFindRefsInValue:
    def test_ref(self):
        assert _find_refs_in_value({"Ref": "MyVpc"}) == {"MyVpc"}

    def test_fn_getatt_list(self):
        assert _find_refs_in_value({"Fn::GetAtt": ["MyDB", "Endpoint.Address"]}) == {"MyDB"}

    def test_fn_getatt_string(self):
        assert _find_refs_in_value({"Fn::GetAtt": "MyDB.Endpoint.Address"}) == {"MyDB"}

    def test_fn_sub(self):
        result = _find_refs_in_value({"Fn::Sub": "arn:aws:s3:::${MyBucket}/*"})
        assert "MyBucket" in result

    def test_fn_sub_list_form(self):
        result = _find_refs_in_value({"Fn::Sub": ["${MyBucket}-suffix", {}]})
        assert "MyBucket" in result

    def test_nested_refs(self):
        value = {
            "Properties": {
                "SecurityGroupIds": [{"Ref": "SG1"}, {"Ref": "SG2"}],
                "SubnetId": {"Ref": "Subnet"},
            }
        }
        refs = _find_refs_in_value(value)
        assert refs == {"SG1", "SG2", "Subnet"}

    def test_no_refs(self):
        assert _find_refs_in_value({"Value": "static"}) == set()
        assert _find_refs_in_value("plain string") == set()
        assert _find_refs_in_value(42) == set()


class TestBuildDependencyGraph:
    def test_ref_creates_edge(self):
        template = {
            "Resources": {
                "VPC": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}},
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {"VpcId": {"Ref": "VPC"}},
                },
            }
        }
        graph = build_dependency_graph(template)
        assert "Subnet" in graph.get("VPC", [])

    def test_depends_on_creates_edge(self):
        template = {
            "Resources": {
                "DB": {"Type": "AWS::RDS::DBInstance", "Properties": {}},
                "App": {
                    "Type": "AWS::EC2::Instance",
                    "DependsOn": "DB",
                    "Properties": {},
                },
            }
        }
        graph = build_dependency_graph(template)
        assert "App" in graph.get("DB", [])

    def test_no_self_reference(self):
        template = {
            "Resources": {
                "SG": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {"GroupDescription": {"Ref": "SG"}},
                },
            }
        }
        graph = build_dependency_graph(template)
        assert "SG" not in graph.get("SG", [])

    def test_empty_resources(self):
        assert build_dependency_graph({"Resources": {}}) == {}
        assert build_dependency_graph({}) == {}


class TestComputeBlastRadius:
    def test_no_dependents(self):
        template = {
            "Resources": {
                "A": {"Type": "AWS::EC2::Instance", "Properties": {}},
                "B": {"Type": "AWS::EC2::Instance", "Properties": {}},
            }
        }
        changes = [_make_change("A")]
        br = compute_blast_radius(template, changes)
        assert br.total_affected == 1
        assert br.directly_affected == []
        assert br.severity == "LOW"

    def test_direct_dependents(self):
        template = {
            "Resources": {
                "VPC": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}},
                "SubnetA": {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": {"Ref": "VPC"}}},
                "SubnetB": {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": {"Ref": "VPC"}}},
            }
        }
        changes = [_make_change("VPC")]
        br = compute_blast_radius(template, changes)
        assert set(br.directly_affected) == {"SubnetA", "SubnetB"}
        assert br.total_affected == 3
        assert br.severity == "MEDIUM"

    def test_transitive_dependents(self):
        template = {
            "Resources": {
                "VPC": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16"}},
                "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": {"Ref": "VPC"}}},
                "Instance": {"Type": "AWS::EC2::Instance", "Properties": {"SubnetId": {"Ref": "Subnet"}}},
            }
        }
        changes = [_make_change("VPC")]
        br = compute_blast_radius(template, changes)
        assert "Subnet" in br.directly_affected
        assert "Instance" in br.transitively_affected
        assert br.total_affected == 3

    def test_severity_critical(self):
        resources = {}
        for i in range(12):
            name = f"R{i}"
            props = {"VpcId": {"Ref": "R0"}} if i > 0 else {"CidrBlock": "10.0.0.0/16"}
            resources[name] = {"Type": "AWS::EC2::Instance", "Properties": props}
        template = {"Resources": resources}
        changes = [_make_change("R0")]
        br = compute_blast_radius(template, changes)
        assert br.total_affected >= 10
        assert br.severity == "CRITICAL"
