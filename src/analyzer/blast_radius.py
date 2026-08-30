from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from src.models.schemas import BlastRadius, ResourceChange


def _find_refs_in_value(value: Any) -> set[str]:
    """Recursively find all resource references in a CloudFormation property value."""
    refs: set[str] = set()
    if isinstance(value, dict):
        if "Ref" in value and isinstance(value["Ref"], str):
            refs.add(value["Ref"])
        if "GetAtt" in value:
            att = value["GetAtt"]
            if isinstance(att, list) and len(att) >= 1:
                refs.add(str(att[0]))
            elif isinstance(att, str) and "." in att:
                refs.add(att.split(".")[0])
        if "Fn::GetAtt" in value:
            att = value["Fn::GetAtt"]
            if isinstance(att, list) and len(att) >= 1:
                refs.add(str(att[0]))
            elif isinstance(att, str) and "." in att:
                refs.add(att.split(".")[0])
        if "Fn::Sub" in value:
            sub_val = value["Fn::Sub"]
            if isinstance(sub_val, str):
                for m in re.finditer(r'\$\{([A-Za-z0-9_]+)\}', sub_val):
                    refs.add(m.group(1))
            elif isinstance(sub_val, list) and len(sub_val) >= 1:
                for m in re.finditer(r'\$\{([A-Za-z0-9_]+)\}', str(sub_val[0])):
                    refs.add(m.group(1))
        for v in value.values():
            refs.update(_find_refs_in_value(v))
    elif isinstance(value, list):
        for item in value:
            refs.update(_find_refs_in_value(item))
    return refs


def build_dependency_graph(template: dict[str, Any]) -> dict[str, list[str]]:
    """Build a reverse dependency graph: target → [resources that depend on target]."""
    resources = template.get("Resources", {})
    if not isinstance(resources, dict):
        return {}

    resource_names = set(resources.keys())
    reverse_graph: dict[str, list[str]] = defaultdict(list)

    for res_id, res_def in resources.items():
        if not isinstance(res_def, dict):
            continue

        deps_on = res_def.get("DependsOn", [])
        if isinstance(deps_on, str):
            deps_on = [deps_on]
        for dep in deps_on:
            if dep in resource_names:
                reverse_graph[dep].append(res_id)

        props = res_def.get("Properties", {})
        if not isinstance(props, dict):
            continue

        refs = _find_refs_in_value(props)
        for ref in refs:
            if ref in resource_names and ref != res_id:
                if res_id not in reverse_graph[ref]:
                    reverse_graph[ref].append(res_id)

    return dict(reverse_graph)


def compute_blast_radius(
    template: dict[str, Any],
    changes: list[ResourceChange],
) -> BlastRadius:
    """Compute blast radius for changed resources."""
    reverse_graph = build_dependency_graph(template)
    changed_ids = {c.resource_id for c in changes}

    directly_affected: set[str] = set()
    for cid in changed_ids:
        for dep in reverse_graph.get(cid, []):
            if dep not in changed_ids:
                directly_affected.add(dep)

    transitively_affected: set[str] = set()
    visited = changed_ids | directly_affected
    frontier = list(directly_affected)
    while frontier:
        current = frontier.pop(0)
        for dep in reverse_graph.get(current, []):
            if dep not in visited:
                transitively_affected.add(dep)
                visited.add(dep)
                frontier.append(dep)

    total = len(changed_ids) + len(directly_affected) + len(transitively_affected)

    if total >= 10:
        severity = "CRITICAL"
    elif total >= 6:
        severity = "HIGH"
    elif total >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return BlastRadius(
        changed_resources=sorted(changed_ids),
        directly_affected=sorted(directly_affected),
        transitively_affected=sorted(transitively_affected),
        total_affected=total,
        severity=severity,
        graph=reverse_graph,
    )
