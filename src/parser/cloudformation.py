from __future__ import annotations

import json
from typing import Any

import yaml

from src.models.schemas import ChangeType, ResourceChange


class _CfnLoader(yaml.SafeLoader):
    pass


def _cfn_tag_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node, deep=True)}
    if isinstance(node, yaml.MappingNode):
        return {tag_suffix: loader.construct_mapping(node, deep=True)}
    return {tag_suffix: None}


_CfnLoader.add_multi_constructor("!", lambda loader, suffix, node: _cfn_tag_constructor(loader, suffix, node))


def parse_template(template_str: str) -> dict[str, Any]:
    template_str = template_str.strip()
    if not template_str:
        raise ValueError("Empty template")

    # Try JSON first
    if template_str.startswith("{"):
        try:
            return json.loads(template_str)
        except json.JSONDecodeError:
            pass

    # Try YAML with CFn intrinsic function support
    try:
        parsed = yaml.load(template_str, Loader=_CfnLoader)
        if not isinstance(parsed, dict):
            raise ValueError(f"Template parsed to {type(parsed).__name__}, expected dict")
        return parsed
    except yaml.YAMLError as e:
        raise ValueError(f"Failed to parse template as YAML or JSON: {e}")


def _get_resources(template: dict[str, Any]) -> dict[str, dict[str, Any]]:
    resources = template.get("Resources", {})
    if not isinstance(resources, dict):
        return {}
    return resources


def diff_templates(before: dict[str, Any], after: dict[str, Any]) -> list[ResourceChange]:
    before_resources = _get_resources(before)
    after_resources = _get_resources(after)
    changes: list[ResourceChange] = []

    all_ids = set(before_resources.keys()) | set(after_resources.keys())

    for resource_id in sorted(all_ids):
        in_before = resource_id in before_resources
        in_after = resource_id in after_resources

        if in_before and not in_after:
            res = before_resources[resource_id]
            changes.append(ResourceChange(
                resource_id=resource_id,
                resource_type=res.get("Type", "Unknown"),
                change_type=ChangeType.DELETE,
                before=res.get("Properties", {}),
                after={},
            ))
        elif not in_before and in_after:
            res = after_resources[resource_id]
            changes.append(ResourceChange(
                resource_id=resource_id,
                resource_type=res.get("Type", "Unknown"),
                change_type=ChangeType.CREATE,
                before={},
                after=res.get("Properties", {}),
            ))
        else:
            before_res = before_resources[resource_id]
            after_res = after_resources[resource_id]
            before_props = before_res.get("Properties", {})
            after_props = after_res.get("Properties", {})

            if before_props != after_props or before_res.get("Type") != after_res.get("Type"):
                changes.append(ResourceChange(
                    resource_id=resource_id,
                    resource_type=after_res.get("Type", before_res.get("Type", "Unknown")),
                    change_type=ChangeType.MODIFY,
                    before=before_props,
                    after=after_props,
                ))

    return changes


def parse_single_template(template: dict[str, Any]) -> list[ResourceChange]:
    resources = _get_resources(template)
    changes: list[ResourceChange] = []
    for resource_id, res in sorted(resources.items()):
        changes.append(ResourceChange(
            resource_id=resource_id,
            resource_type=res.get("Type", "Unknown"),
            change_type=ChangeType.CREATE,
            before={},
            after=res.get("Properties", {}),
        ))
    return changes
