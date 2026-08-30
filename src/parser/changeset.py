from __future__ import annotations

import json
from typing import Any

from src.models.schemas import ChangeType, ResourceChange

_ACTION_MAP = {
    "Add": ChangeType.CREATE,
    "Modify": ChangeType.MODIFY,
    "Remove": ChangeType.DELETE,
    "Import": ChangeType.CREATE,
}


def parse_changeset(changeset_json: str) -> tuple[list[ResourceChange], dict[str, Any]]:
    """Parse AWS ChangeSet JSON. Returns (changes, metadata).

    Accepts the output of `aws cloudformation describe-change-set` or the
    Changes array directly.
    """
    data = json.loads(changeset_json)

    if isinstance(data, list):
        raw_changes = data
        meta: dict[str, Any] = {}
    else:
        raw_changes = data.get("Changes", [])
        meta = {
            "changeset_id": data.get("ChangeSetId", ""),
            "changeset_name": data.get("ChangeSetName", ""),
            "stack_id": data.get("StackId", ""),
            "stack_name": data.get("StackName", ""),
            "status": data.get("Status", ""),
            "execution_status": data.get("ExecutionStatus", ""),
        }

    changes: list[ResourceChange] = []
    replacements: dict[str, str] = {}

    for entry in raw_changes:
        rc = entry.get("ResourceChange", entry)

        action = rc.get("Action", "Modify")
        change_type = _ACTION_MAP.get(action, ChangeType.MODIFY)

        resource_id = rc.get("LogicalResourceId", "Unknown")
        resource_type = rc.get("ResourceType", "Unknown")
        physical_id = rc.get("PhysicalResourceId", "")
        replacement = rc.get("Replacement", "False")

        details = rc.get("Details", [])
        changed_props: dict[str, str] = {}
        for detail in details:
            target = detail.get("Target", {})
            prop_name = target.get("Name", "")
            if prop_name:
                changed_props[prop_name] = detail.get("ChangeSource", "DirectModification")

        after_props: dict[str, Any] = {}
        if changed_props:
            after_props["_changed_properties"] = list(changed_props.keys())
        if physical_id:
            after_props["_physical_resource_id"] = physical_id
        if replacement in ("True", "Conditional"):
            after_props["_replacement"] = replacement

        changes.append(ResourceChange(
            resource_id=resource_id,
            resource_type=resource_type,
            change_type=change_type,
            before={},
            after=after_props,
        ))

        if replacement in ("True", "Conditional"):
            replacements[resource_id] = replacement

    meta["replacements"] = replacements
    meta["total_changes"] = len(changes)
    meta["has_replacements"] = bool(replacements)
    meta["replacement_count"] = len(replacements)

    return changes, meta


def is_changeset(content: str) -> bool:
    """Check if content looks like an AWS ChangeSet JSON."""
    content = content.strip()
    if not content.startswith("{") and not content.startswith("["):
        return False
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return any("ResourceChange" in item for item in data if isinstance(item, dict))
        return "Changes" in data and isinstance(data.get("Changes"), list)
    except (json.JSONDecodeError, TypeError):
        return False
