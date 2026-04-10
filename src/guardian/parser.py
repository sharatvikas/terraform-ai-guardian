"""Parse terraform show -json output into structured change sets."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ChangeAction(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"
    NO_OP = "no-op"
    READ = "read"


@dataclass
class ResourceChange:
    address: str
    module_address: str | None
    resource_type: str
    resource_name: str
    provider: str
    actions: list[ChangeAction]
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    after_unknown: dict[str, Any]
    replace_paths: list[list[str]]

    @property
    def is_destroy(self) -> bool:
        return ChangeAction.DELETE in self.actions

    @property
    def is_create(self) -> bool:
        return ChangeAction.CREATE in self.actions

    @property
    def is_update(self) -> bool:
        return ChangeAction.UPDATE in self.actions

    @property
    def is_replace(self) -> bool:
        return ChangeAction.REPLACE in self.actions or (
            ChangeAction.DELETE in self.actions and ChangeAction.CREATE in self.actions
        )

    @property
    def short_address(self) -> str:
        """Return just the resource type and name without module prefix."""
        parts = self.address.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else self.address


@dataclass
class TerraformPlan:
    format_version: str
    terraform_version: str
    resource_changes: list[ResourceChange] = field(default_factory=list)
    output_changes: dict[str, Any] = field(default_factory=dict)
    prior_state: dict[str, Any] | None = None
    variables: dict[str, Any] = field(default_factory=dict)

    @property
    def creates(self) -> list[ResourceChange]:
        return [r for r in self.resource_changes if r.is_create and not r.is_replace]

    @property
    def updates(self) -> list[ResourceChange]:
        return [r for r in self.resource_changes if r.is_update and not r.is_replace]

    @property
    def destroys(self) -> list[ResourceChange]:
        return [r for r in self.resource_changes if r.is_destroy and not r.is_replace]

    @property
    def replaces(self) -> list[ResourceChange]:
        return [r for r in self.resource_changes if r.is_replace]

    @property
    def total_changes(self) -> int:
        return len([r for r in self.resource_changes if r.actions != [ChangeAction.NO_OP]])

    def summary(self) -> str:
        return (
            f"{len(self.creates)} to add, "
            f"{len(self.updates)} to change, "
            f"{len(self.destroys)} to destroy, "
            f"{len(self.replaces)} to replace"
        )


def parse_plan(plan_file: str | Path) -> TerraformPlan:
    """Parse a terraform show -json plan file into a TerraformPlan object."""
    with open(plan_file) as f:
        raw = json.load(f)

    resource_changes = []
    for rc in raw.get("resource_changes", []):
        change = rc.get("change", {})
        actions_raw = change.get("actions", ["no-op"])

        actions = []
        for a in actions_raw:
            try:
                actions.append(ChangeAction(a))
            except ValueError:
                actions.append(ChangeAction.NO_OP)

        resource_changes.append(
            ResourceChange(
                address=rc.get("address", ""),
                module_address=rc.get("module_address"),
                resource_type=rc.get("type", ""),
                resource_name=rc.get("name", ""),
                provider=rc.get("provider_name", ""),
                actions=actions,
                before=change.get("before"),
                after=change.get("after"),
                after_unknown=change.get("after_unknown", {}),
                replace_paths=change.get("replace_paths", []),
            )
        )

    return TerraformPlan(
        format_version=raw.get("format_version", ""),
        terraform_version=raw.get("terraform_version", ""),
        resource_changes=resource_changes,
        output_changes=raw.get("output_changes", {}),
        prior_state=raw.get("prior_state"),
        variables=raw.get("variables", {}),
    )
