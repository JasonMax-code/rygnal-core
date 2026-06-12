"""Role permission loading for Rygnal approval authorization."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from rygnal.models import RolePermission

DEFAULT_ROLES_PATH = Path("policies/roles.yaml")


class RoleLoadError(ValueError):
    """Raised when role permissions cannot be loaded or validated."""


def load_default_roles() -> dict[str, RolePermission]:
    """Load the default operator role permissions."""
    return load_roles_file(DEFAULT_ROLES_PATH)


def load_roles_file(path: str | Path) -> dict[str, RolePermission]:
    """Load and validate role permissions from a YAML file."""
    roles_path = Path(path)

    try:
        data = yaml.safe_load(roles_path.read_text()) or {}
    except OSError as exc:
        raise RoleLoadError(f"Could not read roles file: {roles_path}") from exc
    except yaml.YAMLError as exc:
        raise RoleLoadError(f"Could not parse roles file: {roles_path}") from exc

    if not isinstance(data, dict):
        raise RoleLoadError("roles.yaml must contain a mapping.")

    raw_roles = data.get("roles")
    if not isinstance(raw_roles, dict) or not raw_roles:
        raise RoleLoadError("roles.yaml must define a non-empty roles mapping.")

    roles: dict[str, RolePermission] = {}

    for reviewer_id, raw_permission in raw_roles.items():
        if not isinstance(reviewer_id, str) or not reviewer_id.strip():
            raise RoleLoadError("Role reviewer IDs must be non-blank strings.")

        if not isinstance(raw_permission, dict):
            raise RoleLoadError(f"Role permission for {reviewer_id!r} must be a mapping.")

        roles[reviewer_id] = _validate_role_permission(
            reviewer_id=reviewer_id,
            raw_permission=raw_permission,
        )

    return roles


def _validate_role_permission(
    *,
    reviewer_id: str,
    raw_permission: dict[str, Any],
) -> RolePermission:
    try:
        return RolePermission.model_validate(raw_permission)
    except ValidationError as exc:
        raise RoleLoadError(f"Invalid role permission for {reviewer_id!r}: {exc}") from exc
