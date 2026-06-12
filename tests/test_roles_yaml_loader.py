from pathlib import Path

import pytest

from rygnal.models import Severity
from rygnal.roles import DEFAULT_ROLES_PATH, RoleLoadError, load_default_roles, load_roles_file


def test_load_roles_file_parses_operator_role_permissions(tmp_path: Path) -> None:
    roles_file = tmp_path / "roles.yaml"
    roles_file.write_text(
        """
roles:
  security_approver:
    role: security_approver
    allowed_severities: [high, critical]
    allowed_actions: [delete_file]
    environments: [production]
"""
    )

    roles = load_roles_file(roles_file)

    assert set(roles) == {"security_approver"}
    permission = roles["security_approver"]
    assert permission.role == "security_approver"
    assert permission.allowed_severities == [Severity.HIGH, Severity.CRITICAL]
    assert permission.allowed_actions == ["delete_file"]
    assert permission.environments == ["production"]


def test_load_roles_file_rejects_empty_environments(tmp_path: Path) -> None:
    roles_file = tmp_path / "roles.yaml"
    roles_file.write_text(
        """
roles:
  security_approver:
    role: security_approver
    allowed_severities: [high]
    allowed_actions: [delete_file]
    environments: []
"""
    )

    with pytest.raises(RoleLoadError, match="environments"):
        load_roles_file(roles_file)


def test_default_roles_yaml_exists_and_loads() -> None:
    assert DEFAULT_ROLES_PATH.exists()

    roles = load_default_roles()

    assert "viewer" in roles
    assert "security_approver" in roles
    assert roles["viewer"].role == "viewer"
    assert roles["security_approver"].environments is None
