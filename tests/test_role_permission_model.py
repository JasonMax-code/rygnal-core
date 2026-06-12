import pytest
from pydantic import ValidationError

from rygnal.models import RolePermission, Severity


def test_role_permission_accepts_null_environments_as_all_environments() -> None:
    permission = RolePermission(
        role="security_approver",
        allowed_severities=[Severity.HIGH, Severity.CRITICAL],
        allowed_actions=["delete_file", "write_file"],
        environments=None,
    )

    assert permission.role == "security_approver"
    assert permission.allowed_severities == [Severity.HIGH, Severity.CRITICAL]
    assert permission.allowed_actions == ["delete_file", "write_file"]
    assert permission.environments is None


def test_role_permission_rejects_empty_environments_list() -> None:
    with pytest.raises(ValidationError, match="environments"):
        RolePermission(
            role="security_approver",
            allowed_severities=[Severity.HIGH],
            allowed_actions=["delete_file"],
            environments=[],
        )


def test_role_permission_rejects_blank_role_and_blank_list_values() -> None:
    with pytest.raises(ValidationError):
        RolePermission(
            role=" ",
            allowed_severities=[Severity.HIGH],
            allowed_actions=["delete_file"],
            environments=None,
        )

    with pytest.raises(ValidationError):
        RolePermission(
            role="security_approver",
            allowed_severities=[Severity.HIGH],
            allowed_actions=[" "],
            environments=None,
        )
