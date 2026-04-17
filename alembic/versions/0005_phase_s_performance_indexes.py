"""Add composite performance indexes for findings, audit_logs, scans — Phase S.2.

Revision ID: 0005_phase_s_performance_indexes
Revises: 0004_phase_r_multi_tenancy
Create Date: 2026-04-16
"""

from __future__ import annotations

from alembic import op

revision = "0005_phase_s_performance_indexes"
down_revision = "0004_phase_r_multi_tenancy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # findings — most common query pattern: scan_id filter with severity sort
    op.create_index(
        "ix_findings_scan_severity_created",
        "findings",
        ["scan_id", "severity", "created_at"],
        if_not_exists=True,
    )
    # findings — org-scoped lookup (multi-tenant fast path)
    op.create_index(
        "ix_findings_org_created",
        "findings",
        ["organization_id", "created_at"],
        if_not_exists=True,
    )
    # findings — severity filter across all scans (dashboard widget)
    op.create_index(
        "ix_findings_severity",
        "findings",
        ["severity"],
        if_not_exists=True,
    )
    # audit_logs — user timeline / compliance report query
    op.create_index(
        "ix_audit_logs_user_created",
        "audit_logs",
        ["user_id", "created_at"],
        if_not_exists=True,
    )
    # audit_logs — action filter (e.g. list all login events)
    op.create_index(
        "ix_audit_logs_action_created",
        "audit_logs",
        ["action", "created_at"],
        if_not_exists=True,
    )
    # scans — user scans sorted by recency
    op.create_index(
        "ix_scans_user_created",
        "scans",
        ["user_id", "created_at"],
        if_not_exists=True,
    )
    # scans — org timeline
    op.create_index(
        "ix_scans_org_created",
        "scans",
        ["organization_id", "created_at"],
        if_not_exists=True,
    )
    # scans — status filter (queue depth / running scans widget)
    op.create_index(
        "ix_scans_status",
        "scans",
        ["status"],
        if_not_exists=True,
    )
    # organization_members — membership lookup
    op.create_index(
        "ix_org_members_org_user",
        "organization_members",
        ["organization_id", "user_id"],
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index("ix_org_members_org_user", table_name="organization_members", if_exists=True)
    op.drop_index("ix_scans_status", table_name="scans", if_exists=True)
    op.drop_index("ix_scans_org_created", table_name="scans", if_exists=True)
    op.drop_index("ix_scans_user_created", table_name="scans", if_exists=True)
    op.drop_index("ix_audit_logs_action_created", table_name="audit_logs", if_exists=True)
    op.drop_index("ix_audit_logs_user_created", table_name="audit_logs", if_exists=True)
    op.drop_index("ix_findings_severity", table_name="findings", if_exists=True)
    op.drop_index("ix_findings_org_created", table_name="findings", if_exists=True)
    op.drop_index("ix_findings_scan_severity_created", table_name="findings", if_exists=True)
