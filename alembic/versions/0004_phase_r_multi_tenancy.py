"""Add organizations, organization_members, sso_providers tables (Phase R multi-tenancy).

Revision ID: 0004_phase_r_multi_tenancy
Revises: 0003_phase_l_persistence
Create Date: 2026-04-16
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0004_phase_r_multi_tenancy"
down_revision = "0003_phase_l_persistence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # organizations
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("logo_url", sa.String(), nullable=True),
        sa.Column("primary_color", sa.String(), nullable=True, server_default="#0EA5E9"),
        sa.Column("seat_limit", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("plan", sa.String(), nullable=False, server_default="free"),
        sa.Column("settings", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)

    # organization_members
    op.create_table(
        "organization_members",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="member"),
        sa.Column("invited_by", sa.String(), nullable=True),
        sa.Column(
            "joined_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_org_members_org_id", "organization_members", ["org_id"])
    op.create_index("ix_org_members_user_id", "organization_members", ["user_id"])
    op.create_index(
        "ix_org_members_org_user", "organization_members", ["org_id", "user_id"], unique=True
    )

    # sso_providers
    op.create_table(
        "sso_providers",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), nullable=False),
        sa.Column("provider_type", sa.String(), nullable=False),
        sa.Column("provider_name", sa.String(), nullable=False),
        sa.Column("client_id", sa.String(), nullable=True),
        sa.Column("settings", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sso_providers_org_id", "sso_providers", ["org_id"])

    # Add org_id to users (nullable for backward compat)
    op.add_column("users", sa.Column("org_id", sa.String(), nullable=True))
    op.create_index("ix_users_org_id", "users", ["org_id"])

    # Add org_id to scans (nullable for backward compat)
    op.add_column("scans", sa.Column("org_id", sa.String(), nullable=True))
    op.create_index("ix_scans_org_id", "scans", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_scans_org_id", table_name="scans")
    op.drop_column("scans", "org_id")
    op.drop_index("ix_users_org_id", table_name="users")
    op.drop_column("users", "org_id")
    op.drop_index("ix_sso_providers_org_id", table_name="sso_providers")
    op.drop_table("sso_providers")
    op.drop_index("ix_org_members_org_user", table_name="organization_members")
    op.drop_index("ix_org_members_user_id", table_name="organization_members")
    op.drop_index("ix_org_members_org_id", table_name="organization_members")
    op.drop_table("organization_members")
    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_table("organizations")
