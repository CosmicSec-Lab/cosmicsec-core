"""Add plugin marketplace, ratings, repositories, and integration events tables (Phase L).

Revision ID: 0003_phase_l_persistence
Revises: 0002_initial_schema
Create Date: 2026-04-15
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0003_phase_l_persistence"
down_revision = "0002_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Plugin Marketplace
    op.create_table(
        "plugin_marketplace",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False, server_default="0.0.0"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("author", sa.String(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("download_url", sa.String(), nullable=True),
        sa.Column("checksum_sha256", sa.String(), nullable=True),
        sa.Column("downloads", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_repo", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_plugin_marketplace_name", "plugin_marketplace", ["name"], unique=True)

    # Plugin Ratings
    op.create_table(
        "plugin_ratings",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("plugin_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("rating", sa.Integer(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_plugin_ratings_plugin_id", "plugin_ratings", ["plugin_id"])
    op.create_index("ix_plugin_ratings_plugin_user", "plugin_ratings", ["plugin_id", "user_id"])

    # Plugin Repositories
    op.create_table(
        "plugin_repositories",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("index_url", sa.String(), nullable=False),
        sa.Column("trust_level", sa.String(), nullable=False, server_default="community"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("last_sync", sa.DateTime(timezone=True), nullable=True),
        sa.Column("imported_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Integration Events
    op.create_table(
        "integration_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(), nullable=False, server_default="stored"),
        sa.Column("response_code", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_integration_events_provider", "integration_events", ["provider"])
    op.create_index("ix_integration_events_event_type", "integration_events", ["event_type"])
    op.create_index(
        "ix_integration_events_provider_created",
        "integration_events",
        ["provider", "created_at"],
    )


def downgrade() -> None:
    op.drop_table("integration_events")
    op.drop_table("plugin_repositories")
    op.drop_table("plugin_ratings")
    op.drop_table("plugin_marketplace")
