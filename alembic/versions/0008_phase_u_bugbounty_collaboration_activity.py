"""Add persistent bug bounty collaboration threads and activity audit tables.

Revision ID: 0008_phase_u_bugbounty_collaboration_activity
Revises: 0007_phase_t_agent_task_persistence
Create Date: 2026-04-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0008_phase_u_bugbounty_collaboration_activity"
down_revision = "0007_phase_t_agent_task_persistence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "bugbounty_threads",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("program_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("participants", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["program_id"], ["bugbounty_programs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_bugbounty_threads_program_id", "bugbounty_threads", ["program_id"])
    op.create_index("ix_bugbounty_threads_program_created", "bugbounty_threads", ["program_id", "created_at"])

    op.create_table(
        "bugbounty_activity",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("program_id", sa.String(), nullable=False),
        sa.Column("submission_id", sa.String(), nullable=True),
        sa.Column("activity_type", sa.String(), nullable=False),
        sa.Column("actor", sa.String(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["program_id"], ["bugbounty_programs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["submission_id"], ["bugbounty_submissions.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_bugbounty_activity_program_id", "bugbounty_activity", ["program_id"])
    op.create_index("ix_bugbounty_activity_submission_id", "bugbounty_activity", ["submission_id"])
    op.create_index("ix_bugbounty_activity_activity_type", "bugbounty_activity", ["activity_type"])
    op.create_index("ix_bugbounty_activity_actor", "bugbounty_activity", ["actor"])
    op.create_index("ix_bugbounty_activity_program_created", "bugbounty_activity", ["program_id", "created_at"])
    op.create_index("ix_bugbounty_activity_submission_created", "bugbounty_activity", ["submission_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_bugbounty_activity_submission_created", table_name="bugbounty_activity")
    op.drop_index("ix_bugbounty_activity_program_created", table_name="bugbounty_activity")
    op.drop_index("ix_bugbounty_activity_actor", table_name="bugbounty_activity")
    op.drop_index("ix_bugbounty_activity_activity_type", table_name="bugbounty_activity")
    op.drop_index("ix_bugbounty_activity_submission_id", table_name="bugbounty_activity")
    op.drop_index("ix_bugbounty_activity_program_id", table_name="bugbounty_activity")
    op.drop_table("bugbounty_activity")

    op.drop_index("ix_bugbounty_threads_program_created", table_name="bugbounty_threads")
    op.drop_index("ix_bugbounty_threads_program_id", table_name="bugbounty_threads")
    op.drop_table("bugbounty_threads")
