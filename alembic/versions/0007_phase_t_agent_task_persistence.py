"""Add persistent agent task ledger table.

Revision ID: 0007_phase_t_agent_task_persistence
Revises: 0006_phase_s_partitioning_and_dashboard_view
Create Date: 2026-04-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0007_phase_t_agent_task_persistence"
down_revision = "0006_phase_s_partitioning_and_dashboard_view"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_tasks",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("requested_by", sa.String(), nullable=True),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=True),
        sa.Column("args", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(), nullable=False, server_default="dispatched"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["agent_id"], ["agent_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_tasks_agent_id", "agent_tasks", ["agent_id"])
    op.create_index("ix_agent_tasks_requested_by", "agent_tasks", ["requested_by"])
    op.create_index("ix_agent_tasks_status", "agent_tasks", ["status"])
    op.create_index("ix_agent_tasks_created_at", "agent_tasks", ["created_at"])
    op.create_index("ix_agent_tasks_agent_status", "agent_tasks", ["agent_id", "status"])
    op.create_index("ix_agent_tasks_agent_created", "agent_tasks", ["agent_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_agent_tasks_agent_created", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_agent_status", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_created_at", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_status", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_requested_by", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_agent_id", table_name="agent_tasks")
    op.drop_table("agent_tasks")
