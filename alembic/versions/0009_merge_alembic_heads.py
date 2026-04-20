"""Merge Alembic heads for the split migration branches.

Revision ID: 0009_merge_alembic_heads
Revises: 0003_add_users_2fa_columns, 0008_phase_u_bugbounty_collaboration_activity
Create Date: 2026-04-20
"""

from __future__ import annotations

# revision identifiers, used by Alembic.
revision = "0009_merge_alembic_heads"
down_revision = ("0003_add_users_2fa_columns", "0008_phase_u_bugbounty_collaboration_activity")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass