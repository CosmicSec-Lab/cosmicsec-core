"""initial placeholder migration

Revision ID: 0001_initial_placeholder
Revises:
Create Date: 2026-03-14
"""



revision = "0001_initial_placeholder"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Database bootstrap is currently handled by infrastructure/init-db.sql.
    # This placeholder keeps Alembic wiring valid for Makefile db-migrate.
    pass


def downgrade() -> None:
    pass
