"""Phase S.2: partition mirrors and dashboard materialized view.

Revision ID: 0006_phase_s_partitioning_and_dashboard_view
Revises: 0005_phase_s_performance_indexes
Create Date: 2026-04-16
"""

from __future__ import annotations

from alembic import op

revision = "0006_phase_s_partitioning_and_dashboard_view"
down_revision = "0005_phase_s_performance_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS findings_partitioned (
            id TEXT NOT NULL,
            scan_id TEXT,
            user_id TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            description TEXT,
            evidence TEXT,
            tool TEXT,
            target TEXT,
            cve_id TEXT,
            cvss_score DOUBLE PRECISION,
            mitre_technique TEXT,
            source TEXT NOT NULL DEFAULT 'web_scan',
            extra JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        ) PARTITION BY RANGE (created_at);
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs_partitioned (
            id BIGINT NOT NULL,
            user_id TEXT,
            action TEXT NOT NULL,
            resource TEXT,
            resource_id TEXT,
            ip_address TEXT,
            extra JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        ) PARTITION BY RANGE (created_at);
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS findings_partitioned_default
        PARTITION OF findings_partitioned DEFAULT;
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs_partitioned_default
        PARTITION OF audit_logs_partitioned DEFAULT;
        """
    )
    op.execute(
        """
        DO $$
        DECLARE
            base date := date_trunc('month', now())::date - interval '1 month';
            i integer;
            from_ts timestamptz;
            to_ts timestamptz;
            part_name text;
        BEGIN
            FOR i IN 0..3 LOOP
                from_ts := (base + (i || ' month')::interval)::timestamptz;
                to_ts := (base + ((i + 1) || ' month')::interval)::timestamptz;
                part_name := 'findings_partitioned_' || to_char(from_ts, 'YYYY_MM');
                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I PARTITION OF findings_partitioned FOR VALUES FROM (%L) TO (%L)',
                    part_name, from_ts, to_ts
                );

                part_name := 'audit_logs_partitioned_' || to_char(from_ts, 'YYYY_MM');
                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_logs_partitioned FOR VALUES FROM (%L) TO (%L)',
                    part_name, from_ts, to_ts
                );
            END LOOP;
        END$$;
        """
    )
    op.execute(
        """
        INSERT INTO findings_partitioned (
            id, scan_id, user_id, title, severity, description, evidence, tool, target,
            cve_id, cvss_score, mitre_technique, source, extra, created_at
        )
        SELECT
            f.id, f.scan_id, f.user_id, f.title, f.severity, f.description, f.evidence, f.tool, f.target,
            f.cve_id, f.cvss_score, f.mitre_technique, f.source, f.extra::jsonb, f.created_at
        FROM findings f
        ON CONFLICT DO NOTHING;
        """
    )
    op.execute(
        """
        INSERT INTO audit_logs_partitioned (
            id, user_id, action, resource, resource_id, ip_address, extra, created_at
        )
        SELECT
            a.id::bigint, a.user_id, a.action, a.resource, a.resource_id, a.ip_address, a.extra::jsonb, a.created_at
        FROM audit_logs a
        ON CONFLICT DO NOTHING;
        """
    )
    op.execute(
        """
        CREATE MATERIALIZED VIEW IF NOT EXISTS dashboard_stats AS
        SELECT
            now() AS refreshed_at,
            COALESCE((SELECT COUNT(*) FROM scans), 0) AS total_scans,
            COALESCE((SELECT COUNT(*) FROM findings), 0) AS total_findings,
            COALESCE((SELECT COUNT(*) FROM findings WHERE severity = 'critical'), 0) AS critical_findings,
            COALESCE((SELECT COUNT(*) FROM findings WHERE severity = 'high'), 0) AS high_findings,
            COALESCE((SELECT COUNT(*) FROM findings WHERE severity = 'medium'), 0) AS medium_findings,
            COALESCE((SELECT COUNT(*) FROM findings WHERE severity = 'low'), 0) AS low_findings,
            COALESCE((SELECT COUNT(*) FROM findings WHERE severity = 'info'), 0) AS info_findings,
            COALESCE((SELECT COUNT(*) FROM scans WHERE created_at >= now() - interval '24 hours'), 0) AS scans_24h,
            COALESCE((SELECT COUNT(*) FROM findings WHERE created_at >= now() - interval '24 hours'), 0) AS findings_24h;
        """
    )
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ix_dashboard_stats_singleton
        ON dashboard_stats ((1));
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute("DROP INDEX IF EXISTS ix_dashboard_stats_singleton")
    op.execute("DROP MATERIALIZED VIEW IF EXISTS dashboard_stats")
    op.execute("DROP TABLE IF EXISTS findings_partitioned CASCADE")
    op.execute("DROP TABLE IF EXISTS audit_logs_partitioned CASCADE")
