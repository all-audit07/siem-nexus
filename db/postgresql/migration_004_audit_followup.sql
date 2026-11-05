-- v2.0 · Seguimiento de hallazgos de auditoría: quién cerró y verificó cada hallazgo,
-- y un historial inmutable de todos los cambios. Idempotente.

BEGIN;

ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS closed_by    TEXT;
ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS verified_by  TEXT;
ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS verified_at  TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS audit_finding_history (
    id           SERIAL PRIMARY KEY,
    finding_id   INTEGER     NOT NULL REFERENCES audit_findings(id) ON DELETE CASCADE,
    changed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    changed_by   TEXT        NOT NULL,
    changed_role TEXT        NOT NULL,
    old_status   VARCHAR(16),
    new_status   VARCHAR(16),
    old_owner    TEXT,
    new_owner    TEXT,
    note         TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_history_finding ON audit_finding_history(finding_id, changed_at);

-- Ningún registro del historial puede modificarse: ni la aplicación ni un usuario con acceso a la base
-- pueden alterarlo sin desactivar antes este disparador, lo que deja rastro en el esquema.
-- (Borrar solo ocurre en cascada, al eliminar la importación completa.)
CREATE OR REPLACE FUNCTION audit_history_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_finding_history es de solo inserción';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_history_append_only ON audit_finding_history;
CREATE TRIGGER trg_audit_history_append_only
    BEFORE UPDATE ON audit_finding_history
    FOR EACH ROW EXECUTE FUNCTION audit_history_append_only();

COMMIT;
