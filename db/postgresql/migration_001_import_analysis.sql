-- =============================================================================
-- SIEM NEXUS — PostgreSQL (siem_correlation)
-- migration_001_import_analysis.sql
-- Objetivo: soportar importación de Excel, reglas de detección, alertas con
--           evidencia trazable (Log_ID) e informes técnicos.
-- Idempotente: puede ejecutarse más de una vez sin error.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. log_imports — cada archivo Excel importado
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_imports (
    id                BIGSERIAL    PRIMARY KEY,
    uuid              UUID         NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    file_name         VARCHAR(255) NOT NULL,
    file_sha256       CHAR(64)     NOT NULL,           -- evita importar dos veces el mismo archivo
    sheet_name        VARCHAR(100),
    source_timezone   VARCHAR(50)  NOT NULL,           -- zona horaria asumida para Timestamp
    rows_total        INTEGER      NOT NULL DEFAULT 0,
    rows_valid        INTEGER      NOT NULL DEFAULT 0,
    rows_rejected     INTEGER      NOT NULL DEFAULT 0,
    rejected_details  JSONB,                           -- [{row, log_id, motivo}]
    status            VARCHAR(20)  NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','imported','analyzed','failed')),
    imported_by_uuid  UUID,                            -- ref. lógica a users.uuid (MySQL)
    imported_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    analyzed_at       TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_log_imports_sha ON log_imports (file_sha256);

-- -----------------------------------------------------------------------------
-- 2. security_events — columnas para los campos del Excel
--    event_type  = categoría normalizada (logon_failure, process_creation...)
--    event_code  = Event_ID original (4625, PROXY_ACCESS, HTTP_ACCESS...)
--    raw_payload = fila original completa, sin modificar
--    import_id NULL = eventos demo previos
-- -----------------------------------------------------------------------------
ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS import_id       BIGINT REFERENCES log_imports(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS source_log_id   VARCHAR(40),
    ADD COLUMN IF NOT EXISTS event_code      VARCHAR(40),
    ADD COLUMN IF NOT EXISTS user_name       VARCHAR(150),
    ADD COLUMN IF NOT EXISTS destination     VARCHAR(255),   -- host, host:puerto o ruta UNC
    ADD COLUMN IF NOT EXISTS log_source      VARCHAR(40),
    ADD COLUMN IF NOT EXISTS command_line    TEXT,
    ADD COLUMN IF NOT EXISTS result          VARCHAR(20),
    ADD COLUMN IF NOT EXISTS source_severity VARCHAR(20);    -- severidad del sensor, literal

CREATE UNIQUE INDEX IF NOT EXISTS uq_events_import_logid
    ON security_events (import_id, source_log_id) WHERE import_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_import       ON security_events (import_id);
CREATE INDEX IF NOT EXISTS idx_events_user_time    ON security_events (user_name, occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_srcip_time   ON security_events (source_ip, occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_host_time    ON security_events (hostname, occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_code_time    ON security_events (event_code, occurred_at);

-- -----------------------------------------------------------------------------
-- 3. correlation_rules — metadatos de las reglas de detección
-- -----------------------------------------------------------------------------
ALTER TABLE correlation_rules
    ADD COLUMN IF NOT EXISTS code             VARCHAR(50) UNIQUE,
    ADD COLUMN IF NOT EXISTS category         VARCHAR(30)
        CHECK (category IN ('brute_force','suspicious_login','privilege_escalation',
                            'process_execution','lateral_movement','anomaly')),
    ADD COLUMN IF NOT EXISTS severity         SMALLINT CHECK (severity BETWEEN 2 AND 5),
    ADD COLUMN IF NOT EXISTS version          INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[];

-- -----------------------------------------------------------------------------
-- 4. alerts — trazabilidad hacia regla, incidente y ventana temporal
-- -----------------------------------------------------------------------------
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS import_id     BIGINT  REFERENCES log_imports(id)       ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS rule_id       INTEGER REFERENCES correlation_rules(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS rule_version  INTEGER,
    ADD COLUMN IF NOT EXISTS incident_id   BIGINT  REFERENCES incidents(id)         ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS justification TEXT,
    ADD COLUMN IF NOT EXISTS window_start  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS window_end    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS analyzed_at   TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_alerts_import   ON alerts (import_id);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts (incident_id);

-- -----------------------------------------------------------------------------
-- 5. alert_evidence — N eventos (Log_ID) que sustentan cada alerta
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_evidence (
    alert_id  BIGINT      NOT NULL REFERENCES alerts(id)          ON DELETE CASCADE,
    event_id  BIGINT      NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
    role      VARCHAR(20) NOT NULL DEFAULT 'supporting'
              CHECK (role IN ('trigger','supporting','context')),
    PRIMARY KEY (alert_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_evidence_event ON alert_evidence (event_id);

-- -----------------------------------------------------------------------------
-- 6. incidents — vínculo con la importación
-- -----------------------------------------------------------------------------
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS import_id BIGINT REFERENCES log_imports(id) ON DELETE CASCADE;

-- -----------------------------------------------------------------------------
-- 7. reports — informes técnicos generados
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id                    BIGSERIAL    PRIMARY KEY,
    uuid                  UUID         NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    import_id             BIGINT       NOT NULL REFERENCES log_imports(id) ON DELETE CASCADE,
    title                 VARCHAR(200) NOT NULL,
    content               JSONB        NOT NULL,   -- secciones estructuradas del informe
    ai_model              VARCHAR(100),            -- NULL si no se usó IA
    ai_generated_sections TEXT[],                  -- qué secciones redactó la IA
    validation_status     VARCHAR(20)  NOT NULL DEFAULT 'pending'
                          CHECK (validation_status IN ('pending','valid','rejected')),
    validation_errors     JSONB,                   -- p. ej. Log_ID citados que no existen
    generated_by_uuid     UUID,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reports_import ON reports (import_id);

COMMIT;
