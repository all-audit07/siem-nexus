-- ============================================================
--  SIEM MULTI-MOTOR — PostgreSQL Schema
--  Motor: PostgreSQL 16 (Docker)
--  DB:    siem_correlation
--  Rol:   Motor de correlación e incidentes
--  v3.0 — Enfoque Híbrido C + Gobernanza
-- ============================================================
-- Ejecutar con:
--   docker exec -it siem_postgres psql -U postgres -d siem_correlation -f schema.sql
-- ============================================================


-- ------------------------------------------------------------
-- 0. EXTENSIONES
--    gen_random_uuid() está disponible de serie en PG 13+,
--    pero la declaramos explícitamente para claridad.
-- ------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
-- uuid-ossp provee uuid_generate_v4(); en PG 13+ se prefiere
-- gen_random_uuid() que no necesita extensión, pero la
-- incluimos para compatibilidad y demostración de extensiones.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


-- ============================================================
-- 1. TIPOS ENUMERADOS
--    PostgreSQL soporta CREATE TYPE ENUM (feature exclusivo vs
--    MySQL ENUM a nivel de motor, vs CHECK CONSTRAINT en MSSQL/Oracle)
-- ============================================================

-- Estado de incidente
CREATE TYPE incident_status_t AS ENUM (
    'open',
    'investigating',
    'contained',
    'resolved'
);

-- Estado de vulnerabilidad
CREATE TYPE vuln_status_t AS ENUM (
    'open',
    'mitigated',
    'accepted',
    'resolved'
);


-- ============================================================
-- 2. TABLAS CORE
--    Compartidas con MySQL, SQL Server y Oracle para benchmark.
--    Mismos nombres de columnas (convención snake_case global).
-- ============================================================

-- ------------------------------------------------------------
-- 2.1 users
--     Fuente de verdad: MySQL. Aquí es réplica para queries
--     locales. user_uuid es la clave de correlación cross-motor.
-- ------------------------------------------------------------
CREATE TABLE users (
    id          SERIAL          PRIMARY KEY,
    uuid        UUID            NOT NULL DEFAULT gen_random_uuid(),
    username    VARCHAR(30)     NOT NULL,   -- RFC: máx razonable; previene abuso de almacenamiento
    email       VARCHAR(254)    NOT NULL,   -- RFC 5321: máximo real de una dirección email
    role        VARCHAR(10)     NOT NULL DEFAULT 'analyst',  -- 'analyst'=7 chars; 10 es el techo
    is_active   BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_users_uuid      UNIQUE (uuid),
    CONSTRAINT uq_users_email     UNIQUE (email),
    CONSTRAINT uq_users_username  UNIQUE (username),
    CONSTRAINT chk_users_role     CHECK  (role IN ('admin','analyst','viewer','auditor')),
    -- Sólo letras, dígitos, guión y guión_bajo; sin espacios ni caracteres especiales
    CONSTRAINT chk_users_username_fmt CHECK (username ~ '^[a-zA-Z0-9_\-]{3,30}$'),
    -- Validación mínima de email: debe contener @ y al menos un punto después
    CONSTRAINT chk_users_email_fmt    CHECK (email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$')
);

COMMENT ON TABLE  users               IS 'Réplica de usuarios para queries locales. Fuente de verdad: MySQL.';
COMMENT ON COLUMN users.uuid          IS 'Clave de correlación cross-motor. Referenciada por audit_logs y incidents.';
COMMENT ON COLUMN users.role          IS 'admin | analyst | viewer | auditor';


-- ------------------------------------------------------------
-- 2.2 security_events
--     Eventos de seguridad capturados. Tabla estrella del
--     benchmark de INSERT/SELECT masivo.
--     INET: tipo nativo PostgreSQL para IPv4/IPv6.
-- ------------------------------------------------------------
CREATE TABLE security_events (
    id              BIGSERIAL       PRIMARY KEY,
    uuid            UUID            NOT NULL DEFAULT gen_random_uuid(),
    event_type      VARCHAR(50)     NOT NULL,   -- suficiente para cualquier tipo predefinido
    severity        SMALLINT        NOT NULL,
    source_ip       INET,                        -- tipo INET nativo PG
    dest_ip         INET,                        -- tipo INET nativo PG
    source_port     INTEGER,                     -- rango válido 0-65535 (ver CHECK abajo)
    dest_port       INTEGER,                     -- rango válido 0-65535 (ver CHECK abajo)
    protocol        VARCHAR(6),                  -- máx real: 'ICMPV6' = 6 chars (RFC)
    hostname        VARCHAR(253),                -- RFC 1035: máximo real de un hostname
    description     VARCHAR(1000),               -- TEXT ilimitado es riesgo; 1000 es suficiente
    raw_payload     JSONB,                       -- JSONB: indexable y binario
    is_enriched     BOOLEAN         NOT NULL DEFAULT FALSE,
    occurred_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_events_severity    CHECK (severity BETWEEN 1 AND 5),
    -- Puertos TCP/UDP válidos: 0–65535
    CONSTRAINT chk_events_source_port CHECK (source_port IS NULL OR source_port BETWEEN 0 AND 65535),
    CONSTRAINT chk_events_dest_port   CHECK (dest_port   IS NULL OR dest_port   BETWEEN 0 AND 65535)
);

COMMENT ON TABLE  security_events            IS 'Eventos de seguridad. Tabla CORE compartida — benchmark principal INSERT/SELECT.';
COMMENT ON COLUMN security_events.source_ip  IS 'INET: tipo nativo PG. Soporta IPv4 e IPv6. Permite operadores de red como <<, >>=.';
COMMENT ON COLUMN security_events.raw_payload IS 'JSONB: binario, indexable con GIN. Diferente a JSON texto de MySQL/SQL Server.';
COMMENT ON COLUMN security_events.occurred_at IS 'Momento del evento. Nombre canónico shared entre los 4 motores.';


-- ------------------------------------------------------------
-- 2.3 alerts
--     Alertas generadas a partir de eventos.
--     FK física a security_events (relación 1:N).
--     assigned_to_uuid: referencia lógica cross-motor a MySQL users.
-- ------------------------------------------------------------
CREATE TABLE alerts (
    id                  BIGSERIAL   PRIMARY KEY,
    uuid                UUID        NOT NULL DEFAULT gen_random_uuid(),
    event_id            BIGINT      REFERENCES security_events(id) ON DELETE SET NULL,
    title               VARCHAR(150) NOT NULL,   -- 150 es suficiente para un título de alerta
    description         VARCHAR(2000),            -- TEXT ilimitado reemplazado por límite razonable
    severity            SMALLINT    NOT NULL,
    status              VARCHAR(20)  NOT NULL DEFAULT 'open',  -- 'false_positive'=14 chars; 20 es techo
    assigned_to_uuid    UUID,                        -- ref lógica cross-motor → MySQL users.uuid
    false_positive      BOOLEAN      NOT NULL DEFAULT FALSE,
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_alerts_uuid    UNIQUE (uuid),
    CONSTRAINT chk_alerts_sev    CHECK  (severity BETWEEN 1 AND 5),
    CONSTRAINT chk_alerts_status CHECK  (status IN ('open','acknowledged','investigating','resolved','false_positive'))
);

COMMENT ON TABLE  alerts                  IS 'Alertas CORE. FK física → security_events. assigned_to_uuid es ref lógica a MySQL.';
COMMENT ON COLUMN alerts.assigned_to_uuid IS 'Referencia lógica cross-motor. El DB Adapter de Node.js resuelve este UUID contra MySQL users.';


-- ------------------------------------------------------------
-- 2.4 audit_logs
--     Log de auditoría de acciones del sistema.
--     Alta velocidad de INSERT — ideal para benchmark.
--     user_uuid: referencia lógica cross-motor a MySQL users.
-- ------------------------------------------------------------
CREATE TABLE audit_logs (
    id          BIGSERIAL       PRIMARY KEY,
    user_uuid   UUID,                        -- ref lógica → MySQL users.uuid
    action      VARCHAR(50)     NOT NULL,    -- acciones predefinidas cortas: 'login', 'delete_alert', etc.
    target_type VARCHAR(40),                 -- nombre de tabla/entidad: 'security_events', 'incidents'
    target_id   BIGINT,
    old_values  JSONB,                       -- estado anterior para rollback/auditoría
    new_values  JSONB,                       -- estado nuevo
    ip_address  INET,                        -- INET nativo (vs VARCHAR(45) en otros motores)
    occurred_at TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE  audit_logs            IS 'Auditoría de acciones. Benchmark: INSERT 10,000 filas para comparar los 4 motores.';
COMMENT ON COLUMN audit_logs.old_values IS 'JSONB: permite rollback. Consultable con ->, ->>, @>.';
COMMENT ON COLUMN audit_logs.ip_address IS 'INET: valida formato IP automáticamente. MySQL/MSSQL/Oracle usan VARCHAR(45).';


-- ============================================================
-- 3. TABLAS EXCLUSIVAS POSTGRESQL
--    Demuestran features únicos: JSONB+GIN, ARRAY, INET,
--    TSRANGE, BOOLEAN nativo, TIMESTAMPTZ, NUMERIC preciso.
-- ============================================================

-- ------------------------------------------------------------
-- 3.1 correlation_rules
--     Reglas SIEM almacenadas como JSONB.
--     GIN index sobre pattern para queries como:
--       WHERE pattern @> '{"event_type": "login_fail"}'
-- ------------------------------------------------------------
CREATE TABLE correlation_rules (
    id                  SERIAL          PRIMARY KEY,
    name                VARCHAR(100)    NOT NULL,   -- nombres de reglas no necesitan 150 chars
    description         VARCHAR(500),               -- TEXT ilimitado reemplazado; 500 es suficiente
    pattern             JSONB           NOT NULL,    -- condiciones, umbrales, ventanas de tiempo
    event_types         TEXT[],                      -- ARRAY: tipos de evento que disparan la regla
    time_window_secs    INTEGER,                     -- ventana de correlación en segundos
    threshold           INTEGER,                     -- nº mínimo de eventos para activar
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,   -- BOOLEAN nativo (vs BIT en MSSQL)
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_rules_name  UNIQUE (name),
    CONSTRAINT chk_rules_tw   CHECK  (time_window_secs > 0),
    CONSTRAINT chk_rules_thr  CHECK  (threshold > 0)
);

COMMENT ON TABLE  correlation_rules          IS 'Reglas de correlación SIEM. Feature: JSONB + índice GIN + ARRAY + BOOLEAN nativo.';
COMMENT ON COLUMN correlation_rules.pattern  IS 'JSONB: almacenado en binario. Índice GIN permite queries como WHERE pattern @> ''{"event_type":"login_fail"}''.';
COMMENT ON COLUMN correlation_rules.event_types IS 'TEXT[]: ARRAY nativo PG. Evita tabla de relación. Índice GIN permite WHERE ''login_fail'' = ANY(event_types).';
COMMENT ON COLUMN correlation_rules.is_active IS 'BOOLEAN nativo PG. MySQL usa TINYINT(1), SQL Server usa BIT, Oracle usa NUMBER(1).';


-- ------------------------------------------------------------
-- 3.2 incidents
--     Incidentes correlacionados de seguridad.
--     Features exclusivos:
--       - UUID sin extensión (gen_random_uuid())
--       - TEXT[] para activos afectados y tácticas MITRE
--       - TSRANGE para rango temporal del incidente
--       - JSONB para metadata adicional indexable
--       - FK a correlation_rules
--       - assigned_to_uuid: ref lógica cross-motor a MySQL
-- ------------------------------------------------------------
CREATE TABLE incidents (
    id                  BIGSERIAL           PRIMARY KEY,
    uuid                UUID                NOT NULL DEFAULT gen_random_uuid(),
    rule_id             INTEGER             REFERENCES correlation_rules(id) ON DELETE SET NULL,
    title               VARCHAR(150)        NOT NULL,   -- alineado con alerts.title
    severity            SMALLINT            NOT NULL,
    status              incident_status_t   NOT NULL DEFAULT 'open',   -- ENUM personalizado PG
    affected_assets     TEXT[],                     -- ARRAY: IPs/hostnames afectados
    mitre_tactics       TEXT[],                     -- ARRAY: tácticas MITRE ATT&CK
    timeline            TSRANGE,                    -- TSRANGE: rango temporal nativo PG
    metadata            JSONB,                      -- JSONB: datos extra indexables
    assigned_to_uuid    UUID,                       -- ref lógica → MySQL users.uuid
    correlation_score   NUMERIC(5,2),               -- score SIEM con precisión exacta
    created_at          TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_incidents_uuid UNIQUE (uuid),
    CONSTRAINT chk_inc_severity  CHECK  (severity BETWEEN 1 AND 5),
    CONSTRAINT chk_inc_score     CHECK  (correlation_score >= 0 AND correlation_score <= 100)
);

COMMENT ON TABLE  incidents                IS 'Incidentes correlacionados. Tabla más rica del SIEM — demuestra los 5 features exclusivos PG.';
COMMENT ON COLUMN incidents.uuid           IS 'gen_random_uuid(): no necesita extensión en PG 13+. Clave de correlación distribuida.';
COMMENT ON COLUMN incidents.status         IS 'Tipo ENUM personalizado (incident_status_t). Más expresivo que CHECK CONSTRAINT.';
COMMENT ON COLUMN incidents.affected_assets IS 'TEXT[]: ARRAY nativo. Soporta operadores @>, &&, = ANY(). Sin tabla adicional.';
COMMENT ON COLUMN incidents.mitre_tactics  IS 'TEXT[]: tácticas MITRE ATT&CK (ej: {Persistence, Lateral Movement}).';
COMMENT ON COLUMN incidents.timeline       IS 'TSRANGE: rango temporal [inicio, fin). Permite queries como WHERE timeline @> NOW()::timestamp.';
COMMENT ON COLUMN incidents.metadata       IS 'JSONB: índice GIN. Permite WHERE metadata @> ''{"category":"brute_force"}''.';
COMMENT ON COLUMN incidents.correlation_score IS 'NUMERIC(5,2): precisión exacta vs FLOAT. Ej: 87.35.';


-- ------------------------------------------------------------
-- 3.3 vulnerabilities
--     Vulnerabilidades en activos monitoreados.
--     Features: INET para asset_ip, NUMERIC para CVSS,
--               JSONB para detalles técnicos.
-- ------------------------------------------------------------
CREATE TABLE vulnerabilities (
    id              SERIAL          PRIMARY KEY,
    cve_id          VARCHAR(20),                    -- CVE-YYYY-NNNNN (máx ~17 chars reales)
    title           VARCHAR(150)    NOT NULL,        -- alineado con incidents.title
    cvss_score      NUMERIC(3,1),                   -- 0.0–10.0 con precisión exacta
    affected_asset  VARCHAR(253)    NOT NULL,        -- RFC 1035: alineado con hostname
    asset_ip        INET,                           -- INET: tipo nativo PG para IPv4/IPv6
    status          vuln_status_t   NOT NULL DEFAULT 'open',
    details         JSONB,                          -- detalles técnicos indexables
    detected_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_vuln_cvss CHECK (cvss_score >= 0.0 AND cvss_score <= 10.0)
);

COMMENT ON TABLE  vulnerabilities           IS 'Vulnerabilidades detectadas. Features: INET nativo, NUMERIC preciso, JSONB, ENUM.';
COMMENT ON COLUMN vulnerabilities.asset_ip  IS 'INET: valida formato IPv4/IPv6 automáticamente. Permite operadores de red: <<= (subnet), >> (supernet).';
COMMENT ON COLUMN vulnerabilities.cvss_score IS 'NUMERIC(3,1): precisión exacta para scores CVSS. Evita errores de redondeo de FLOAT.';


-- ============================================================
-- 4. TABLAS INTERMEDIAS (N:M)
-- ============================================================

-- ------------------------------------------------------------
-- 4.1 incident_vulns
--     N:M física dentro de PostgreSQL: incidents ↔ vulnerabilities
-- ------------------------------------------------------------
CREATE TABLE incident_vulns (
    incident_id         BIGINT  NOT NULL REFERENCES incidents(id)       ON DELETE CASCADE,
    vulnerability_id    INTEGER NOT NULL REFERENCES vulnerabilities(id)  ON DELETE CASCADE,
    linked_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (incident_id, vulnerability_id)
);

COMMENT ON TABLE incident_vulns IS 'Tabla intermedia N:M entre incidents y vulnerabilities (relación física dentro de PostgreSQL).';


-- ------------------------------------------------------------
-- 4.2 incident_events (referencia lógica cross-motor)
--     Vincula incidents (PostgreSQL) con security_events
--     que viven en otros motores. No tiene FK física hacia
--     afuera — la integridad es responsabilidad del Adapter.
-- ------------------------------------------------------------
CREATE TABLE incident_events (
    id              BIGSERIAL   PRIMARY KEY,
    incident_id     BIGINT      NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_uuid      UUID        NOT NULL,    -- UUID del security_event en cualquier motor
    source_engine   VARCHAR(15) NOT NULL,    -- 'postgresql'=10 chars (el más largo); 15 es el techo
    linked_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_ie_engine CHECK (source_engine IN ('mysql','sqlserver','postgresql','oracle'))
);

COMMENT ON TABLE  incident_events             IS 'Vincula incidentes con eventos de cualquier motor (ref lógica cross-DB). FK física solo al lado PG.';
COMMENT ON COLUMN incident_events.event_uuid  IS 'UUID del security_event en el motor de origen. El Adapter resuelve la referencia.';
COMMENT ON COLUMN incident_events.source_engine IS 'Motor de origen del evento: mysql | sqlserver | postgresql | oracle.';


-- ============================================================
-- 5. ÍNDICES
--    PostgreSQL brilla en diversidad de índices:
--    B-Tree (default), GIN (JSON/arrays), BRIN (timestamps).
-- ============================================================

-- --- CORE: users ---
CREATE INDEX idx_users_uuid       ON users(uuid);
CREATE INDEX idx_users_email      ON users(email);
CREATE INDEX idx_users_is_active  ON users(is_active);

-- --- CORE: security_events ---
CREATE INDEX idx_events_severity    ON security_events(severity);
CREATE INDEX idx_events_occurred_at ON security_events(occurred_at DESC);
CREATE INDEX idx_events_event_type  ON security_events(event_type);
CREATE INDEX idx_events_source_ip   ON security_events USING GIST(source_ip);  -- GIST para INET
-- GIN sobre raw_payload JSONB: permite WHERE raw_payload @> '{"key":"val"}'
CREATE INDEX idx_events_raw_payload ON security_events USING GIN(raw_payload);

-- --- CORE: alerts ---
CREATE INDEX idx_alerts_status      ON alerts(status);
CREATE INDEX idx_alerts_severity    ON alerts(severity);
CREATE INDEX idx_alerts_event_id    ON alerts(event_id);
CREATE INDEX idx_alerts_created_at  ON alerts(created_at DESC);

-- --- CORE: audit_logs ---
CREATE INDEX idx_audit_user_uuid    ON audit_logs(user_uuid);
CREATE INDEX idx_audit_occurred_at  ON audit_logs(occurred_at DESC);
CREATE INDEX idx_audit_action       ON audit_logs(action);
-- GIN sobre old_values/new_values para búsquedas en cambios
CREATE INDEX idx_audit_new_values   ON audit_logs USING GIN(new_values);

-- --- EXCLUSIVA: correlation_rules ---
-- GIN sobre pattern JSONB (EL índice más importante de las reglas)
CREATE INDEX idx_rules_pattern      ON correlation_rules USING GIN(pattern);
-- GIN sobre event_types TEXT[] — permite WHERE 'login_fail' = ANY(event_types)
CREATE INDEX idx_rules_event_types  ON correlation_rules USING GIN(event_types);
CREATE INDEX idx_rules_is_active    ON correlation_rules(is_active);

-- --- EXCLUSIVA: incidents ---
CREATE INDEX idx_inc_status         ON incidents(status);
CREATE INDEX idx_inc_severity       ON incidents(severity);
CREATE INDEX idx_inc_rule_id        ON incidents(rule_id);
CREATE INDEX idx_inc_created_at     ON incidents(created_at DESC);
-- GIN sobre affected_assets TEXT[]
CREATE INDEX idx_inc_affected_assets ON incidents USING GIN(affected_assets);
-- GIN sobre mitre_tactics TEXT[]
CREATE INDEX idx_inc_mitre_tactics   ON incidents USING GIN(mitre_tactics);
-- GIN sobre metadata JSONB
CREATE INDEX idx_inc_metadata        ON incidents USING GIN(metadata);
-- GiST sobre timeline TSRANGE (range queries)
CREATE INDEX idx_inc_timeline        ON incidents USING GIST(timeline);

-- --- EXCLUSIVA: vulnerabilities ---
CREATE INDEX idx_vuln_status         ON vulnerabilities(status);
CREATE INDEX idx_vuln_cvss           ON vulnerabilities(cvss_score DESC);
CREATE INDEX idx_vuln_detected_at    ON vulnerabilities(detected_at DESC);
CREATE INDEX idx_vuln_asset_ip       ON vulnerabilities USING GIST(asset_ip);
CREATE INDEX idx_vuln_details        ON vulnerabilities USING GIN(details);

-- --- INTERMEDIAS ---
CREATE INDEX idx_ie_incident_id      ON incident_events(incident_id);
CREATE INDEX idx_ie_event_uuid       ON incident_events(event_uuid);


-- ============================================================
-- 6. VISTAS
--    Prefijo v_ según convención global de nombres.
-- ============================================================

-- Vista 1: Resumen de incidentes con nombre de regla
CREATE VIEW v_incidents_summary AS
SELECT
    i.id,
    i.uuid,
    i.title,
    i.severity,
    i.status,
    i.correlation_score,
    i.affected_assets,
    i.mitre_tactics,
    cr.name         AS rule_name,
    i.created_at
FROM incidents i
LEFT JOIN correlation_rules cr ON cr.id = i.rule_id
ORDER BY i.created_at DESC;

COMMENT ON VIEW v_incidents_summary IS 'Incidentes con nombre de regla correlacionada. Uso directo en dashboard.';


-- Vista 2: Reglas activas con conteo de incidentes generados
CREATE VIEW v_active_rules_stats AS
SELECT
    cr.id,
    cr.name,
    cr.is_active,
    cr.time_window_secs,
    cr.threshold,
    COUNT(i.id)     AS total_incidents,
    MAX(i.created_at) AS last_incident_at
FROM correlation_rules cr
LEFT JOIN incidents i ON i.rule_id = cr.id
WHERE cr.is_active = TRUE
GROUP BY cr.id, cr.name, cr.is_active, cr.time_window_secs, cr.threshold
ORDER BY total_incidents DESC;

COMMENT ON VIEW v_active_rules_stats IS 'Reglas activas con conteo de incidentes. Útil para ajustar umbrales.';


-- Vista 3: Vulnerabilidades abiertas por score CVSS
CREATE VIEW v_open_vulnerabilities AS
SELECT
    id,
    cve_id,
    title,
    cvss_score,
    affected_asset,
    asset_ip::TEXT  AS asset_ip,     -- cast a texto para compatibilidad con clientes JDBC
    status,
    detected_at
FROM vulnerabilities
WHERE status = 'open'
ORDER BY cvss_score DESC NULLS LAST;

COMMENT ON VIEW v_open_vulnerabilities IS 'Vulnerabilidades abiertas ordenadas por criticidad CVSS.';


-- Vista 4: Actividad de analistas (últimas 7 días)
CREATE VIEW v_analyst_activity AS
SELECT
    user_uuid,
    COUNT(*)                AS total_actions,
    COUNT(DISTINCT action)  AS action_types,
    MAX(occurred_at)        AS last_action
FROM audit_logs
WHERE occurred_at >= NOW() - INTERVAL '7 days'
GROUP BY user_uuid
ORDER BY total_actions DESC;

COMMENT ON VIEW v_analyst_activity IS 'Actividad de analistas en los últimos 7 días. Benchmark: usa INTERVAL nativo de PG.';


-- Vista 5: Eventos críticos recientes (severity >= 4)
CREATE VIEW v_critical_events AS
SELECT
    id,
    uuid,
    event_type,
    severity,
    source_ip::TEXT AS source_ip,
    dest_ip::TEXT   AS dest_ip,
    hostname,
    occurred_at
FROM security_events
WHERE severity >= 4
  AND occurred_at >= NOW() - INTERVAL '24 hours'
ORDER BY occurred_at DESC;

COMMENT ON VIEW v_critical_events IS 'Eventos de severidad 4-5 en las últimas 24 horas.';


-- ============================================================
-- 7. FUNCIONES AUXILIARES (PL/pgSQL)
--    Demuestran PL/pgSQL — exclusivo de PostgreSQL.
-- ============================================================

-- Función: calcular score de correlación por ventana de tiempo
CREATE OR REPLACE FUNCTION fn_calc_correlation_score(
    p_event_count   INTEGER,
    p_window_secs   INTEGER,
    p_threshold     INTEGER
) RETURNS NUMERIC(5,2)
LANGUAGE plpgsql
AS $$
DECLARE
    v_ratio     NUMERIC;
    v_score     NUMERIC(5,2);
BEGIN
    IF p_threshold IS NULL OR p_threshold = 0 THEN
        RETURN 0;
    END IF;
    v_ratio := p_event_count::NUMERIC / p_threshold::NUMERIC;
    v_score := LEAST(v_ratio * 50, 100);    -- cap en 100
    RETURN ROUND(v_score, 2);
END;
$$;

COMMENT ON FUNCTION fn_calc_correlation_score IS
    'Calcula un correlation_score 0-100 basado en cuántas veces se superó el threshold.';


-- ============================================================
-- FIN DEL SCHEMA
-- ============================================================
-- Resumen de objetos creados:
--
--   Extensiones  : 2 (pgcrypto, uuid-ossp)
--   Tipos ENUM   : 2 (incident_status_t, vuln_status_t)
--   Tablas CORE  : 4 (users, security_events, alerts, audit_logs)
--   Tablas excl. : 3 (correlation_rules, incidents, vulnerabilities)
--   Tablas N:M   : 2 (incident_vulns, incident_events)
--   Índices      : 28 (B-Tree, GIN, GiST)
--   Vistas       : 5 (v_ prefix)
--   Funciones    : 1 (fn_calc_correlation_score)
--
-- Medidas de seguridad aplicadas (v3.1):
--   - VARCHAR dimensionados según estándares RFC (email=254, hostname=253)
--   - TEXT ilimitado eliminado; reemplazado por VARCHAR con techo razonable
--   - CHECK de formato en users.username (regex: solo alfanumérico/_/-)
--   - CHECK de formato básico en users.email (debe contener @)
--   - CHECK de rango en source_port/dest_port (0–65535 TCP/UDP)
--   - source_engine reducido a VARCHAR(15) y protegido por CHECK de valores
--   - Todos los campos de status protegidos por CHECK o tipo ENUM
-- ============================================================
