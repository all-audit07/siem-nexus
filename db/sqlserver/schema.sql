/* ============================================================================
   SIEM Multi-Motor — SQL Server (Motor 02 — T-SQL — :1433)
   Rol: Captura, ingesta y almacenamiento operacional de eventos
   schema.sql — basado en "Esquema de Dominios SIEM v3.0" + governance v3
   ----------------------------------------------------------------------------
   IMPORTANTE — reglas de autoridad (fuente de verdad):
     - SQL Server NO administra usuarios -> users es SOLO LECTURA (réplica).
     - SQL Server es AUTORIDAD de: security_events.
     - SQL Server NUNCA almacena password_hash ni roles administrativos.
     - SQL Server NUNCA hace UPDATE sobre un security_events original:
       todo re-procesamiento es un INSERT nuevo (ver versionado v2 abajo).
   ============================================================================ */

CREATE DATABASE siem_events;
GO

USE siem_events;
GO

/* ============================================================================
   1. TABLAS CORE — estructura lógica idéntica en los 4 motores
   ============================================================================ */

-- ----------------------------------------------------------------------------
-- users (RÉPLICA DE SOLO LECTURA — autoridad real: MySQL)
-- Solo se sincronizan: id, uuid, username, email, full_name, status,
-- last_login_at, created_at. JAMÁS password_hash ni roles administrativos.
-- id NO usa IDENTITY: debe coincidir exactamente con el id del maestro MySQL.
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    id              INT                 NOT NULL PRIMARY KEY,
    uuid            UNIQUEIDENTIFIER    NOT NULL UNIQUE,
    username        NVARCHAR(60)        NOT NULL UNIQUE,
    email           NVARCHAR(120)       NOT NULL UNIQUE,
    full_name       NVARCHAR(120)       NOT NULL,
    status          NVARCHAR(20)        NOT NULL DEFAULT 'active'
                        CONSTRAINT ck_users_status
                        CHECK (status IN ('active','inactive','locked')),
    last_login_at   DATETIMEOFFSET      NULL,
    created_at      DATETIMEOFFSET      NOT NULL DEFAULT SYSDATETIMEOFFSET()
);
GO

-- ----------------------------------------------------------------------------
-- security_events (CORE — AUTORIDAD de SQL Server)
-- occurred_at usa DATETIMEOFFSET: feature exclusivo de SQL Server que guarda
-- el offset de timezone explícito junto con la fecha/hora.
-- Incluye versionado v2 (gobernanza v3): nunca se hace UPDATE de un evento
-- original; cada re-procesamiento es un INSERT con version+1 y
-- original_event_id apuntando al registro original.
-- ----------------------------------------------------------------------------
CREATE TABLE security_events (
    id                  BIGINT              IDENTITY(1,1) PRIMARY KEY,
    event_uuid          UNIQUEIDENTIFIER    NOT NULL DEFAULT NEWID(),

    event_type          NVARCHAR(60)        NOT NULL,
    severity            TINYINT             NOT NULL
                            CONSTRAINT ck_events_severity
                            CHECK (severity BETWEEN 1 AND 5),
    source_ip           NVARCHAR(45)        NULL,
    dest_ip             NVARCHAR(45)        NULL,
    user_uuid           UNIQUEIDENTIFIER    NULL,
    description         NVARCHAR(MAX)       NULL,
    raw_payload         NVARCHAR(MAX)       NULL,   -- solo dato original del sensor, inmutable

    occurred_at         DATETIMEOFFSET      NOT NULL,
    ingested_at         DATETIMEOFFSET      NOT NULL DEFAULT SYSDATETIMEOFFSET(),

    -- Versionado de eventos (security_events v2 — gobernanza v3)
    version             TINYINT             NOT NULL DEFAULT 1,
    is_enriched         BIT                 NOT NULL DEFAULT 0,
    original_event_id   BIGINT              NULL,
    enrichment_data      NVARCHAR(MAX)       NULL,   -- solo datos de enriquecimiento externo (GeoIP, etc.)

    CONSTRAINT fk_events_original
        FOREIGN KEY (original_event_id) REFERENCES security_events(id),
    CONSTRAINT fk_events_user
        FOREIGN KEY (user_uuid) REFERENCES users(uuid)
);
GO

-- ----------------------------------------------------------------------------
-- alerts (CORE)
-- ----------------------------------------------------------------------------
CREATE TABLE alerts (
    id                  INT                 IDENTITY(1,1) PRIMARY KEY,
    event_id            BIGINT              NOT NULL,
    title               NVARCHAR(200)       NOT NULL,
    severity            TINYINT             NOT NULL
                            CONSTRAINT ck_alerts_severity
                            CHECK (severity BETWEEN 1 AND 5),
    status              NVARCHAR(20)        NOT NULL DEFAULT 'open'
                            CONSTRAINT ck_alerts_status
                            CHECK (status IN ('open','investigating','resolved','false_positive')),
    assigned_to_uuid    UNIQUEIDENTIFIER    NULL,
    notes               NVARCHAR(MAX)       NULL,
    resolved_at         DATETIMEOFFSET      NULL,
    created_at          DATETIMEOFFSET      NOT NULL DEFAULT SYSDATETIMEOFFSET(),

    CONSTRAINT fk_alerts_event
        FOREIGN KEY (event_id) REFERENCES security_events(id),
    CONSTRAINT fk_alerts_assigned
        FOREIGN KEY (assigned_to_uuid) REFERENCES users(uuid)
);
GO

-- ----------------------------------------------------------------------------
-- audit_logs (CORE — registro inmutable, alto volumen de INSERTs)
-- ----------------------------------------------------------------------------
CREATE TABLE audit_logs (
    id                  BIGINT              IDENTITY(1,1) PRIMARY KEY,
    user_uuid           UNIQUEIDENTIFIER    NOT NULL,
    action              NVARCHAR(80)        NOT NULL,
    target_table        NVARCHAR(60)        NULL,
    target_id           BIGINT              NULL,
    old_values          NVARCHAR(MAX)       NULL,   -- solo campos modificados, valor anterior
    new_values          NVARCHAR(MAX)       NULL,   -- solo campos modificados, valor nuevo
    ip_address          NVARCHAR(45)        NULL,
    occurred_at         DATETIMEOFFSET      NOT NULL DEFAULT SYSDATETIMEOFFSET(),

    CONSTRAINT fk_audit_user
        FOREIGN KEY (user_uuid) REFERENCES users(uuid)
);
GO

/* ============================================================================
   2. TABLAS EXCLUSIVAS DE SQL SERVER (features únicos del motor)
   ============================================================================ */

-- ----------------------------------------------------------------------------
-- network_logs — demuestra DATETIMEOFFSET y NVARCHAR
-- ----------------------------------------------------------------------------
CREATE TABLE network_logs (
    id              BIGINT              IDENTITY(1,1) PRIMARY KEY,
    src_ip          NVARCHAR(45)        NOT NULL,
    dst_ip          NVARCHAR(45)        NOT NULL,
    src_port        INT                 NULL,
    dst_port        INT                 NULL,
    protocol        NVARCHAR(10)        NULL,       -- TCP, UDP, ICMP, HTTP
    bytes_sent      BIGINT              NULL,
    action          NVARCHAR(20)        NULL,       -- allow, deny, drop
    logged_at       DATETIMEOFFSET      NOT NULL
);
GO

-- ----------------------------------------------------------------------------
-- alert_rules — demuestra JSON_VALUE() nativo (SQL Server 2016+) y BIT
-- ----------------------------------------------------------------------------
CREATE TABLE alert_rules (
    id                  INT                 IDENTITY(1,1) PRIMARY KEY,
    name                NVARCHAR(150)       NOT NULL UNIQUE,
    condition_json      NVARCHAR(MAX)       NOT NULL,   -- consultable con JSON_VALUE()
    severity            TINYINT             NOT NULL
                            CONSTRAINT ck_rules_severity
                            CHECK (severity BETWEEN 1 AND 5),
    is_active           BIT                 NOT NULL DEFAULT 1,
    created_at          DATETIME2           NOT NULL DEFAULT SYSDATETIME()
);
GO

-- ----------------------------------------------------------------------------
-- file_changes — demuestra UNIQUEIDENTIFIER para correlación cross-sistema
-- ----------------------------------------------------------------------------
CREATE TABLE file_changes (
    id                  BIGINT              IDENTITY(1,1) PRIMARY KEY,
    correlation_id      UNIQUEIDENTIFIER    NOT NULL DEFAULT NEWID(),
    file_path           NVARCHAR(500)       NOT NULL,
    change_type         NVARCHAR(20)        NOT NULL,  -- created, modified, deleted, permission_change
    hash_before         CHAR(64)            NULL,
    hash_after          CHAR(64)            NULL,
    detected_at         DATETIMEOFFSET      NOT NULL
);
GO

/* ============================================================================
   3. TABLAS OPERATIVAS DE INGESTA (capa de captura propia de este motor)
   ============================================================================ */

-- ----------------------------------------------------------------------------
-- event_sources — origen de los eventos (agentes, sensores, integraciones)
-- ----------------------------------------------------------------------------
CREATE TABLE event_sources (
    id              INT                 IDENTITY(1,1) PRIMARY KEY,
    source_name     NVARCHAR(100)       NOT NULL,
    source_type     NVARCHAR(50)        NULL,       -- network, application, identity...
    ip_address      NVARCHAR(45)        NULL,
    is_active       BIT                 NOT NULL DEFAULT 1
);
GO

-- ----------------------------------------------------------------------------
-- event_queue — cola de procesamiento (eventos pendientes de correlación)
-- ----------------------------------------------------------------------------
CREATE TABLE event_queue (
    id              BIGINT              IDENTITY(1,1) PRIMARY KEY,
    event_id        BIGINT              NOT NULL,
    processed       BIT                 NOT NULL DEFAULT 0,
    queued_at       DATETIME2           NOT NULL DEFAULT SYSDATETIME(),

    CONSTRAINT fk_queue_event
        FOREIGN KEY (event_id) REFERENCES security_events(id)
);
GO

/* ============================================================================
   FIN schema.sql
   Siguiente paso: indexes.sql (índices críticos sobre estas tablas)
   y luego seed.sql (datos de prueba: event_sources, users replicados, etc.)
   ============================================================================ */
