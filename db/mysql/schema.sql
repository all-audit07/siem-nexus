-- =============================================================================
-- SIEM MULTI-MOTOR — MySQL 8
-- schema.sql
-- Archivo: ./db/mysql/schema.sql
-- Motor: MySQL 8 · Puerto 3306 · DB: siem_benchmark
-- Versión del esquema: v3.2 — Híbrido C + Gobernanza + RBAC + Security Hardening
-- =============================================================================
-- CONTENIDO:
--   BLOQUE 1 — Configuración del entorno
--   BLOQUE 2 — Tablas de referencia (catálogos)
--   BLOQUE 3 — Tablas CORE (compartidas con los 4 motores)
--              · users
--              · security_events
--              · alerts
--              · audit_logs
--   BLOQUE 4 — Tablas EXCLUSIVAS MySQL
--              · organizations
--              · user_sessions
--              · user_devices
--   BLOQUE 5 — Sistema RBAC (Role-Based Access Control)
--              · roles
--              · permissions
--              · role_permissions  (relación N:M roles ↔ permissions)
--              · user_roles        (relación N:M users ↔ roles)
--   BLOQUE 6 — Vistas dashboard (incluye v_user_permissions)
-- =============================================================================
-- CHANGELOG v3.2 — Security Hardening (límites de caracteres por campo)
-- -----------------------------------------------------------------------------
-- Campo                Tabla(s)            Antes   Después  Razón
-- ---------------------+-------------------+-------+---------+-----------------
-- username             users               60      20       Previene payloads
--                                                           XSS masivos
-- email                users               120     254      Estándar RFC 5321
-- full_name            users               120     60       Soporta nombres
--                                                           compuestos (2×30)
-- contact_email        organizations       120     254      Estándar RFC 5321
-- password_hash        users               255     255      Sin cambio — correcto
--                                                           para BCrypt/Argon2
-- =============================================================================

-- -----------------------------------------------------------------------------
-- BLOQUE 1 — Configuración del entorno
-- -----------------------------------------------------------------------------

SET NAMES utf8mb4;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;   -- Desactivamos FKs para poder crear tablas en cualquier orden
SET sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- Usamos la base de datos creada automáticamente por Docker
USE siem_benchmark;

-- -----------------------------------------------------------------------------
-- BLOQUE 2 — Tablas de referencia (catálogos inmutables)
-- Gobernanza v3: fuente de verdad para tipos de evento y niveles de severidad.
-- Estas tablas evitan strings "mágicos" dispersos en el código y en los datos.
-- -----------------------------------------------------------------------------

-- Tabla: event_types
-- Catálogo de todos los tipos de evento posibles en el SIEM.
-- Permite JOIN para obtener descripciones legibles en el dashboard.
CREATE TABLE IF NOT EXISTS event_types (
    id          TINYINT UNSIGNED    NOT NULL AUTO_INCREMENT,
    code        VARCHAR(60)         NOT NULL COMMENT 'Código canónico: login_fail, net_scan, file_change...',
    label       VARCHAR(100)        NOT NULL COMMENT 'Nombre legible para la UI',
    category    VARCHAR(60)         NOT NULL COMMENT 'Categoría: authentication, network, filesystem, api',
    description TEXT                    NULL COMMENT 'Descripción completa del tipo de evento',
    is_active   TINYINT(1)          NOT NULL DEFAULT 1 COMMENT 'Permite desactivar tipos sin borrarlos',
    created_at  DATETIME            NOT NULL DEFAULT (NOW()),

    PRIMARY KEY (id),
    UNIQUE KEY uq_event_types_code (code)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Catálogo de tipos de evento — fuente de verdad para event_type en security_events';


-- Tabla: severity_levels
-- Catálogo de niveles de severidad 1-5.
-- Permite JOIN para obtener label y color en el dashboard sin hardcodear en frontend.
CREATE TABLE IF NOT EXISTS severity_levels (
    id          TINYINT UNSIGNED    NOT NULL,   -- 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
    code        VARCHAR(20)         NOT NULL COMMENT 'info, low, medium, high, critical',
    label       VARCHAR(40)         NOT NULL COMMENT 'Información, Bajo, Medio, Alto, Crítico',
    color_hex   CHAR(7)             NOT NULL COMMENT 'Color para la UI, ej: #EF4444',
    description VARCHAR(200)            NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uq_severity_code (code)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Catálogo de severidades 1-5 — fuente de verdad para severity en security_events y alerts';


-- =============================================================================
-- BLOQUE 3 — Tablas CORE
-- Presentes en los 4 motores con estructura lógica idéntica.
-- La sintaxis es específica de MySQL 8 (tipos, ENUM, AUTO_INCREMENT, DATETIME).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Tabla CORE: users
-- Analistas del SIEM. La columna uuid actúa como llave de referencia cross-motor.
-- En MySQL, status se implementa como ENUM nativo (ventaja de storage vs CHECK).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INT UNSIGNED        NOT NULL AUTO_INCREMENT,
    uuid            VARCHAR(36)         NOT NULL COMMENT 'UUID v4 — referencia cross-motor, no exponer el id numérico',
    username        VARCHAR(20)         NOT NULL COMMENT 'Máx 20 chars — previene payloads XSS masivos',
    email           VARCHAR(254)        NOT NULL COMMENT 'Máx 254 chars — cumple estándar RFC 5321',
    password_hash   VARCHAR(255)        NOT NULL COMMENT 'Hash bcrypt/Argon2 — nunca almacenar texto plano',
    full_name       VARCHAR(60)         NOT NULL COMMENT 'Máx 60 chars — soporta nombres compuestos (2×30)',
    birth_date      DATE                    NULL COMMENT 'Fecha de nacimiento — validación edad mínima en registro',
    avatar_path     VARCHAR(255)            NULL COMMENT 'Ruta relativa del avatar en /app/uploads',
    -- FEATURE MYSQL: ENUM almacenado como 1-2 bytes internamente. SQL Server / Oracle usan CHECK CONSTRAINT.
    status          ENUM('active','inactive','locked') NOT NULL DEFAULT 'active',
    last_login_at   DATETIME                NULL COMMENT 'Actualizado por la app en cada login exitoso',
    created_at      DATETIME            NOT NULL DEFAULT (NOW()),

    PRIMARY KEY (id),
    UNIQUE KEY uq_users_uuid     (uuid),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email    (email)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='CORE — Analistas del SIEM. Presente en los 4 motores.';


-- -----------------------------------------------------------------------------
-- Tabla CORE: security_events
-- Eventos de seguridad capturados por los agentes del SIEM.
-- Es la tabla de mayor volumen del sistema — las decisiones de índice aquí
-- tienen el mayor impacto en el rendimiento general.
-- En MySQL, raw_payload se almacena como JSON (validado a nivel de motor desde MySQL 5.7.8).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    id              BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT  COMMENT 'BIGINT porque puede superar 2 billones de filas',
    -- event_type referencia a event_types.code (FK lógica — ver índice)
    event_type      VARCHAR(60)         NOT NULL COMMENT 'login_fail, net_scan, file_change, api_access...',
    severity        TINYINT UNSIGNED    NOT NULL COMMENT '1=Info 2=Low 3=Medium 4=High 5=Critical',
    source_ip       VARCHAR(45)             NULL COMMENT 'IPv4 o IPv6 (45 chars soporta IPv6 completo). PG usará INET.',
    dest_ip         VARCHAR(45)             NULL,
    -- user_uuid: referencia lógica cross-motor. No FK hard para no acoplar motores entre sí.
    user_uuid       VARCHAR(36)             NULL COMMENT 'Ref. lógica a users.uuid — sin FK hard (cross-motor)',
    description     TEXT                    NULL,
    -- FEATURE MYSQL 8: columna JSON con validación de estructura a nivel de motor
    raw_payload     JSON                    NULL COMMENT 'Payload original del agente. PG usa JSONB; Oracle usa CLOB.',
    -- is_enriched: gobernanza v3 — flag para saber si el event ya fue enriquecido con threat intel
    is_enriched     TINYINT(1)          NOT NULL DEFAULT 0,
    -- occurred_at: DATETIME en MySQL (sin timezone explícita — se gestiona vía app en UTC)
    -- SQL Server usará DATETIMEOFFSET; PG usará TIMESTAMPTZ; Oracle TIMESTAMP WITH TIME ZONE
    occurred_at     DATETIME            NOT NULL COMMENT 'Momento del evento — siempre en UTC',
    ingested_at     DATETIME            NOT NULL DEFAULT (NOW()) COMMENT 'Momento en que el SIEM recibió el evento',

    PRIMARY KEY (id),
    -- Índices críticos para queries del dashboard (definidos en indexes.sql también, aquí inline)
    KEY idx_security_events_occurred_at  (occurred_at DESC),
    KEY idx_security_events_type_sev     (event_type, severity),
    KEY idx_security_events_source_ip    (source_ip),
    KEY idx_security_events_user_uuid    (user_uuid),
    KEY idx_security_events_severity     (severity),

    -- CHECK nativo MySQL 8: severity debe estar entre 1 y 5
    CONSTRAINT chk_security_events_severity CHECK (severity BETWEEN 1 AND 5)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='CORE — Eventos de seguridad. Mayor volumen del sistema. Presente en los 4 motores.';


-- -----------------------------------------------------------------------------
-- Tabla CORE: alerts
-- Alertas generadas a partir de eventos de seguridad.
-- Un evento puede generar múltiples alertas. Relación 1:N con security_events.
-- status usa ENUM (feature MySQL) en lugar de CHECK CONSTRAINT.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id                  BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    event_id            BIGINT UNSIGNED         NULL COMMENT 'FK a security_events. NULL = alerta manual.',
    title               VARCHAR(200)        NOT NULL,
    severity            TINYINT UNSIGNED    NOT NULL COMMENT '1-5, puede diferir del evento origen',
    -- FEATURE MYSQL: ENUM para status. SQL Server y Oracle usan CHECK CONSTRAINT.
    status              ENUM('open','investigating','resolved','false_positive') NOT NULL DEFAULT 'open',
    -- assigned_to_uuid: ref. lógica a users.uuid (cross-motor, sin FK hard)
    assigned_to_uuid    VARCHAR(36)             NULL COMMENT 'Analista asignado — ref. lógica a users.uuid',
    notes               TEXT                    NULL COMMENT 'Notas del analista durante la investigación',
    resolved_at         DATETIME                NULL COMMENT 'NULL = no resuelta',
    created_at          DATETIME            NOT NULL DEFAULT (NOW()),

    PRIMARY KEY (id),
    KEY idx_alerts_status           (status),
    KEY idx_alerts_severity         (severity),
    KEY idx_alerts_event_id         (event_id),
    KEY idx_alerts_assigned_to_uuid (assigned_to_uuid),
    KEY idx_alerts_created_at       (created_at DESC),

    CONSTRAINT chk_alerts_severity CHECK (severity BETWEEN 1 AND 5),

    -- FK interna (dentro del mismo motor MySQL)
    CONSTRAINT fk_alerts_event_id
        FOREIGN KEY (event_id) REFERENCES security_events(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='CORE — Alertas del SIEM. Presente en los 4 motores.';


-- -----------------------------------------------------------------------------
-- Tabla CORE: audit_logs
-- Registro INMUTABLE de cada acción que realiza un analista.
-- Es la tabla estrella del benchmark de escritura (alta tasa de INSERTs).
-- No tiene FK hard a users para permitir audit logs de usuarios ya eliminados.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    user_uuid       VARCHAR(36)         NOT NULL COMMENT 'Analista — ref. lógica, sin FK para mantener inmutabilidad',
    action          VARCHAR(80)         NOT NULL COMMENT 'alert.resolve, rule.create, event.export, user.login...',
    target_table    VARCHAR(60)             NULL COMMENT 'Tabla afectada por la acción',
    target_id       BIGINT UNSIGNED         NULL COMMENT 'ID del registro afectado',
    -- old_values / new_values: gobernanza v3 — versionado de cambios para rollback / auditoría forense
    old_values      JSON                    NULL COMMENT 'Estado anterior del registro (para rollback)',
    new_values      JSON                    NULL COMMENT 'Estado nuevo del registro',
    ip_address      VARCHAR(45)             NULL COMMENT 'IP del analista en el momento de la acción',
    occurred_at     DATETIME            NOT NULL DEFAULT (NOW()) COMMENT 'Momento exacto de la acción — en UTC',

    PRIMARY KEY (id),
    KEY idx_audit_logs_user_uuid   (user_uuid),
    KEY idx_audit_logs_occurred_at (occurred_at DESC),
    KEY idx_audit_logs_action      (action),
    KEY idx_audit_logs_target      (target_table, target_id)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='CORE — Audit log inmutable. Tabla estrella del benchmark de escritura. Presente en los 4 motores.';


-- =============================================================================
-- BLOQUE 4 — Tablas EXCLUSIVAS de MySQL
-- Demuestran features únicos de MySQL que no existen igual en los otros motores:
--   · ENUM nativo (1-2 bytes de storage)
--   · ON UPDATE NOW() sin trigger
--   · Índices compuestos con ENUM
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Tabla EXCLUSIVA MySQL: organizations
-- Tenants del sistema SIEM (multi-tenant).
-- FEATURE EXCLUSIVO: ON UPDATE NOW() — MySQL actualiza updated_at automáticamente
-- sin necesidad de trigger. SQL Server / Oracle / PG requieren trigger o DEFAULT.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organizations (
    id              INT UNSIGNED        NOT NULL AUTO_INCREMENT,
    name            VARCHAR(120)        NOT NULL,
    slug            VARCHAR(80)         NOT NULL COMMENT 'Identificador URL-safe, ej: acme-corp',
    contact_email   VARCHAR(254)            NULL COMMENT 'Máx 254 chars — cumple estándar RFC 5321',
    -- FEATURE MYSQL: ENUM para status del tenant
    status          ENUM('active','suspended') NOT NULL DEFAULT 'active',
    created_at      DATETIME            NOT NULL DEFAULT (NOW()),
    -- FEATURE EXCLUSIVO MYSQL: ON UPDATE NOW() — actualización automática sin trigger
    -- SQL Server requiere trigger. Oracle requiere trigger. PG requiere trigger o extensión.
    updated_at      DATETIME            NOT NULL DEFAULT (NOW()) ON UPDATE NOW()
                                        COMMENT 'MySQL actualiza este campo automáticamente en cada UPDATE',

    PRIMARY KEY (id),
    UNIQUE KEY uq_organizations_slug (slug),
    KEY idx_organizations_status (status)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='EXCLUSIVA MySQL — Tenants del SIEM. Demuestra ON UPDATE NOW() sin trigger.';


-- -----------------------------------------------------------------------------
-- Tabla EXCLUSIVA MySQL: user_sessions
-- Sesiones activas de analistas.
-- FEATURES EXCLUSIVOS:
--   · ENUM nativo para status (active/expired/revoked)
--   · Índice compuesto (user_id, status) optimizado para "sesiones activas por usuario"
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_sessions (
    id          BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED        NOT NULL COMMENT 'FK a users.id',
    token_hash  VARCHAR(255)            NULL COMMENT 'Hash SHA-256 del JWT. NULL si sesión revocada.',
    ip_address  VARCHAR(45)         NOT NULL,
    user_agent  TEXT                    NULL COMMENT 'Navegador / cliente HTTP',
    -- FEATURE MYSQL: ENUM de 3 valores — almacenado como 1 byte internamente
    status      ENUM('active','expired','revoked') NOT NULL DEFAULT 'active',
    created_at  DATETIME            NOT NULL DEFAULT (NOW()),
    expires_at  DATETIME            NOT NULL COMMENT 'Expiración del JWT',

    PRIMARY KEY (id),
    UNIQUE KEY uq_user_sessions_token_hash (token_hash),
    -- Índice compuesto: consulta frecuente "sesiones activas de usuario X"
    KEY idx_user_sessions_user_status (user_id, status),
    KEY idx_user_sessions_expires_at  (expires_at),

    CONSTRAINT fk_user_sessions_user_id
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='EXCLUSIVA MySQL — Sesiones de analistas. Demuestra ENUM nativo e índice compuesto con ENUM.';


-- -----------------------------------------------------------------------------
-- Tabla EXCLUSIVA MySQL: user_devices
-- Dispositivos registrados por cada analista.
-- FEATURE EXCLUSIVO: TINYINT(1) como booleano (patrón clásico MySQL pre-8).
-- MySQL 8 tiene BIT(1) pero TINYINT(1) es el estándar de facto en el ecosistema.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_devices (
    id              INT UNSIGNED        NOT NULL AUTO_INCREMENT,
    user_id         INT UNSIGNED        NOT NULL COMMENT 'FK a users.id',
    device_name     VARCHAR(100)        NOT NULL,
    -- FEATURE MYSQL: ENUM para device_type
    device_type     ENUM('desktop','laptop','mobile','server') NOT NULL,
    mac_address     CHAR(17)                NULL COMMENT 'Formato: AA:BB:CC:DD:EE:FF',
    ip_address      VARCHAR(45)             NULL COMMENT 'Última IP conocida',
    os              VARCHAR(80)             NULL COMMENT 'Sistema operativo, ej: Windows 11 Pro',
    -- FEATURE MYSQL: TINYINT(1) como booleano — 0=false, 1=true
    -- En MySQL 8+ se puede usar BOOLEAN (alias de TINYINT(1))
    is_trusted      TINYINT(1)          NOT NULL DEFAULT 0 COMMENT '1 = dispositivo de confianza verificado',
    registered_at   DATETIME            NOT NULL DEFAULT (NOW()),

    PRIMARY KEY (id),
    -- Índice compuesto: "dispositivos confiables del usuario X"
    KEY idx_user_devices_user_trusted (user_id, is_trusted),
    KEY idx_user_devices_mac          (mac_address),

    CONSTRAINT fk_user_devices_user_id
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='EXCLUSIVA MySQL — Dispositivos de analistas. Demuestra TINYINT(1) booleano y ENUM de device_type.';



-- =============================================================================
-- BLOQUE 5 — Sistema RBAC (Role-Based Access Control)
-- =============================================================================
-- Arquitectura: 4 tablas con relaciones N:M
--
--   users ──< user_roles >── roles ──< role_permissions >── permissions
--
-- Un usuario puede tener MÚLTIPLES roles.
-- Un rol puede tener MÚLTIPLES permisos.
-- Un permiso puede pertenecer a MÚLTIPLES roles.
--
-- Ventaja vs columna role en users:
--   · Analista senior puede tener roles 'analyst' + 'auditor' simultáneamente
--   · Agregar un permiso nuevo solo requiere INSERT, no ALTER TABLE
--   · Historial de asignación (granted_at, granted_by_uuid, expires_at)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Tabla RBAC: roles
-- Catálogo de roles del sistema SIEM.
-- Roles base: admin, analyst, viewer, auditor, responder
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id          TINYINT UNSIGNED    NOT NULL AUTO_INCREMENT,
    name        VARCHAR(60)         NOT NULL COMMENT 'admin, analyst, viewer, auditor, responder',
    label       VARCHAR(100)        NOT NULL COMMENT 'Nombre legible: Administrador, Analista SOC...',
    description TEXT                    NULL COMMENT 'Descripción completa del rol y sus responsabilidades',
    is_system   TINYINT(1)          NOT NULL DEFAULT 0 COMMENT '1 = rol del sistema, no se puede eliminar',
    is_active   TINYINT(1)          NOT NULL DEFAULT 1,
    created_at  DATETIME            NOT NULL DEFAULT (NOW()),

    PRIMARY KEY (id),
    UNIQUE KEY uq_roles_name (name),
    KEY idx_roles_active (is_active)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='RBAC — Catálogo de roles del sistema SIEM';


-- -----------------------------------------------------------------------------
-- Tabla RBAC: permissions
-- Catálogo granular de permisos.
-- Formato del código: recurso.accion  (ej: alert.resolve, user.create)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permissions (
    id          SMALLINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    code        VARCHAR(80)         NOT NULL COMMENT 'Formato: recurso.accion — alert.resolve, event.export...',
    label       VARCHAR(120)        NOT NULL COMMENT 'Nombre legible para la UI de gestión',
    resource    VARCHAR(40)         NOT NULL COMMENT 'alert, event, user, audit, config, report',
    description VARCHAR(255)            NULL,
    is_active   TINYINT(1)          NOT NULL DEFAULT 1,
    created_at  DATETIME            NOT NULL DEFAULT (NOW()),

    PRIMARY KEY (id),
    UNIQUE KEY uq_permissions_code (code),
    KEY idx_permissions_resource (resource, is_active)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='RBAC — Catálogo granular de permisos. Formato: recurso.accion';


-- -----------------------------------------------------------------------------
-- Tabla RBAC: role_permissions  (relación N:M roles ↔ permissions)
-- Un rol tiene múltiples permisos. Un permiso puede estar en múltiples roles.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id         TINYINT UNSIGNED    NOT NULL COMMENT 'FK a roles.id',
    permission_id   SMALLINT UNSIGNED   NOT NULL COMMENT 'FK a permissions.id',
    granted_at      DATETIME            NOT NULL DEFAULT (NOW()),
    granted_by_uuid VARCHAR(36)             NULL COMMENT 'UUID del admin que asignó el permiso — ref. lógica',

    PRIMARY KEY (role_id, permission_id),
    KEY idx_rp_permission_id (permission_id),
    KEY idx_rp_granted_at    (granted_at),

    CONSTRAINT fk_rp_role_id
        FOREIGN KEY (role_id) REFERENCES roles(id)
        ON DELETE CASCADE ON UPDATE CASCADE,

    CONSTRAINT fk_rp_permission_id
        FOREIGN KEY (permission_id) REFERENCES permissions(id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='RBAC — Relación N:M roles ↔ permissions. PK compuesta (role_id, permission_id)';


-- -----------------------------------------------------------------------------
-- Tabla RBAC: user_roles  (relación N:M users ↔ roles)
-- Un usuario puede tener múltiples roles simultáneamente.
-- expires_at NULL = rol permanente. Con fecha = rol temporal (acceso de emergencia).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
    user_id         INT UNSIGNED        NOT NULL COMMENT 'FK a users.id',
    role_id         TINYINT UNSIGNED    NOT NULL COMMENT 'FK a roles.id',
    granted_at      DATETIME            NOT NULL DEFAULT (NOW()),
    granted_by_uuid VARCHAR(36)             NULL COMMENT 'UUID del admin que asignó el rol — ref. lógica',
    expires_at      DATETIME                NULL COMMENT 'NULL = permanente. Con fecha = rol temporal.',
    is_active       TINYINT(1)          NOT NULL DEFAULT 1 COMMENT 'Permite revocar sin borrar historial',

    PRIMARY KEY (user_id, role_id),
    KEY idx_ur_role_id    (role_id),
    KEY idx_ur_active     (user_id, is_active),
    KEY idx_ur_expires_at (expires_at),

    CONSTRAINT fk_ur_user_id
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE ON UPDATE CASCADE,

    CONSTRAINT fk_ur_role_id
        FOREIGN KEY (role_id) REFERENCES roles(id)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='RBAC — Relación N:M users ↔ roles. Soporta roles temporales con expires_at';

-- =============================================================================
-- BLOQUE 6 — Vistas dashboard
-- Gobernanza v3: el DB Adapter en Node.js y Grafana/Power BI consultan estas
-- vistas directamente. Sin JOINs ni agregaciones en código de aplicación.
-- =============================================================================

-- Vista 1: Resumen de seguridad — conteos por severidad en las últimas 24h
CREATE OR REPLACE VIEW v_security_overview AS
SELECT
    severity,
    COUNT(*)                            AS total_events,
    SUM(CASE WHEN ingested_at >= NOW() - INTERVAL 1 HOUR  THEN 1 ELSE 0 END) AS last_hour,
    SUM(CASE WHEN ingested_at >= NOW() - INTERVAL 24 HOUR THEN 1 ELSE 0 END) AS last_24h,
    MAX(occurred_at)                    AS last_seen
FROM security_events
GROUP BY severity
ORDER BY severity DESC;


-- Vista 2: Alertas abiertas con datos del evento origen
CREATE OR REPLACE VIEW v_open_alerts AS
SELECT
    a.id                AS alert_id,
    a.title,
    a.severity          AS alert_severity,
    a.status,
    a.assigned_to_uuid,
    a.created_at,
    se.event_type,
    se.source_ip,
    se.occurred_at      AS event_occurred_at
FROM alerts a
LEFT JOIN security_events se ON a.event_id = se.id
WHERE a.status IN ('open', 'investigating')
ORDER BY a.severity DESC, a.created_at DESC;


-- Vista 3: Tiempo promedio de resolución por severidad
CREATE OR REPLACE VIEW v_avg_resolution_time AS
SELECT
    severity,
    COUNT(*)                                                            AS total_resolved,
    AVG(TIMESTAMPDIFF(MINUTE, created_at, resolved_at))                AS avg_resolution_minutes,
    MIN(TIMESTAMPDIFF(MINUTE, created_at, resolved_at))                AS min_resolution_minutes,
    MAX(TIMESTAMPDIFF(MINUTE, created_at, resolved_at))                AS max_resolution_minutes
FROM alerts
WHERE status = 'resolved'
  AND resolved_at IS NOT NULL
GROUP BY severity
ORDER BY severity DESC;


-- Vista 4: Top 10 IPs por volumen de eventos (últimas 24h)
CREATE OR REPLACE VIEW v_top_source_ips AS
SELECT
    source_ip,
    COUNT(*)            AS event_count,
    MAX(severity)       AS max_severity,
    MIN(occurred_at)    AS first_seen,
    MAX(occurred_at)    AS last_seen
FROM security_events
WHERE source_ip IS NOT NULL
  AND occurred_at >= NOW() - INTERVAL 24 HOUR
GROUP BY source_ip
ORDER BY event_count DESC
LIMIT 10;


-- Vista 5: Actividad de analistas — últimos 7 días
CREATE OR REPLACE VIEW v_analyst_activity AS
SELECT
    user_uuid,
    COUNT(*)                    AS total_actions,
    COUNT(DISTINCT action)      AS distinct_action_types,
    MIN(occurred_at)            AS first_action,
    MAX(occurred_at)            AS last_action
FROM audit_logs
WHERE occurred_at >= NOW() - INTERVAL 7 DAY
GROUP BY user_uuid
ORDER BY total_actions DESC;


-- Vista 6: Sesiones activas con datos del usuario (JOIN exclusivo MySQL)
-- Esta vista solo existe en MySQL porque user_sessions es una tabla exclusiva MySQL.
CREATE OR REPLACE VIEW v_active_sessions AS
SELECT
    s.id                AS session_id,
    s.user_id,
    u.username,
    u.email,
    u.full_name,
    s.ip_address,
    s.user_agent,
    s.created_at        AS session_start,
    s.expires_at
FROM user_sessions s
INNER JOIN users u ON s.user_id = u.id
WHERE s.status = 'active'
  AND s.expires_at > NOW()
ORDER BY s.created_at DESC;



-- Vista 7: Permisos efectivos por usuario (RBAC — exclusiva MySQL)
-- Muestra todos los permisos que tiene un usuario a través de sus roles activos.
-- El backend consulta esta vista para autorizar cada acción del analista.
CREATE OR REPLACE VIEW v_user_permissions AS
SELECT
    u.id                AS user_id,
    u.uuid              AS user_uuid,
    u.username,
    r.name              AS role_name,
    r.label             AS role_label,
    p.code              AS permission_code,
    p.resource,
    p.label             AS permission_label,
    ur.expires_at       AS role_expires_at
FROM users u
INNER JOIN user_roles ur       ON u.id    = ur.user_id    AND ur.is_active = 1
INNER JOIN roles r             ON ur.role_id = r.id       AND r.is_active  = 1
INNER JOIN role_permissions rp ON r.id    = rp.role_id
INNER JOIN permissions p       ON rp.permission_id = p.id AND p.is_active  = 1
WHERE u.status = 'active'
  AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
ORDER BY u.username, r.name, p.resource, p.code;


-- =============================================================================
-- Reactivar foreign key checks
-- =============================================================================
SET foreign_key_checks = 1;

-- =============================================================================
-- FIN: schema.sql v3.2 — siem_benchmark · MySQL 8.4
-- Bloques: catálogos + CORE + exclusivas MySQL + RBAC + vistas
-- Siguiente archivo: indexes.sql
-- =============================================================================
