-- =============================================================================
-- SIEM MULTI-MOTOR — MySQL 8.4
-- indexes.sql (v3 — compatible MySQL 8.4)
-- Archivo: ./db/mysql/indexes.sql
-- CORRECCIÓN v3: MySQL 8.4 NO soporta CREATE INDEX IF NOT EXISTS
--                ni DROP INDEX IF EXISTS.
--                Se usa un PROCEDURE con lógica condicional sobre
--                information_schema.STATISTICS para crear índices
--                solo si no existen. Patrón 100% compatible MySQL 8.4.
-- =============================================================================

USE siem_benchmark;

-- =============================================================================
-- HELPER: Procedimiento para crear un índice solo si no existe.
-- Consulta information_schema.STATISTICS antes de ejecutar el DDL.
-- Se llama con: CALL create_index_if_not_exists('tabla', 'indice', 'definicion');
-- Se elimina al final del script para no dejar objetos basura en la BD.
-- =============================================================================
DROP PROCEDURE IF EXISTS _create_index;

DELIMITER $$
CREATE PROCEDURE _create_index(
    IN p_table   VARCHAR(64),
    IN p_index   VARCHAR(64),
    IN p_ddl     TEXT
)
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME   = p_table
          AND INDEX_NAME   = p_index
        LIMIT 1
    ) THEN
        SET @sql = p_ddl;
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END$$
DELIMITER ;

-- =============================================================================
-- SECCIÓN 1 — ÍNDICES DOCUMENTADOS (ya existen desde schema.sql)
-- =============================================================================
-- No se re-crean aquí. Documentados como referencia completa.
--
-- TABLE: security_events
--   idx_security_events_occurred_at  (occurred_at DESC)
--   idx_security_events_type_sev     (event_type, severity)
--   idx_security_events_source_ip    (source_ip)
--   idx_security_events_user_uuid    (user_uuid)
--   idx_security_events_severity     (severity)
-- TABLE: alerts
--   idx_alerts_status / idx_alerts_severity / idx_alerts_event_id
--   idx_alerts_assigned_to_uuid / idx_alerts_created_at
-- TABLE: audit_logs
--   idx_audit_logs_user_uuid / idx_audit_logs_occurred_at
--   idx_audit_logs_action / idx_audit_logs_target
-- TABLE: user_sessions
--   idx_user_sessions_user_status / idx_user_sessions_expires_at
-- TABLE: user_devices
--   idx_user_devices_user_trusted / idx_user_devices_mac
-- =============================================================================


-- =============================================================================
-- SECCIÓN 2 — COVERING INDEXES
-- MySQL resuelve el query solo con el índice sin leer la tabla.
-- =============================================================================

CALL _create_index(
    'security_events',
    'idx_se_cover_dashboard',
    'CREATE INDEX idx_se_cover_dashboard
     ON security_events (severity, occurred_at, event_type, source_ip)
     COMMENT "Covering index — dashboard: severity+tiempo+tipo+IP sin hit a tabla"'
);

CALL _create_index(
    'security_events',
    'idx_se_cover_timerange',
    'CREATE INDEX idx_se_cover_timerange
     ON security_events (occurred_at, event_type, severity, source_ip)
     COMMENT "Covering index — range queries por ventana de tiempo + tipo"'
);

CALL _create_index(
    'alerts',
    'idx_alerts_cover_analyst',
    'CREATE INDEX idx_alerts_cover_analyst
     ON alerts (assigned_to_uuid, status, severity, created_at)
     COMMENT "Covering index — alertas abiertas por analista asignado"'
);

CALL _create_index(
    'audit_logs',
    'idx_al_cover_user_history',
    'CREATE INDEX idx_al_cover_user_history
     ON audit_logs (user_uuid, occurred_at, action, target_table)
     COMMENT "Covering index — historial cronológico de acciones por usuario"'
);


-- =============================================================================
-- SECCIÓN 3 — ÍNDICES FUNCIONALES (MySQL 8.0.13+ EXCLUSIVO)
-- Indexan el resultado de una expresión calculada.
-- Sin estos, MySQL evalúa la función en cada fila = full scan.
-- =============================================================================

CALL _create_index(
    'security_events',
    'idx_se_func_hour',
    'CREATE INDEX idx_se_func_hour
     ON security_events ((HOUR(occurred_at)))
     COMMENT "Índice funcional MySQL 8 — distribución de eventos por hora"'
);

CALL _create_index(
    'security_events',
    'idx_se_func_date',
    'CREATE INDEX idx_se_func_date
     ON security_events ((DATE(occurred_at)))
     COMMENT "Índice funcional MySQL 8 — agrupación de eventos por fecha"'
);

CALL _create_index(
    'security_events',
    'idx_se_func_type_lower',
    'CREATE INDEX idx_se_func_type_lower
     ON security_events ((LOWER(event_type)))
     COMMENT "Índice funcional MySQL 8 — búsqueda case-insensitive en event_type"'
);

CALL _create_index(
    'audit_logs',
    'idx_al_func_action_upper',
    'CREATE INDEX idx_al_func_action_upper
     ON audit_logs ((UPPER(action)))
     COMMENT "Índice funcional MySQL 8 — búsqueda normalizada en action"'
);

CALL _create_index(
    'users',
    'idx_users_func_email_lower',
    'CREATE INDEX idx_users_func_email_lower
     ON users ((LOWER(email)))
     COMMENT "Índice funcional MySQL 8 — login por email case-insensitive"'
);


-- =============================================================================
-- SECCIÓN 4 — ÍNDICES FULLTEXT
-- Reemplaza LIKE "%term%" que hace full scan siempre.
-- Uso: MATCH(col) AGAINST ("término" IN BOOLEAN MODE)
-- =============================================================================

CALL _create_index(
    'security_events',
    'idx_se_fulltext_desc',
    'CREATE FULLTEXT INDEX idx_se_fulltext_desc
     ON security_events (description)
     COMMENT "FULLTEXT — búsqueda libre en descripciones de eventos"'
);

CALL _create_index(
    'alerts',
    'idx_alerts_fulltext_content',
    'CREATE FULLTEXT INDEX idx_alerts_fulltext_content
     ON alerts (title, notes)
     COMMENT "FULLTEXT — búsqueda libre en título y notas de alertas"'
);


-- =============================================================================
-- SECCIÓN 5 — ÍNDICES DE PREFIJO (columnas TEXT)
-- =============================================================================

CALL _create_index(
    'user_sessions',
    'idx_us_user_agent_prefix',
    'CREATE INDEX idx_us_user_agent_prefix
     ON user_sessions (user_agent(100))
     COMMENT "Índice de prefijo 100 chars — fingerprinting de navegador"'
);


-- =============================================================================
-- SECCIÓN 6 — TABLAS DE REFERENCIA
-- =============================================================================

CALL _create_index(
    'event_types',
    'idx_event_types_category',
    'CREATE INDEX idx_event_types_category
     ON event_types (category, is_active)
     COMMENT "Filtrar tipos de evento activos por categoría"'
);


-- =============================================================================
-- SECCIÓN 7 — TABLAS EXCLUSIVAS MySQL
-- =============================================================================

CALL _create_index(
    'organizations',
    'idx_org_status_name',
    'CREATE INDEX idx_org_status_name
     ON organizations (status, name)
     COMMENT "Listado de organizaciones activas ordenadas por nombre"'
);

CALL _create_index(
    'user_sessions',
    'idx_us_cleanup',
    'CREATE INDEX idx_us_cleanup
     ON user_sessions (status, expires_at)
     COMMENT "Job de limpieza — sesiones expiradas pendientes de purga"'
);

CALL _create_index(
    'user_devices',
    'idx_ud_type_user',
    'CREATE INDEX idx_ud_type_user
     ON user_devices (device_type, user_id)
     COMMENT "Inventario de dispositivos por tipo"'
);


-- =============================================================================
-- Limpieza: eliminar el procedimiento helper (no debe quedar en producción)
-- =============================================================================
DROP PROCEDURE IF EXISTS _create_index;


-- =============================================================================
-- SECCIÓN 8 — VERIFICACIÓN FINAL
-- Lista todos los índices. Visible en: docker logs siem_mysql
-- =============================================================================
SELECT
    TABLE_NAME                                                          AS tabla,
    INDEX_NAME                                                          AS indice,
    INDEX_TYPE                                                          AS tipo,
    GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX SEPARATOR ', ')     AS columnas,
    IF(NON_UNIQUE = 0, 'UNIQUE', 'NO UNIQUE')                          AS unicidad,
    INDEX_COMMENT                                                       AS comentario
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = 'siem_benchmark'
GROUP BY TABLE_NAME, INDEX_NAME, INDEX_TYPE, NON_UNIQUE, INDEX_COMMENT
ORDER BY TABLE_NAME, INDEX_NAME;

-- =============================================================================
-- FIN: indexes.sql (v3) — siem_benchmark · MySQL 8.4
-- Siguiente archivo: seed.sql
-- =============================================================================
