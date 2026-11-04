-- ============================================================
--  SIEM MULTI-MOTOR — PostgreSQL Indexes
--  Motor: PostgreSQL 16 (Docker)
--  DB:    siem_correlation
--  v3.1 — Enfoque Híbrido C + Gobernanza
-- ============================================================
-- Ejecutar DESPUÉS de schema.sql:
--   docker exec -it siem_postgres psql -U postgres -d siem_correlation -f indexes.sql
--
-- Tipos de índice utilizados:
--   B-Tree  → columnas escalares: status, severity, timestamps, FKs
--   GIN     → JSONB y TEXT[]: permite @>, &&, ? y = ANY()
--   GiST    → INET y TSRANGE: operadores de red y de rango
-- ============================================================


-- ============================================================
-- 1. TABLAS CORE
--    Índices de acceso frecuente para las 4 tablas compartidas
--    con MySQL, SQL Server y Oracle en el benchmark.
-- ============================================================

-- ------------------------------------------------------------
-- 1.1 users
-- ------------------------------------------------------------

-- Búsqueda por UUID en joins cross-motor desde el Adapter
CREATE INDEX idx_users_uuid
    ON users(uuid);

-- Búsqueda por email en login / autenticación
CREATE UNIQUE INDEX idx_users_email_unique
    ON users(email);

-- Filtrado por usuarios activos / inactivos
CREATE INDEX idx_users_is_active
    ON users(is_active);

-- Índice compuesto: filtrar analistas activos por rol
-- Útil en queries: WHERE role = 'analyst' AND is_active = TRUE
CREATE INDEX idx_users_role_active
    ON users(role, is_active);


-- ------------------------------------------------------------
-- 1.2 security_events
--    Tabla de mayor volumen — benchmark de INSERT y SELECT masivo.
--    Requiere los índices más variados del esquema.
-- ------------------------------------------------------------

-- Filtrado por severidad — columna más consultada en el dashboard
CREATE INDEX idx_events_severity
    ON security_events(severity);

-- Ordenamiento y filtrado temporal descendente (paginación de eventos)
CREATE INDEX idx_events_occurred_at
    ON security_events(occurred_at DESC);

-- Búsqueda por tipo de evento (login_fail, net_scan, ransomware)
CREATE INDEX idx_events_event_type
    ON security_events(event_type);

-- GiST sobre INET: habilita operadores de red
--   source_ip << '192.168.0.0/16'  (está dentro de subnet)
--   source_ip >>= '10.0.0.1'       (supernet)
-- B-Tree no soporta el tipo INET con estos operadores
CREATE INDEX idx_events_source_ip
    ON security_events USING GIST(source_ip);

CREATE INDEX idx_events_dest_ip
    ON security_events USING GIST(dest_ip);

-- GIN sobre JSONB: permite búsquedas dentro del payload sin full scan
--   WHERE raw_payload @> '{"action": "deny"}'
--   WHERE raw_payload ? 'threat_level'
CREATE INDEX idx_events_raw_payload
    ON security_events USING GIN(raw_payload);

-- Índice compuesto: filtrado típico del dashboard en tiempo real
--   WHERE severity >= 4 AND occurred_at >= NOW() - INTERVAL '1 hour'
CREATE INDEX idx_events_severity_occurred
    ON security_events(severity, occurred_at DESC);

-- Cobertura de UUID para joins y correlación cross-motor
CREATE INDEX idx_events_uuid
    ON security_events(uuid);


-- ------------------------------------------------------------
-- 1.3 alerts
-- ------------------------------------------------------------

-- Filtrado por estado — columna más consultada en gestión de alertas
CREATE INDEX idx_alerts_status
    ON alerts(status);

-- Filtrado por severidad
CREATE INDEX idx_alerts_severity
    ON alerts(severity);

-- FK → security_events: acelera JOIN alerts-events
CREATE INDEX idx_alerts_event_id
    ON alerts(event_id);

-- Paginación temporal descendente
CREATE INDEX idx_alerts_created_at
    ON alerts(created_at DESC);

-- Índice compuesto: alertas abiertas de alta severidad
--   WHERE status = 'open' AND severity >= 4
CREATE INDEX idx_alerts_status_severity
    ON alerts(status, severity);

-- Búsqueda de alertas asignadas a un analista específico (cross-motor)
CREATE INDEX idx_alerts_assigned_to
    ON alerts(assigned_to_uuid)
    WHERE assigned_to_uuid IS NOT NULL;   -- índice parcial: omite NULLs


-- ------------------------------------------------------------
-- 1.4 audit_logs
--    Tabla de alta velocidad de INSERT — benchmark de escritura.
--    Los índices se mantienen mínimos para no penalizar los INSERTs.
-- ------------------------------------------------------------

-- Búsqueda de acciones por usuario (cross-motor via UUID)
CREATE INDEX idx_audit_user_uuid
    ON audit_logs(user_uuid);

-- Filtrado temporal — requerido por v_analyst_activity
CREATE INDEX idx_audit_occurred_at
    ON audit_logs(occurred_at DESC);

-- Filtrado por tipo de acción
CREATE INDEX idx_audit_action
    ON audit_logs(action);

-- GIN sobre new_values JSONB: permite buscar qué cambió en una acción
--   WHERE new_values @> '{"status": "resolved"}'
CREATE INDEX idx_audit_new_values
    ON audit_logs USING GIN(new_values);

-- Índice compuesto: auditoría de un usuario en un período
--   WHERE user_uuid = $1 AND occurred_at >= $2
CREATE INDEX idx_audit_user_time
    ON audit_logs(user_uuid, occurred_at DESC);


-- ============================================================
-- 2. TABLAS EXCLUSIVAS POSTGRESQL
--    Aquí PostgreSQL demuestra GIN sobre JSONB y TEXT[],
--    y GiST sobre INET y TSRANGE — features sin equivalente
--    directo en MySQL, SQL Server u Oracle.
-- ============================================================

-- ------------------------------------------------------------
-- 2.1 correlation_rules
-- ------------------------------------------------------------

-- GIN sobre pattern JSONB — el índice más importante de las reglas
-- Permite: WHERE pattern @> '{"event_type": "login_fail"}'
-- Sin este índice la query hace full scan sobre JSONB (muy lento)
CREATE INDEX idx_rules_pattern
    ON correlation_rules USING GIN(pattern);

-- GIN sobre event_types TEXT[]
-- Permite: WHERE 'login_fail' = ANY(event_types)
-- Y también: WHERE event_types @> ARRAY['login_fail','net_scan']
CREATE INDEX idx_rules_event_types
    ON correlation_rules USING GIN(event_types);

-- Filtrado rápido de reglas activas — usado en el motor de correlación
CREATE INDEX idx_rules_is_active
    ON correlation_rules(is_active);

-- Índice parcial: solo reglas activas (subset pequeño del total)
-- Más eficiente que idx_rules_is_active para WHERE is_active = TRUE
CREATE INDEX idx_rules_active_only
    ON correlation_rules(id, name, threshold, time_window_secs)
    WHERE is_active = TRUE;


-- ------------------------------------------------------------
-- 2.2 incidents
-- ------------------------------------------------------------

-- Filtrado por estado usando el tipo ENUM incident_status_t
CREATE INDEX idx_inc_status
    ON incidents(status);

-- Filtrado por severidad
CREATE INDEX idx_inc_severity
    ON incidents(severity);

-- FK → correlation_rules: acelera JOIN y v_incidents_summary
CREATE INDEX idx_inc_rule_id
    ON incidents(rule_id);

-- Paginación temporal descendente
CREATE INDEX idx_inc_created_at
    ON incidents(created_at DESC);

-- UUID para correlación cross-motor
CREATE INDEX idx_inc_uuid
    ON incidents(uuid);

-- GIN sobre affected_assets TEXT[]
-- Permite: WHERE affected_assets @> ARRAY['192.168.1.10']
-- Y también: WHERE '192.168.1.10' = ANY(affected_assets)
CREATE INDEX idx_inc_affected_assets
    ON incidents USING GIN(affected_assets);

-- GIN sobre mitre_tactics TEXT[]
-- Permite: WHERE mitre_tactics && ARRAY['Persistence','Lateral Movement']
CREATE INDEX idx_inc_mitre_tactics
    ON incidents USING GIN(mitre_tactics);

-- GIN sobre metadata JSONB
-- Permite: WHERE metadata @> '{"category": "brute_force"}'
CREATE INDEX idx_inc_metadata
    ON incidents USING GIN(metadata);

-- GiST sobre timeline TSRANGE — operadores de rango temporal
-- Permite: WHERE timeline @> NOW()::timestamp     (incidente activo ahora)
-- Permite: WHERE timeline && '[2025-01-01, 2025-02-01)'  (solapamiento)
-- B-Tree no soporta TSRANGE con estos operadores
CREATE INDEX idx_inc_timeline
    ON incidents USING GIST(timeline);

-- Índice parcial: incidentes abiertos o en investigación
-- Los incidentes resueltos/contenidos son históricos; este índice
-- cubre solo el subconjunto operativo que el dashboard consulta constantemente
CREATE INDEX idx_inc_open_active
    ON incidents(severity, created_at DESC)
    WHERE status IN ('open', 'investigating');


-- ------------------------------------------------------------
-- 2.3 vulnerabilities
-- ------------------------------------------------------------

-- Filtrado por estado usando el tipo ENUM vuln_status_t
CREATE INDEX idx_vuln_status
    ON vulnerabilities(status);

-- Ordenamiento por score CVSS descendente — v_open_vulnerabilities
CREATE INDEX idx_vuln_cvss
    ON vulnerabilities(cvss_score DESC);

-- Filtrado temporal
CREATE INDEX idx_vuln_detected_at
    ON vulnerabilities(detected_at DESC);

-- GiST sobre INET: operadores de red sobre asset_ip
-- Permite: WHERE asset_ip << '10.0.0.0/8'  (toda la red interna)
CREATE INDEX idx_vuln_asset_ip
    ON vulnerabilities USING GIST(asset_ip);

-- GIN sobre details JSONB
-- Permite: WHERE details @> '{"exploit_available": true}'
CREATE INDEX idx_vuln_details
    ON vulnerabilities USING GIN(details);

-- Índice parcial: solo vulnerabilidades abiertas de alta criticidad
-- CVSS >= 7.0 es considerado 'High' o 'Critical' por el estándar
CREATE INDEX idx_vuln_critical_open
    ON vulnerabilities(cvss_score DESC, detected_at DESC)
    WHERE status = 'open' AND cvss_score >= 7.0;


-- ============================================================
-- 3. TABLAS INTERMEDIAS N:M
-- ============================================================

-- ------------------------------------------------------------
-- 3.1 incident_vulns
--    La PK compuesta (incident_id, vulnerability_id) ya actúa
--    como índice implícito para búsquedas por incident_id.
--    Se agrega el índice inverso para búsquedas por vulnerability_id.
-- ------------------------------------------------------------

-- Permite: "¿en qué incidentes aparece esta vulnerabilidad?"
CREATE INDEX idx_iv_vulnerability_id
    ON incident_vulns(vulnerability_id);


-- ------------------------------------------------------------
-- 3.2 incident_events
-- ------------------------------------------------------------

-- FK → incidents: acelera JOIN y cascadas
CREATE INDEX idx_ie_incident_id
    ON incident_events(incident_id);

-- Búsqueda por UUID del evento en el motor de origen
CREATE INDEX idx_ie_event_uuid
    ON incident_events(event_uuid);

-- Índice compuesto: buscar todos los eventos de un motor específico
-- vinculados a un incidente
--   WHERE incident_id = $1 AND source_engine = 'mysql'
CREATE INDEX idx_ie_incident_engine
    ON incident_events(incident_id, source_engine);


-- ============================================================
-- FIN DE INDEXES
-- ============================================================
-- Resumen de índices creados:
--
--   Tabla               B-Tree   GIN   GiST   Parciales   Total
--   ─────────────────── ──────── ───── ────── ─────────── ─────
--   users                  4      0      0        0          4
--   security_events        5      1      2        0          8
--   alerts                 5      0      0        1          6
--   audit_logs             4      1      0        0          5
--   correlation_rules      2      2      0        1          5
--   incidents              5      3      1        1         10
--   vulnerabilities        3      1      1        1          6
--   incident_vulns         1      0      0        0          1
--   incident_events        3      0      0        0          3
--   ─────────────────── ──────── ───── ────── ─────────── ─────
--   TOTAL                 32      8      4        4         48
--
-- Tipos utilizados:
--   B-Tree   → columnas escalares (status, severity, uuid, timestamps, FKs)
--   GIN      → JSONB (pattern, raw_payload, metadata, details, new_values)
--              TEXT[] (event_types, affected_assets, mitre_tactics)
--   GiST     → INET (source_ip, dest_ip, asset_ip)
--              TSRANGE (timeline)
--   Parciales → subconjuntos operativos: registros activos, abiertos,
--               críticos — reducen tamaño del índice y aceleran
--               las queries más frecuentes del dashboard
-- ============================================================
