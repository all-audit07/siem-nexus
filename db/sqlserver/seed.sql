/* ============================================================================
   SIEM Multi-Motor — SQL Server (Motor 02)
   seed.sql — Datos de prueba
   ----------------------------------------------------------------------------
   Orden de ejecución: schema.sql -> triggers.sql -> indexes.sql -> seed.sql
   Usa variables para capturar IDs reales (IDENTITY) en vez de asumir 1,2,3...
   así el script es seguro de re-ejecutar contra una base recién creada.
   ============================================================================ */

USE siem_events;
GO

-- Requerido por SQL Server para insertar en tablas con índices filtrados
-- (security_events tiene idx_events_original como índice filtrado)
SET QUOTED_IDENTIFIER ON;
GO

/* ============================================================================
   1. event_sources — orígenes de eventos
   ============================================================================ */

INSERT INTO event_sources (source_name, source_type, ip_address, is_active)
VALUES
    ('Firewall',               'network',    '192.168.1.1',  1),
    ('Web Server',             'application','192.168.1.10', 1),
    ('Authentication Server',  'identity',   '192.168.1.20', 1);
GO

/* ============================================================================
   2. users — réplica de solo lectura (NUNCA password_hash)
   GUIDs fijos para poder referenciarlos de forma predecible en el resto
   del seed y en pruebas manuales.
   ============================================================================ */

INSERT INTO users (id, uuid, username, email, full_name, status, last_login_at, created_at)
VALUES
    (1, '11111111-1111-1111-1111-111111111111', 'analyst.garcia', 'garcia@siem.local',  'Marta García',   'active', SYSDATETIMEOFFSET(), DATEADD(DAY, -90, SYSDATETIMEOFFSET())),
    (2, '22222222-2222-2222-2222-222222222222', 'analyst.rivera', 'rivera@siem.local',  'Luis Rivera',    'active', DATEADD(HOUR, -6, SYSDATETIMEOFFSET()), DATEADD(DAY, -60, SYSDATETIMEOFFSET())),
    (3, '33333333-3333-3333-3333-333333333333', 'analyst.santos', 'santos@siem.local',  'Ana Santos',     'inactive', DATEADD(DAY, -20, SYSDATETIMEOFFSET()), DATEADD(DAY, -45, SYSDATETIMEOFFSET()));
GO

/* ============================================================================
   3. security_events — variedad de severidades, tipos e IPs
   ============================================================================ */

DECLARE @ev1 BIGINT, @ev2 BIGINT, @ev3 BIGINT, @ev4 BIGINT, @ev5 BIGINT,
        @ev6 BIGINT, @ev7 BIGINT, @ev_original BIGINT;

INSERT INTO security_events
    (event_type, severity, source_ip, dest_ip, user_uuid, description, raw_payload, occurred_at)
VALUES
    ('login_fail', 3, '203.0.113.45', '192.168.1.20',
     '11111111-1111-1111-1111-111111111111',
     'Intento de login fallido repetido',
     N'{"sensor_id":"agent-01","source":"syslog","raw_message":"auth failure user=mgarcia"}',
     DATEADD(MINUTE, -10, SYSDATETIMEOFFSET()));
SET @ev1 = SCOPE_IDENTITY();

INSERT INTO security_events
    (event_type, severity, source_ip, dest_ip, user_uuid, description, raw_payload, occurred_at)
VALUES
    ('net_scan', 4, '198.51.100.23', '192.168.1.1',
     NULL,
     'Escaneo de puertos detectado desde IP externa',
     N'{"sensor_id":"agent-fw","source":"waf","raw_message":"port scan 1-1024"}',
     DATEADD(HOUR, -1, SYSDATETIMEOFFSET()));
SET @ev2 = SCOPE_IDENTITY();

INSERT INTO security_events
    (event_type, severity, source_ip, dest_ip, user_uuid, description, raw_payload, occurred_at)
VALUES
    ('file_change', 2, '192.168.1.10', NULL,
     '22222222-2222-2222-2222-222222222222',
     'Modificación de archivo de configuración',
     N'{"sensor_id":"agent-edr","source":"edr","raw_message":"file modified /etc/app.conf"}',
     DATEADD(HOUR, -3, SYSDATETIMEOFFSET()));
SET @ev3 = SCOPE_IDENTITY();

INSERT INTO security_events
    (event_type, severity, source_ip, dest_ip, user_uuid, description, raw_payload, occurred_at)
VALUES
    ('api_access', 1, '192.168.1.10', '192.168.1.10',
     '22222222-2222-2222-2222-222222222222',
     'Acceso normal a API interna',
     N'{"sensor_id":"agent-01","source":"syslog","raw_message":"api call /v1/status"}',
     DATEADD(HOUR, -5, SYSDATETIMEOFFSET()));
SET @ev4 = SCOPE_IDENTITY();

INSERT INTO security_events
    (event_type, severity, source_ip, dest_ip, user_uuid, description, raw_payload, occurred_at)
VALUES
    ('login_fail', 5, '203.0.113.99', '192.168.1.20',
     NULL,
     'Posible ataque de fuerza bruta — múltiples IPs',
     N'{"sensor_id":"agent-01","source":"syslog","raw_message":"auth failure x12 user=admin"}',
     DATEADD(MINUTE, -2, SYSDATETIMEOFFSET()));
SET @ev5 = SCOPE_IDENTITY();

INSERT INTO security_events
    (event_type, severity, source_ip, dest_ip, user_uuid, description, raw_payload, occurred_at)
VALUES
    ('net_scan', 3, '198.51.100.77', '192.168.1.1',
     NULL,
     'Escaneo de red interno detectado',
     N'{"sensor_id":"agent-fw","source":"waf","raw_message":"internal scan subnet 192.168.1.0/24"}',
     DATEADD(DAY, -1, SYSDATETIMEOFFSET()));
SET @ev6 = SCOPE_IDENTITY();

INSERT INTO security_events
    (event_type, severity, source_ip, dest_ip, user_uuid, description, raw_payload, occurred_at)
VALUES
    ('file_change', 4, '192.168.1.10', NULL,
     '33333333-3333-3333-3333-333333333333',
     'Borrado de archivo sensible',
     N'{"sensor_id":"agent-edr","source":"edr","raw_message":"file deleted /var/secrets/key.pem"}',
     DATEADD(DAY, -2, SYSDATETIMEOFFSET()));
SET @ev7 = SCOPE_IDENTITY();

/* ----------------------------------------------------------------------------
   Ejemplo de versionado v2: re-procesamiento de un evento ya enriquecido.
   IMPORTANTE: esto NO es un UPDATE del evento original (el trigger lo
   impediría). Es un INSERT nuevo con version = 2 y original_event_id
   apuntando al evento base (@ev2).
   ---------------------------------------------------------------------------- */

INSERT INTO security_events
    (event_type, severity, source_ip, dest_ip, user_uuid, description, raw_payload,
     occurred_at, version, is_enriched, original_event_id, enrichment_data)
VALUES
    ('net_scan', 5, '198.51.100.23', '192.168.1.1',
     NULL,
     'Escaneo de puertos — reclasificado tras enriquecimiento GeoIP/threat intel',
     N'{"sensor_id":"agent-fw","source":"waf","raw_message":"port scan 1-1024"}',
     DATEADD(HOUR, -1, SYSDATETIMEOFFSET()),
     2, 1, @ev2,
     N'{"geo_country":"RU","asn":"AS12345","threat_score":91,"isp":"Unknown Hosting"}');
SET @ev_original = SCOPE_IDENTITY();

/* ============================================================================
   4. enriquecimiento legítimo vía UPDATE permitido por el trigger
   (solo is_enriched / enrichment_data — el trigger debe aceptar esto)
   ============================================================================ */

UPDATE security_events
SET is_enriched = 1,
    enrichment_data = N'{"geo_country":"US","asn":"AS64500","threat_score":12,"isp":"Cloud Provider Inc"}'
WHERE id = @ev4;

/* ============================================================================
   5. alerts — generadas a partir de algunos eventos
   ============================================================================ */

INSERT INTO alerts (event_id, title, severity, status, assigned_to_uuid, notes, created_at)
VALUES
    (@ev1, 'Login fallido repetido - posible credential stuffing', 3, 'investigating',
     '11111111-1111-1111-1111-111111111111', 'Revisando origen del intento', DATEADD(MINUTE, -8, SYSDATETIMEOFFSET())),

    (@ev5, 'Fuerza bruta detectada en cuenta admin', 5, 'open',
     NULL, NULL, DATEADD(MINUTE, -1, SYSDATETIMEOFFSET())),

    (@ev_original, 'Escaneo de puertos desde IP de alto riesgo (RU, threat_score 91)', 5, 'open',
     '22222222-2222-2222-2222-222222222222', 'Escalado tras enriquecimiento de threat intel', DATEADD(MINUTE, -50, SYSDATETIMEOFFSET())),

    (@ev7, 'Borrado de archivo sensible /var/secrets/key.pem', 4, 'resolved',
     '11111111-1111-1111-1111-111111111111', 'Confirmado: rotación de llaves programada', DATEADD(DAY, -2, SYSDATETIMEOFFSET()));

-- Marcar la alerta resuelta con su resolved_at
UPDATE alerts
SET resolved_at = DATEADD(DAY, -2, DATEADD(HOUR, 2, SYSDATETIMEOFFSET()))
WHERE event_id = @ev7;

/* ============================================================================
   6. audit_logs — acciones de analistas sobre las alertas
   ============================================================================ */

INSERT INTO audit_logs (user_uuid, action, target_table, target_id, old_values, new_values, ip_address, occurred_at)
VALUES
    ('11111111-1111-1111-1111-111111111111', 'alert.assign', 'alerts', 1,
     N'{"assigned_to_uuid":null}', N'{"assigned_to_uuid":"11111111-1111-1111-1111-111111111111"}',
     '10.0.0.5', DATEADD(MINUTE, -8, SYSDATETIMEOFFSET())),

    ('11111111-1111-1111-1111-111111111111', 'alert.resolve', 'alerts', 4,
     N'{"status":"investigating"}', N'{"status":"resolved"}',
     '10.0.0.5', DATEADD(DAY, -2, SYSDATETIMEOFFSET())),

    ('22222222-2222-2222-2222-222222222222', 'event.export', 'security_events', @ev_original,
     NULL, NULL, '10.0.0.8', DATEADD(MINUTE, -45, SYSDATETIMEOFFSET()));
GO

/* ============================================================================
   7. event_queue — cola de procesamiento
   ============================================================================ */

DECLARE @ev_queue_test BIGINT;
SELECT TOP 1 @ev_queue_test = id FROM security_events WHERE event_type = 'login_fail' ORDER BY id DESC;

INSERT INTO event_queue (event_id, processed, queued_at)
SELECT id, CASE WHEN severity >= 4 THEN 0 ELSE 1 END, DATEADD(MINUTE, -1, occurred_at)
FROM security_events;
GO

/* ============================================================================
   8. Tablas exclusivas de SQL Server — datos de ejemplo
   ============================================================================ */

INSERT INTO network_logs (src_ip, dst_ip, src_port, dst_port, protocol, bytes_sent, action, logged_at)
VALUES
    ('203.0.113.45', '192.168.1.20', 51422, 22,  'TCP',  4096,  'deny',  DATEADD(MINUTE, -10, SYSDATETIMEOFFSET())),
    ('198.51.100.23','192.168.1.1',  60010, 443, 'TCP',  12000, 'allow', DATEADD(HOUR, -1, SYSDATETIMEOFFSET())),
    ('192.168.1.10', '8.8.8.8',      53211, 53,  'UDP',  512,   'allow', DATEADD(HOUR, -5, SYSDATETIMEOFFSET()));
GO

INSERT INTO alert_rules (name, condition_json, severity, is_active, created_at)
VALUES
    ('Brute force login', N'{"event_type":"login_fail","count_gte":5,"window_minutes":10}', 5, 1, DATEADD(DAY, -30, SYSDATETIME())),
    ('Port scan inbound',  N'{"event_type":"net_scan","ports_gte":50,"window_minutes":5}',   4, 1, DATEADD(DAY, -30, SYSDATETIME())),
    ('Sensitive file delete', N'{"event_type":"file_change","change_type":"deleted","path_contains":"/var/secrets/"}', 4, 1, DATEADD(DAY, -15, SYSDATETIME()));
GO

INSERT INTO file_changes (correlation_id, file_path, change_type, hash_before, hash_after, detected_at)
VALUES
    (NEWID(), '/etc/app.conf', 'modified',
     'a3f1c9e2b8d4f6701234567890abcdef1234567890abcdef1234567890abcd',
     'b4e2d0f3c9e5a7812345678901bcdef21234567890abcdef1234567890abce',
     DATEADD(HOUR, -3, SYSDATETIMEOFFSET())),

    (NEWID(), '/var/secrets/key.pem', 'deleted',
     'c5f3e1a0d7b6987654321098765432109876543210987654321098765432aa',
     NULL,
     DATEADD(DAY, -2, SYSDATETIMEOFFSET()));
GO

/* ============================================================================
   FIN seed.sql
   Verificación rápida sugerida tras ejecutar:
     SELECT COUNT(*) FROM security_events;   -- debe dar 8 (7 + 1 versionado)
     SELECT COUNT(*) FROM alerts;            -- debe dar 4
     SELECT * FROM security_events WHERE original_event_id IS NOT NULL;
   ============================================================================ */
