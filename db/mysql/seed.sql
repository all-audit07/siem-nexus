-- =============================================================================
-- SIEM MULTI-MOTOR — MySQL 8.4
-- seed.sql
-- Archivo: ./db/mysql/seed.sql
-- Propósito: Datos iniciales realistas para desarrollo y benchmark.
-- =============================================================================
-- CONTENIDO:
--   BLOQUE 1 — Catálogos: severity_levels + event_types
--   BLOQUE 2 — Organizations (tenants)
--   BLOQUE 3 — Users (analistas)
--   BLOQUE 4 — RBAC: roles → permissions → role_permissions → user_roles
--              ⚠️  Debe ejecutarse ANTES de user_devices y demás tablas
--                  que referencien roles, para que los subSELECTs encuentren
--                  los IDs correctos y no inserten NULL en las PKs.
--   BLOQUE 5 — User devices
--   BLOQUE 6 — Security events (volumen para benchmark)
--   BLOQUE 7 — Alerts (generadas desde eventos)
--   BLOQUE 8 — Audit logs (acciones de analistas)
--   BLOQUE 9 — User sessions
--   BLOQUE 10 — Verificación final (SELECT resumen)
-- =============================================================================

USE siem_benchmark;
SET foreign_key_checks = 0;

-- =============================================================================
-- BLOQUE 1 — CATÁLOGOS (tablas de referencia)
-- Fuente de verdad para severity y event_type en todo el sistema.
-- =============================================================================

-- Niveles de severidad 1-5
INSERT INTO severity_levels (id, code, label, color_hex, description) VALUES
(1, 'info',     'Información', '#6B7280', 'Evento informativo sin impacto en seguridad'),
(2, 'low',      'Bajo',        '#3B82F6', 'Actividad inusual de bajo riesgo'),
(3, 'medium',   'Medio',       '#F59E0B', 'Actividad sospechosa que requiere revisión'),
(4, 'high',     'Alto',        '#EF4444', 'Amenaza confirmada con impacto potencial alto'),
(5, 'critical', 'Crítico',     '#7C3AED', 'Incidente activo — respuesta inmediata requerida');

-- Tipos de evento (catálogo canónico)
INSERT INTO event_types (code, label, category, description) VALUES
('login_fail',        'Login fallido',              'authentication', 'Intento de autenticación fallido por credenciales incorrectas'),
('login_success',     'Login exitoso',              'authentication', 'Autenticación exitosa en el sistema'),
('logout',            'Cierre de sesión',           'authentication', 'El usuario cerró sesión correctamente'),
('brute_force',       'Fuerza bruta',               'authentication', 'Múltiples intentos de login fallidos desde la misma IP'),
('privilege_escalation', 'Escalada de privilegios', 'authentication', 'Intento de obtener permisos superiores a los asignados'),
('net_scan',          'Escaneo de red',             'network',        'Escaneo de puertos o descubrimiento de hosts en la red'),
('port_scan',         'Escaneo de puertos',         'network',        'Escaneo sistemático de puertos en un host objetivo'),
('ddos',              'Ataque DDoS',                'network',        'Tráfico masivo orientado a saturar un servicio'),
('lateral_movement',  'Movimiento lateral',         'network',        'Tráfico interno sospechoso entre hosts de la red'),
('dns_tunneling',     'Túnel DNS',                  'network',        'Uso del protocolo DNS para exfiltrar datos'),
('file_change',       'Cambio de archivo',          'filesystem',     'Modificación de un archivo en ruta sensible'),
('file_delete',       'Borrado de archivo',         'filesystem',     'Eliminación de archivo en directorio crítico'),
('ransomware',        'Ransomware detectado',       'filesystem',     'Patrón de cifrado masivo de archivos detectado'),
('data_exfiltration', 'Exfiltración de datos',      'filesystem',     'Transferencia de datos sensibles fuera del perímetro'),
('api_access',        'Acceso a API',               'api',            'Llamada a endpoint de la API del SIEM'),
('api_abuse',         'Abuso de API',               'api',            'Tasa de llamadas a API excede el límite permitido'),
('config_change',     'Cambio de configuración',    'api',            'Modificación de configuración del sistema'),
('malware_detected',  'Malware detectado',          'filesystem',     'Firma de malware conocido identificada en el host');


-- =============================================================================
-- BLOQUE 2 — ORGANIZATIONS (tenants del SIEM)
-- =============================================================================

INSERT INTO organizations (name, slug, contact_email, status) VALUES
('Acme Corporation',        'acme-corp',       'security@acme.com',       'active'),
('Banco Nacional',          'banco-nacional',  'soc@banconacional.com',   'active'),
('TechStartup SAS',         'techstartup',     'ops@techstartup.io',      'active'),
('Gobierno Digital',        'gov-digital',     'csirt@govdigital.gob',    'active'),
('Retail Plus',             'retail-plus',     'it@retailplus.com',       'suspended');


-- =============================================================================
-- BLOQUE 3 — USERS (analistas del SIEM)
-- password_hash = bcrypt de 'Password123!' (solo para desarrollo)
-- =============================================================================

INSERT INTO users (uuid, username, email, password_hash, full_name, status, last_login_at) VALUES
('a1b2c3d4-0001-0001-0001-000000000001', 'admin',       'admin@siem.local',       '$2b$12$REEMPLAZAR_CON_HASH_BCRYPT', 'Administrador SIEM',   'active',   NOW() - INTERVAL 1 HOUR),
('a1b2c3d4-0002-0002-0002-000000000002', 'ana.gomez',   'ana.gomez@siem.local',   '$2b$12$REEMPLAZAR_CON_HASH_BCRYPT', 'Ana Gómez',           'active',   NOW() - INTERVAL 3 HOUR),
('a1b2c3d4-0003-0003-0003-000000000003', 'carlos.ruiz', 'carlos.ruiz@siem.local', '$2b$12$REEMPLAZAR_CON_HASH_BCRYPT', 'Carlos Ruiz',         'active',   NOW() - INTERVAL 6 HOUR),
('a1b2c3d4-0004-0004-0004-000000000004', 'maria.lopez', 'maria.lopez@siem.local', '$2b$12$REEMPLAZAR_CON_HASH_BCRYPT', 'María López',         'active',   NOW() - INTERVAL 1 DAY),
('a1b2c3d4-0005-0005-0005-000000000005', 'pedro.silva', 'pedro.silva@siem.local', '$2b$12$REEMPLAZAR_CON_HASH_BCRYPT', 'Pedro Silva',         'inactive', NOW() - INTERVAL 7 DAY),
('a1b2c3d4-0006-0006-0006-000000000006', 'lucia.chen',  'lucia.chen@siem.local',  '$2b$12$REEMPLAZAR_CON_HASH_BCRYPT', 'Lucía Chen',          'active',   NOW() - INTERVAL 2 HOUR),
('a1b2c3d4-0007-0007-0007-000000000007', 'jorge.pena',  'jorge.pena@siem.local',  '$2b$12$REEMPLAZAR_CON_HASH_BCRYPT', 'Jorge Peña',          'locked',   NOW() - INTERVAL 14 DAY);


-- =============================================================================
-- BLOQUE 4 — RBAC (roles, permissions, role_permissions, user_roles)
-- ⚠️  DEBE ejecutarse ANTES de user_devices, security_events y cualquier tabla
--     que referencie roles o permisos. Los INSERT de user_roles usan subqueries
--     sobre roles — si roles está vacío los SELECTs devuelven NULL y la PK falla.
-- =============================================================================

-- ── Roles del sistema ────────────────────────────────────────────────────────
INSERT INTO roles (name, label, description, is_system, is_active) VALUES
('admin',     'Administrador',     'Acceso total al sistema. Gestión de usuarios, roles y configuración.',             1, 1),
('analyst',   'Analista SOC',      'Investigación y resolución de alertas. Consulta de eventos de seguridad.',         1, 1),
('viewer',    'Observador',        'Solo lectura. Puede ver eventos y alertas pero no modificar nada.',                 1, 1),
('auditor',   'Auditor',           'Acceso completo a audit logs y reportes. Sin capacidad de modificar alertas.',      1, 1),
('responder', 'Respondedor IR',    'Respuesta a incidentes. Puede resolver alertas y exportar eventos críticos.',       1, 1);


-- ── Permisos granulares por recurso ─────────────────────────────────────────
INSERT INTO permissions (code, label, resource, description) VALUES
-- Recurso: alert
('alert.view',          'Ver alertas',               'alert',  'Listar y ver detalle de alertas'),
('alert.create',        'Crear alerta manual',        'alert',  'Crear alertas manualmente sin evento origen'),
('alert.update',        'Editar alerta',              'alert',  'Modificar título, notas y severidad de alerta'),
('alert.resolve',       'Resolver alerta',            'alert',  'Marcar alerta como resuelta o falso positivo'),
('alert.assign',        'Asignar alerta',             'alert',  'Asignar alerta a un analista'),
('alert.delete',        'Eliminar alerta',            'alert',  'Borrar alertas — acción irreversible'),
-- Recurso: event
('event.view',          'Ver eventos',                'event',  'Consultar eventos de seguridad en el dashboard'),
('event.export',        'Exportar eventos',           'event',  'Descargar eventos en CSV/JSON'),
('event.enrich',        'Enriquecer evento',          'event',  'Marcar evento como enriquecido con threat intel'),
-- Recurso: user
('user.view',           'Ver usuarios',               'user',   'Listar analistas del sistema'),
('user.create',         'Crear usuario',              'user',   'Registrar nuevo analista en el SIEM'),
('user.update',         'Editar usuario',             'user',   'Modificar datos de un analista'),
('user.delete',         'Eliminar usuario',           'user',   'Dar de baja a un analista'),
('user.lock',           'Bloquear usuario',           'user',   'Bloquear cuenta de un analista'),
-- Recurso: audit
('audit.view',          'Ver audit logs',             'audit',  'Consultar el historial de acciones del sistema'),
('audit.export',        'Exportar audit logs',        'audit',  'Descargar audit logs completos'),
-- Recurso: config
('config.view',         'Ver configuración',          'config', 'Consultar configuración del sistema'),
('config.update',       'Editar configuración',       'config', 'Modificar parámetros del sistema SIEM'),
-- Recurso: report
('report.view',         'Ver reportes',               'report', 'Acceder a reportes y métricas del dashboard'),
('report.create',       'Generar reporte',            'report', 'Crear reportes ejecutivos y técnicos'),
-- Recurso: role
('role.view',           'Ver roles',                  'role',   'Consultar roles y permisos del sistema'),
('role.manage',         'Gestionar roles',            'role',   'Crear, editar y asignar roles a usuarios');


-- ── Asignación de permisos a roles ──────────────────────────────────────────
-- Admin: todos los permisos
INSERT INTO role_permissions (role_id, permission_id, granted_by_uuid)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    id,
    'a1b2c3d4-0001-0001-0001-000000000001'
FROM permissions;

-- Analyst: gestión de alertas + consulta de eventos + reportes básicos
INSERT INTO role_permissions (role_id, permission_id, granted_by_uuid)
SELECT
    (SELECT id FROM roles WHERE name = 'analyst'),
    id,
    'a1b2c3d4-0001-0001-0001-000000000001'
FROM permissions
WHERE code IN (
    'alert.view','alert.update','alert.resolve','alert.assign',
    'event.view','event.enrich',
    'report.view',
    'audit.view'
);

-- Viewer: solo lectura en todo
INSERT INTO role_permissions (role_id, permission_id, granted_by_uuid)
SELECT
    (SELECT id FROM roles WHERE name = 'viewer'),
    id,
    'a1b2c3d4-0001-0001-0001-000000000001'
FROM permissions
WHERE code IN (
    'alert.view',
    'event.view',
    'report.view'
);

-- Auditor: audit logs completos + reportes + solo lectura de alertas y eventos
INSERT INTO role_permissions (role_id, permission_id, granted_by_uuid)
SELECT
    (SELECT id FROM roles WHERE name = 'auditor'),
    id,
    'a1b2c3d4-0001-0001-0001-000000000001'
FROM permissions
WHERE code IN (
    'alert.view',
    'event.view','event.export',
    'audit.view','audit.export',
    'report.view','report.create',
    'user.view'
);

-- Responder: resolución de incidentes + exportación de eventos críticos
INSERT INTO role_permissions (role_id, permission_id, granted_by_uuid)
SELECT
    (SELECT id FROM roles WHERE name = 'responder'),
    id,
    'a1b2c3d4-0001-0001-0001-000000000001'
FROM permissions
WHERE code IN (
    'alert.view','alert.update','alert.resolve','alert.assign','alert.create',
    'event.view','event.export','event.enrich',
    'report.view'
);


-- ── Asignación de roles a usuarios ──────────────────────────────────────────
-- user_id 1 — admin       → rol admin (sistema)
-- user_id 2 — ana.gomez   → analyst + auditor (analista senior)
-- user_id 3 — carlos.ruiz → analyst
-- user_id 4 — maria.lopez → analyst
-- user_id 5 — pedro.silva → viewer (inactivo pero conserva rol)
-- user_id 6 — lucia.chen  → responder + analyst
-- user_id 7 — jorge.pena  → viewer (cuenta bloqueada)

INSERT INTO user_roles (user_id, role_id, granted_by_uuid, expires_at, is_active) VALUES
-- admin
(1, (SELECT id FROM roles WHERE name = 'admin'),     'a1b2c3d4-0001-0001-0001-000000000001', NULL, 1),
-- ana.gomez: analyst + auditor
(2, (SELECT id FROM roles WHERE name = 'analyst'),   'a1b2c3d4-0001-0001-0001-000000000001', NULL, 1),
(2, (SELECT id FROM roles WHERE name = 'auditor'),   'a1b2c3d4-0001-0001-0001-000000000001', NULL, 1),
-- carlos.ruiz: analyst
(3, (SELECT id FROM roles WHERE name = 'analyst'),   'a1b2c3d4-0001-0001-0001-000000000001', NULL, 1),
-- maria.lopez: analyst
(4, (SELECT id FROM roles WHERE name = 'analyst'),   'a1b2c3d4-0001-0001-0001-000000000001', NULL, 1),
-- pedro.silva: viewer
(5, (SELECT id FROM roles WHERE name = 'viewer'),    'a1b2c3d4-0001-0001-0001-000000000001', NULL, 1),
-- lucia.chen: responder + analyst (rol analyst temporal 90 días)
(6, (SELECT id FROM roles WHERE name = 'responder'), 'a1b2c3d4-0001-0001-0001-000000000001', NULL, 1),
(6, (SELECT id FROM roles WHERE name = 'analyst'),   'a1b2c3d4-0001-0001-0001-000000000001', NOW() + INTERVAL 90 DAY, 1),
-- jorge.pena: viewer (cuenta bloqueada, rol desactivado)
(7, (SELECT id FROM roles WHERE name = 'viewer'),    'a1b2c3d4-0001-0001-0001-000000000001', NULL, 0);


-- =============================================================================
-- BLOQUE 5 — USER DEVICES
-- =============================================================================

INSERT INTO user_devices (user_id, device_name, device_type, mac_address, ip_address, os, is_trusted) VALUES
(1, 'Admin Workstation',   'desktop', 'AA:BB:CC:DD:EE:01', '10.0.0.10', 'Ubuntu 22.04 LTS',    1),
(2, 'Ana Laptop',          'laptop',  'AA:BB:CC:DD:EE:02', '10.0.0.11', 'Windows 11 Pro',      1),
(2, 'Ana Mobile',          'mobile',  'AA:BB:CC:DD:EE:03', '10.0.0.12', 'iOS 17',              0),
(3, 'Carlos Desktop',      'desktop', 'AA:BB:CC:DD:EE:04', '10.0.0.13', 'Windows 11 Pro',      1),
(4, 'Maria Laptop',        'laptop',  'AA:BB:CC:DD:EE:05', '10.0.0.14', 'macOS Sonoma 14',     1),
(6, 'Lucia Workstation',   'desktop', 'AA:BB:CC:DD:EE:06', '10.0.0.15', 'Ubuntu 24.04 LTS',    1),
(6, 'Lucia Laptop',        'laptop',  'AA:BB:CC:DD:EE:07', '10.0.0.16', 'Ubuntu 24.04 LTS',    0),
(1, 'SIEM Server',         'server',  'AA:BB:CC:DD:EE:08', '10.0.0.2',  'Debian 12 Bookworm',  1);


-- =============================================================================
-- BLOQUE 5 — SECURITY EVENTS
-- Volumen suficiente para demostrar diferencias de rendimiento en el benchmark.
-- Incluye eventos de distintos tipos, severidades, IPs y usuarios.
-- =============================================================================

-- ── Eventos críticos y de alto impacto (severity 4-5) ──────────────────────
INSERT INTO security_events (event_type, severity, source_ip, dest_ip, user_uuid, description, raw_payload, is_enriched, occurred_at) VALUES

-- Ransomware detectado
('ransomware', 5, '10.0.0.55', '10.0.0.14', 'a1b2c3d4-0004-0004-0004-000000000004',
 'Patrón de cifrado masivo detectado en host de María López. 847 archivos afectados en 3 minutos.',
 '{"host":"WORKSTATION-ML","files_encrypted":847,"extension":".locked","process":"svchost.exe","pid":4821}',
 1, NOW() - INTERVAL 2 HOUR),

-- Escalada de privilegios
('privilege_escalation', 5, '10.0.0.13', '10.0.0.2', 'a1b2c3d4-0003-0003-0003-000000000003',
 'Carlos Ruiz intentó ejecutar comandos con sudo sin autorización en el servidor SIEM.',
 '{"host":"SIEM-SERVER","command":"sudo /bin/bash","user":"carlos.ruiz","exit_code":1}',
 1, NOW() - INTERVAL 4 HOUR),

-- Exfiltración de datos
('data_exfiltration', 5, '10.0.0.11', '203.0.113.99', 'a1b2c3d4-0002-0002-0002-000000000002',
 'Transferencia de 2.3GB hacia IP externa no autorizada detectada desde laptop de Ana Gómez.',
 '{"bytes_sent":2469606400,"dest_country":"RU","protocol":"HTTPS","port":443,"duration_sec":182}',
 1, NOW() - INTERVAL 6 HOUR),

-- DDoS entrante
('ddos', 5, '198.51.100.22', '10.0.0.1', NULL,
 'Ataque DDoS volumétrico detectado. 450,000 paquetes/segundo hacia el gateway.',
 '{"pps":450000,"mbps":3200,"attack_type":"UDP_FLOOD","duration_sec":300,"mitigated":false}',
 0, NOW() - INTERVAL 8 HOUR),

-- Brute force SSH
('brute_force', 4, '185.220.101.47', '10.0.0.2', NULL,
 'Fuerza bruta SSH detectada. 2,340 intentos en 5 minutos desde IP de red Tor.',
 '{"attempts":2340,"service":"SSH","port":22,"tor_exit_node":true,"blocked":false}',
 1, NOW() - INTERVAL 10 HOUR),

-- Movimiento lateral
('lateral_movement', 4, '10.0.0.13', '10.0.0.100', 'a1b2c3d4-0003-0003-0003-000000000003',
 'Tráfico SMB inusual entre workstations. Posible propagación de malware.',
 '{"protocol":"SMB","shares_accessed":["C$","ADMIN$"],"files_read":23,"source_host":"WORKSTATION-CR"}',
 1, NOW() - INTERVAL 12 HOUR),

-- Malware detectado
('malware_detected', 4, '10.0.0.12', NULL, 'a1b2c3d4-0004-0004-0004-000000000004',
 'Firma de Emotet trojan detectada en proceso en memoria.',
 '{"malware_family":"Emotet","hash_md5":"d41d8cd98f00b204e9800998ecf8427e","process":"winword.exe","memory_injected":true}',
 1, NOW() - INTERVAL 15 HOUR),

-- DNS Tunneling
('dns_tunneling', 4, '10.0.0.11', '8.8.8.8', 'a1b2c3d4-0002-0002-0002-000000000002',
 'Consultas DNS anómalas con payloads codificados en base64. Posible exfiltración via DNS.',
 '{"queries_per_min":340,"avg_subdomain_length":52,"entropy":4.8,"suspicious_domain":"evil-c2.example.com"}',
 1, NOW() - INTERVAL 18 HOUR),

-- ── Eventos de severidad media (severity 3) ─────────────────────────────────
('net_scan', 3, '10.0.0.55', '10.0.0.0/24', NULL,
 'Escaneo de red interno detectado. 254 hosts escaneados en 90 segundos.',
 '{"hosts_scanned":254,"ports_per_host":1000,"tool_fingerprint":"nmap","scan_type":"SYN"}',
 0, NOW() - INTERVAL 20 HOUR),

('port_scan', 3, '192.168.1.105', '10.0.0.2', NULL,
 'Escaneo de puertos en servidor SIEM. Puertos 22, 80, 443, 3306 sondeados.',
 '{"ports_scanned":[22,80,443,3306,8080,8443],"open_ports":[22,443],"os_detection":"Linux"}',
 0, NOW() - INTERVAL 22 HOUR),

('file_change', 3, '10.0.0.10', NULL, 'a1b2c3d4-0001-0001-0001-000000000001',
 'Modificación en archivo de configuración crítico /etc/passwd en servidor SIEM.',
 '{"file":"/etc/passwd","action":"modified","prev_hash":"abc123","new_hash":"def456","user":"root"}',
 1, NOW() - INTERVAL 1 DAY),

('api_abuse', 3, '10.0.0.15', '10.0.0.2', 'a1b2c3d4-0006-0006-0006-000000000006',
 'Lucía Chen excedió el límite de la API: 850 llamadas en 1 minuto (límite: 100/min).',
 '{"endpoint":"/api/v1/events","calls_per_min":850,"limit":100,"status":"rate_limited"}',
 0, NOW() - INTERVAL 25 HOUR),

-- ── Eventos de baja severidad (severity 1-2) ────────────────────────────────
('login_fail', 2, '10.0.0.11', '10.0.0.2', 'a1b2c3d4-0002-0002-0002-000000000002',
 'Ana Gómez falló 3 intentos de login consecutivos.',
 '{"attempts":3,"reason":"wrong_password","account_locked":false}',
 0, NOW() - INTERVAL 3 HOUR),

('login_fail', 2, '10.0.0.13', '10.0.0.2', 'a1b2c3d4-0003-0003-0003-000000000003',
 'Login fallido desde la cuenta de Carlos Ruiz.',
 '{"attempts":1,"reason":"wrong_password","account_locked":false}',
 0, NOW() - INTERVAL 5 HOUR),

('login_success', 1, '10.0.0.10', '10.0.0.2', 'a1b2c3d4-0001-0001-0001-000000000001',
 'Admin inició sesión correctamente.',
 '{"method":"password","mfa":true,"session_id":"sess_admin_001"}',
 0, NOW() - INTERVAL 1 HOUR),

('login_success', 1, '10.0.0.11', '10.0.0.2', 'a1b2c3d4-0002-0002-0002-000000000002',
 'Ana Gómez inició sesión correctamente.',
 '{"method":"password","mfa":true,"session_id":"sess_ana_001"}',
 0, NOW() - INTERVAL 3 HOUR),

('api_access', 1, '10.0.0.15', '10.0.0.2', 'a1b2c3d4-0006-0006-0006-000000000006',
 'Consulta al endpoint de eventos del dashboard.',
 '{"endpoint":"/api/v1/events","method":"GET","status":200,"response_ms":45}',
 0, NOW() - INTERVAL 30 MINUTE),

('config_change', 2, '10.0.0.10', '10.0.0.2', 'a1b2c3d4-0001-0001-0001-000000000001',
 'Admin modificó la configuración de retención de logs: 90 días → 180 días.',
 '{"setting":"log_retention_days","old_value":90,"new_value":180,"requires_restart":false}',
 0, NOW() - INTERVAL 2 DAY),

('logout', 1, '10.0.0.11', '10.0.0.2', 'a1b2c3d4-0002-0002-0002-000000000002',
 'Ana Gómez cerró sesión.',
 '{"session_duration_min":127,"session_id":"sess_ana_000"}',
 0, NOW() - INTERVAL 4 HOUR),

('file_delete', 2, '10.0.0.13', NULL, 'a1b2c3d4-0003-0003-0003-000000000003',
 'Archivo de log eliminado en directorio de auditoría.',
 '{"file":"/var/log/siem/audit_2024_01_10.log","size_bytes":4521890,"deleted_by":"carlos.ruiz"}',
 0, NOW() - INTERVAL 3 DAY);


-- ── Bloque de volumen: 50 login_fail para benchmark de lectura ───────────────
INSERT INTO security_events (event_type, severity, source_ip, dest_ip, user_uuid, description, raw_payload, is_enriched, occurred_at)
SELECT
    'login_fail',
    2,
    CONCAT('185.220.', FLOOR(RAND()*255), '.', FLOOR(RAND()*255)),
    '10.0.0.2',
    CASE FLOOR(RAND()*4)
        WHEN 0 THEN 'a1b2c3d4-0002-0002-0002-000000000002'
        WHEN 1 THEN 'a1b2c3d4-0003-0003-0003-000000000003'
        WHEN 2 THEN 'a1b2c3d4-0004-0004-0004-000000000004'
        ELSE NULL
    END,
    CONCAT('Intento de login fallido #', seq, ' desde IP externa.'),
    JSON_OBJECT('attempts', 1, 'reason', 'wrong_password', 'seq', seq),
    0,
    NOW() - INTERVAL FLOOR(RAND() * 72) HOUR
FROM (
    SELECT a.N + b.N * 10 + 1 AS seq
    FROM
        (SELECT 0 AS N UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4
         UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) a,
        (SELECT 0 AS N UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4) b
    ORDER BY seq
) AS nums;


-- =============================================================================
-- BLOQUE 6 — ALERTS
-- Generadas a partir de los eventos de mayor severidad.
-- =============================================================================

INSERT INTO alerts (event_id, title, severity, status, assigned_to_uuid, notes, resolved_at) VALUES

-- Alerta crítica: ransomware (event_id 1)
(1, 'CRÍTICO: Ransomware activo en WORKSTATION-ML', 5, 'investigating',
 'a1b2c3d4-0001-0001-0001-000000000001',
 'Equipo de María López aislado de la red a las 08:15. Se inició análisis forense. Pendiente: identificar vector de entrada.',
 NULL),

-- Alerta crítica: escalada de privilegios (event_id 2)
(2, 'CRÍTICO: Escalada de privilegios — carlos.ruiz en SIEM-SERVER', 5, 'investigating',
 'a1b2c3d4-0001-0001-0001-000000000001',
 'Se revisó el historial de comandos. No se encontró compromiso exitoso. Usuario notificado por RRHH.',
 NULL),

-- Alerta crítica: exfiltración (event_id 3)
(3, 'CRÍTICO: Exfiltración de datos 2.3GB hacia IP rusa', 5, 'open',
 'a1b2c3d4-0006-0006-0006-000000000006',
 NULL,
 NULL),

-- Alerta alta: DDoS (event_id 4)
(4, 'ALTO: Ataque DDoS activo — 450Kpps en gateway', 4, 'resolved',
 'a1b2c3d4-0002-0002-0002-000000000002',
 'Mitigado mediante ACL en firewall perimetral. Tráfico bloqueado a las 10:45. Proveedor upstream notificado.',
 NOW() - INTERVAL 6 HOUR),

-- Alerta alta: brute force (event_id 5)
(5, 'ALTO: Fuerza bruta SSH — 2340 intentos desde nodo Tor', 4, 'resolved',
 'a1b2c3d4-0003-0003-0003-000000000003',
 'IP bloqueada en firewall. Fail2ban activado. No hubo acceso exitoso confirmado.',
 NOW() - INTERVAL 8 HOUR),

-- Alerta alta: movimiento lateral (event_id 6)
(6, 'ALTO: Movimiento lateral SMB detectado en red interna', 4, 'investigating',
 'a1b2c3d4-0006-0006-0006-000000000006',
 'Tráfico SMB anómalo entre WORKSTATION-CR y servidor de archivos. Analizando con Wireshark.',
 NULL),

-- Alerta alta: malware (event_id 7)
(7, 'ALTO: Emotet detectado en proceso winword.exe', 4, 'resolved',
 'a1b2c3d4-0002-0002-0002-000000000002',
 'Proceso terminado. Archivo origen eliminado. Imagen del disco tomada para análisis forense. Sistema reinstalado.',
 NOW() - INTERVAL 12 HOUR),

-- Alerta media: net scan (event_id 9)
(9, 'MEDIO: Escaneo interno de red — 254 hosts', 3, 'false_positive',
 'a1b2c3d4-0003-0003-0003-000000000003',
 'Confirmado como escaneo de vulnerabilidades autorizado por el equipo de infraestructura. Ticket #INF-2847.',
 NOW() - INTERVAL 18 HOUR),

-- Alerta media: file change (event_id 11)
(11, 'MEDIO: Modificación en /etc/passwd en servidor SIEM', 3, 'resolved',
 'a1b2c3d4-0001-0001-0001-000000000001',
 'Cambio realizado por admin durante mantenimiento programado. Verificado contra change log #CHG-0091.',
 NOW() - INTERVAL 22 HOUR),

-- Alerta abierta sin evento asociado (alerta manual)
(NULL, 'REVISIÓN: Actividad inusual cuenta jorge.pena fuera de horario', 2, 'open',
 'a1b2c3d4-0002-0002-0002-000000000002',
 'Detectada actividad en cuenta bloqueada. Requiere revisión de acceso directo a BD.',
 NULL);


-- =============================================================================
-- BLOQUE 7 — AUDIT LOGS
-- Registro inmutable de acciones de analistas.
-- =============================================================================

INSERT INTO audit_logs (user_uuid, action, target_table, target_id, old_values, new_values, ip_address, occurred_at) VALUES

('a1b2c3d4-0001-0001-0001-000000000001', 'user.login',        NULL,             NULL, NULL,
 '{"session":"sess_admin_001","mfa":true}',                                                    '10.0.0.10', NOW() - INTERVAL 1 HOUR),

('a1b2c3d4-0002-0002-0002-000000000002', 'user.login',        NULL,             NULL, NULL,
 '{"session":"sess_ana_001","mfa":true}',                                                      '10.0.0.11', NOW() - INTERVAL 3 HOUR),

('a1b2c3d4-0002-0002-0002-000000000002', 'alert.view',        'alerts',         4,    NULL,    NULL,        '10.0.0.11', NOW() - INTERVAL 3 HOUR),

('a1b2c3d4-0002-0002-0002-000000000002', 'alert.resolve',     'alerts',         4,
 '{"status":"open"}',        '{"status":"resolved","notes":"Mitigado via ACL"}',               '10.0.0.11', NOW() - INTERVAL 6 HOUR),

('a1b2c3d4-0003-0003-0003-000000000003', 'user.login',        NULL,             NULL, NULL,
 '{"session":"sess_carlos_001"}',                                                              '10.0.0.13', NOW() - INTERVAL 5 HOUR),

('a1b2c3d4-0003-0003-0003-000000000003', 'alert.resolve',     'alerts',         5,
 '{"status":"open"}',        '{"status":"resolved","notes":"IP bloqueada en firewall"}',       '10.0.0.13', NOW() - INTERVAL 8 HOUR),

('a1b2c3d4-0003-0003-0003-000000000003', 'alert.update',      'alerts',         8,
 '{"status":"open"}',        '{"status":"false_positive","notes":"Escaneo autorizado #INF-2847"}', '10.0.0.13', NOW() - INTERVAL 18 HOUR),

('a1b2c3d4-0006-0006-0006-000000000006', 'user.login',        NULL,             NULL, NULL,
 '{"session":"sess_lucia_001"}',                                                               '10.0.0.15', NOW() - INTERVAL 2 HOUR),

('a1b2c3d4-0006-0006-0006-000000000006', 'alert.assign',      'alerts',         3,
 '{"assigned_to_uuid":null}','{"assigned_to_uuid":"a1b2c3d4-0006-0006-0006-000000000006"}',   '10.0.0.15', NOW() - INTERVAL 2 HOUR),

('a1b2c3d4-0001-0001-0001-000000000001', 'config.update',     'organizations',  1,
 '{"status":"active"}',      '{"log_retention_days":180}',                                    '10.0.0.10', NOW() - INTERVAL 2 DAY),

('a1b2c3d4-0001-0001-0001-000000000001', 'user.create',       'users',          7,    NULL,
 '{"username":"jorge.pena","status":"locked"}',                                                '10.0.0.10', NOW() - INTERVAL 14 DAY),

('a1b2c3d4-0002-0002-0002-000000000002', 'event.export',      'security_events', NULL, NULL,
 '{"format":"CSV","rows":1500,"filter":"severity>=4"}',                                        '10.0.0.11', NOW() - INTERVAL 1 DAY),

('a1b2c3d4-0001-0001-0001-000000000001', 'alert.resolve',     'alerts',         7,
 '{"status":"investigating"}','{"status":"resolved","notes":"Sistema reinstalado post-Emotet"}','10.0.0.10', NOW() - INTERVAL 12 HOUR),

('a1b2c3d4-0001-0001-0001-000000000001', 'alert.resolve',     'alerts',         9,
 '{"status":"investigating"}','{"status":"resolved","notes":"Verificado contra CHG-0091"}',    '10.0.0.10', NOW() - INTERVAL 22 HOUR);


-- =============================================================================
-- BLOQUE 8 — USER SESSIONS (tabla exclusiva MySQL)
-- =============================================================================

INSERT INTO user_sessions (user_id, token_hash, ip_address, user_agent, status, created_at, expires_at) VALUES
(1, SHA2('token_admin_session_001', 256),  '10.0.0.10', 'Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0 Safari/537.36',           'active',  NOW() - INTERVAL 1 HOUR,  NOW() + INTERVAL 7 HOUR),
(2, SHA2('token_ana_session_001',   256),  '10.0.0.11', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36', 'active',  NOW() - INTERVAL 3 HOUR,  NOW() + INTERVAL 5 HOUR),
(3, SHA2('token_carlos_session_001',256),  '10.0.0.13', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/125.0',              'expired', NOW() - INTERVAL 10 HOUR, NOW() - INTERVAL 2 HOUR),
(4, SHA2('token_maria_session_001', 256),  '10.0.0.14', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1.15',         'expired', NOW() - INTERVAL 25 HOUR, NOW() - INTERVAL 17 HOUR),
(6, SHA2('token_lucia_session_001', 256),  '10.0.0.15', 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/125.0',                'active',  NOW() - INTERVAL 2 HOUR,  NOW() + INTERVAL 6 HOUR),
(1, SHA2('token_admin_session_000', 256),  '10.0.0.10', 'Mozilla/5.0 (X11; Linux x86_64) Chrome/123.0 Safari/537.36',           'revoked', NOW() - INTERVAL 2 DAY,   NOW() - INTERVAL 1 DAY);



-- =============================================================================
-- BLOQUE 10 — VERIFICACIÓN FINAL
-- Resumen de filas insertadas por tabla.
-- Visible en: docker logs siem_mysql
-- =============================================================================

SELECT 'severity_levels'  AS tabla, COUNT(*) AS filas FROM severity_levels
UNION ALL
SELECT 'event_types',               COUNT(*) FROM event_types
UNION ALL
SELECT 'organizations',             COUNT(*) FROM organizations
UNION ALL
SELECT 'users',                     COUNT(*) FROM users
UNION ALL
SELECT 'user_devices',              COUNT(*) FROM user_devices
UNION ALL
SELECT 'security_events',           COUNT(*) FROM security_events
UNION ALL
SELECT 'alerts',                    COUNT(*) FROM alerts
UNION ALL
SELECT 'audit_logs',                COUNT(*) FROM audit_logs
UNION ALL
SELECT 'user_sessions',             COUNT(*) FROM user_sessions
UNION ALL
SELECT 'roles',                     COUNT(*) FROM roles
UNION ALL
SELECT 'permissions',               COUNT(*) FROM permissions
UNION ALL
SELECT 'role_permissions',          COUNT(*) FROM role_permissions
UNION ALL
SELECT 'user_roles',                COUNT(*) FROM user_roles;

SET foreign_key_checks = 1;

-- =============================================================================
-- FIN: seed.sql v3.2 — siem_benchmark · MySQL 8.4
-- Base de datos lista para desarrollo y benchmark.
-- =============================================================================
