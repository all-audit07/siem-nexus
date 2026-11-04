-- ============================================================
--  SIEM MULTI-MOTOR — PostgreSQL Seed
--  Motor: PostgreSQL 16 (Docker)
--  DB:    siem_correlation
--  v3.2 — UUIDs sincronizados con MySQL + pgcrypto demos
-- ============================================================
-- Ejecutar DESPUÉS de schema.sql e indexes.sql:
--   docker cp seed.sql siem_postgres:/tmp/seed.sql
--   docker exec -it siem_postgres psql -U postgresql -d siem_correlation -f /tmp/seed.sql
--
-- UUIDs sincronizados con MySQL (fuente de verdad):
--   a1b2c3d4-0001-0001-0001-000000000001 → admin       (admin)
--   a1b2c3d4-0002-0002-0002-000000000002 → ana.gomez   (analyst)
--   a1b2c3d4-0003-0003-0003-000000000003 → carlos.ruiz (analyst)
--   a1b2c3d4-0004-0004-0004-000000000004 → maria.lopez (analyst)
--   a1b2c3d4-0005-0005-0005-000000000005 → pedro.silva (viewer)
--   a1b2c3d4-0006-0006-0006-000000000006 → lucia.chen  (auditor)
--   a1b2c3d4-0007-0007-0007-000000000007 → jorge.pena  (analyst - inactive)
-- ============================================================

BEGIN;

-- ============================================================
-- 1. USERS
--    Réplica exacta de MySQL. UUIDs idénticos para que el
--    DB Adapter resuelva referencias cross-motor correctamente.
--    PostgreSQL NO guarda contraseñas — esa es responsabilidad
--    de MySQL. Aquí solo se replica identidad y rol.
-- ============================================================

INSERT INTO users (uuid, username, email, role, is_active, created_at) VALUES
(
    'a1b2c3d4-0001-0001-0001-000000000001',
    'admin',
    'admin@siem.local',
    'admin',
    TRUE,
    NOW() - INTERVAL '90 days'
),
(
    'a1b2c3d4-0002-0002-0002-000000000002',
    'ana-gomez',
    'ana.gomez@siem.local',
    'analyst',
    TRUE,
    NOW() - INTERVAL '60 days'
),
(
    'a1b2c3d4-0003-0003-0003-000000000003',
    'carlos-ruiz',
    'carlos.ruiz@siem.local',
    'analyst',
    TRUE,
    NOW() - INTERVAL '45 days'
),
(
    'a1b2c3d4-0004-0004-0004-000000000004',
    'maria-lopez',
    'maria.lopez@siem.local',
    'analyst',
    TRUE,
    NOW() - INTERVAL '30 days'
),
(
    'a1b2c3d4-0005-0005-0005-000000000005',
    'pedro-silva',
    'pedro.silva@siem.local',
    'viewer',
    TRUE,
    NOW() - INTERVAL '20 days'
),
(
    'a1b2c3d4-0006-0006-0006-000000000006',
    'lucia-chen',
    'lucia.chen@siem.local',
    'auditor',
    TRUE,
    NOW() - INTERVAL '15 days'
),
(
    'a1b2c3d4-0007-0007-0007-000000000007',
    'jorge-pena',
    'jorge.pena@siem.local',
    'analyst',
    FALSE,
    NOW() - INTERVAL '120 days'
);


-- ============================================================
-- 2. CORRELATION_RULES
-- ============================================================

INSERT INTO correlation_rules
    (name, description, pattern, event_types, time_window_secs, threshold, is_active)
VALUES
(
    'Brute Force Detection',
    'Detecta múltiples intentos fallidos de login desde la misma IP en una ventana corta.',
    '{"event_type":"login_fail","category":"authentication","action":"block_source_ip","threshold":5,"window_secs":120}',
    ARRAY['login_fail'],
    120, 5, TRUE
),
(
    'Port Scan Detection',
    'Detecta barrido de puertos desde una misma IP en poco tiempo.',
    '{"event_type":"port_scan","category":"reconnaissance","action":"alert_and_log","threshold":20,"window_secs":60}',
    ARRAY['port_scan', 'net_scan'],
    60, 20, TRUE
),
(
    'Lateral Movement Alert',
    'Detecta conexiones sucesivas entre hosts internos en un período corto.',
    '{"event_type":"lateral_movement","category":"lateral_movement","network":"internal","action":"isolate_host","threshold":3,"window_secs":300}',
    ARRAY['lateral_movement', 'smb_access', 'rdp_login'],
    300, 3, TRUE
),
(
    'Ransomware Activity',
    'Detecta cifrado masivo de archivos, patrón típico de ransomware.',
    '{"event_type":"file_encrypt","category":"impact","action":"isolate_and_snapshot","threshold":50,"window_secs":60}',
    ARRAY['file_encrypt', 'ransomware'],
    60, 50, TRUE
),
(
    'Privilege Escalation',
    'Detecta escalación de privilegios: un usuario obtiene permisos no asignados.',
    '{"event_type":"privilege_escalation","category":"privilege_escalation","action":"suspend_account","threshold":1,"window_secs":3600}',
    ARRAY['privilege_escalation', 'sudo_abuse'],
    3600, 1, TRUE
),
(
    'Data Exfiltration Attempt',
    'Detecta transferencia de gran volumen de datos hacia IPs externas.',
    '{"event_type":"data_transfer","category":"exfiltration","direction":"outbound","bytes_min":104857600,"action":"block_and_alert","threshold":1,"window_secs":600}',
    ARRAY['data_transfer', 'ftp_upload', 'dns_tunnel'],
    600, 1, TRUE
),
(
    'Legacy SQL Injection',
    'Regla desactivada — reemplazada por WAF externo.',
    '{"event_type":"sql_injection","category":"web_attack","action":"block_request","threshold":3,"window_secs":60}',
    ARRAY['sql_injection', 'web_attack'],
    60, 3, FALSE
);


-- ============================================================
-- 3. SECURITY_EVENTS
--    20 eventos que forman 3 cadenas de ataque coherentes.
--    INET, JSONB y CHECKs de puertos quedan ejercitados.
-- ============================================================

INSERT INTO security_events
    (uuid, event_type, severity, source_ip, dest_ip, source_port, dest_port,
     protocol, hostname, description, raw_payload, is_enriched, occurred_at)
VALUES
-- ── CADENA 1: BRUTE FORCE SSH ────────────────────────────────
(
    'e0000001-0000-0000-0000-000000000001',
    'login_fail', 4,
    '185.220.101.45', '10.0.1.10',
    54321, 22, 'TCP', 'auth-server-01.internal',
    'Intento SSH fallido — usuario: root.',
    '{"user":"root","method":"password","attempt":1,"category":"authentication","attacker_ip":"185.220.101.45"}',
    TRUE, NOW() - INTERVAL '2 hours'
),
(
    'e0000001-0000-0000-0000-000000000002',
    'login_fail', 4,
    '185.220.101.45', '10.0.1.10',
    54322, 22, 'TCP', 'auth-server-01.internal',
    'Intento SSH fallido — usuario: admin.',
    '{"user":"admin","method":"password","attempt":2,"category":"authentication","attacker_ip":"185.220.101.45"}',
    TRUE, NOW() - INTERVAL '2 hours' + INTERVAL '20 seconds'
),
(
    'e0000001-0000-0000-0000-000000000003',
    'login_fail', 4,
    '185.220.101.45', '10.0.1.10',
    54323, 22, 'TCP', 'auth-server-01.internal',
    'Intento SSH fallido — usuario: ubuntu.',
    '{"user":"ubuntu","method":"password","attempt":3,"category":"authentication","attacker_ip":"185.220.101.45"}',
    TRUE, NOW() - INTERVAL '2 hours' + INTERVAL '40 seconds'
),
(
    'e0000001-0000-0000-0000-000000000004',
    'login_fail', 4,
    '185.220.101.45', '10.0.1.10',
    54324, 22, 'TCP', 'auth-server-01.internal',
    'Intento SSH fallido — usuario: deploy.',
    '{"user":"deploy","method":"password","attempt":4,"category":"authentication","attacker_ip":"185.220.101.45"}',
    TRUE, NOW() - INTERVAL '2 hours' + INTERVAL '60 seconds'
),
(
    'e0000001-0000-0000-0000-000000000005',
    'login_fail', 5,
    '185.220.101.45', '10.0.1.10',
    54325, 22, 'TCP', 'auth-server-01.internal',
    'UMBRAL ALCANZADO — 5 intentos SSH fallidos en 90 segundos.',
    '{"user":"git","method":"password","attempt":5,"category":"authentication","threshold_reached":true,"attacker_ip":"185.220.101.45"}',
    TRUE, NOW() - INTERVAL '2 hours' + INTERVAL '90 seconds'
),
-- ── CADENA 2: PORT SCAN + LATERAL MOVEMENT ───────────────────
(
    'e0000001-0000-0000-0000-000000000006',
    'port_scan', 3,
    '203.0.113.77', '10.0.0.1',
    45000, 80, 'TCP', NULL,
    'Barrido SYN hacia segmento 10.0.0.0/24.',
    '{"ports_scanned":[22,80,443,3306,5432,1433],"scan_type":"SYN","category":"reconnaissance","tool":"nmap"}',
    FALSE, NOW() - INTERVAL '3 hours'
),
(
    'e0000001-0000-0000-0000-000000000007',
    'net_scan', 3,
    '10.0.1.15', '10.0.2.1',
    44000, 80, 'TCP', 'workstation-15.internal',
    'Escaneo interno desde workstation hacia segmento de servidores.',
    '{"ports_scanned":[1433,3306,5432,8080],"scan_type":"TCP_CONNECT","category":"reconnaissance","src_host":"workstation-15"}',
    TRUE, NOW() - INTERVAL '1 hour' + INTERVAL '5 minutes'
),
(
    'e0000001-0000-0000-0000-000000000008',
    'lateral_movement', 5,
    '10.0.1.15', '10.0.2.20',
    49152, 1433, 'TCP', 'workstation-15.internal',
    'Conexión MSSQL desde workstation no autorizada hacia db-server-02.',
    '{"src_host":"workstation-15","dst_host":"db-server-02","dst_service":"mssql","category":"lateral_movement","authorized":false}',
    TRUE, NOW() - INTERVAL '1 hour' + INTERVAL '10 minutes'
),
(
    'e0000001-0000-0000-0000-000000000009',
    'smb_access', 4,
    '10.0.1.15', '10.0.2.25',
    49153, 445, 'TCP', 'workstation-15.internal',
    'Acceso SMB hacia fileserver desde workstation comprometida.',
    '{"src_host":"workstation-15","dst_host":"fileserver-01","share":"data","category":"lateral_movement"}',
    TRUE, NOW() - INTERVAL '1 hour' + INTERVAL '15 minutes'
),
(
    'e0000001-0000-0000-0000-000000000010',
    'privilege_escalation', 5,
    '10.0.1.22', '10.0.1.22',
    NULL, NULL, NULL, 'workstation-22.internal',
    'Usuario sin privilegios ejecutó sudo su - con éxito.',
    '{"user":"jsmith","command":"sudo su -","result":"success","category":"privilege_escalation","sudoers_entry":false}',
    TRUE, NOW() - INTERVAL '45 minutes'
),
-- ── CADENA 3: RANSOMWARE + EXFILTRACIÓN ──────────────────────
(
    'e0000001-0000-0000-0000-000000000011',
    'ransomware', 5,
    '10.0.3.50', '10.0.3.50',
    NULL, NULL, NULL, 'fileserver-03.internal',
    'Cifrado masivo detectado — extensión .locked — 312 archivos.',
    '{"files_encrypted":312,"extension":".locked","ransom_note":true,"category":"impact","vector":"EternalBlue"}',
    TRUE, NOW() - INTERVAL '30 minutes'
),
(
    'e0000001-0000-0000-0000-000000000012',
    'file_encrypt', 5,
    '10.0.3.50', '10.0.3.50',
    NULL, NULL, NULL, 'fileserver-03.internal',
    'Segundo lote de cifrado — 180 archivos adicionales.',
    '{"files_encrypted":180,"extension":".locked","total_encrypted":492,"category":"impact","progress":"continuing"}',
    TRUE, NOW() - INTERVAL '25 minutes'
),
(
    'e0000001-0000-0000-0000-000000000013',
    'data_transfer', 4,
    '10.0.2.30', '45.33.32.156',
    52000, 443, 'TCP', 'db-server-01.internal',
    'Transferencia saliente inusual — 250 MB hacia IP externa.',
    '{"bytes_sent":262144000,"dst_country":"RU","protocol":"HTTPS","category":"exfiltration","dst_asn":"AS63949"}',
    TRUE, NOW() - INTERVAL '20 minutes'
),
(
    'e0000001-0000-0000-0000-000000000014',
    'dns_tunnel', 4,
    '10.0.2.30', '8.8.8.8',
    53001, 53, 'UDP', 'db-server-01.internal',
    'Posible DNS tunneling — queries inusualmente largas.',
    '{"query_length_avg":180,"queries_per_min":45,"category":"exfiltration","technique":"dns_tunneling"}',
    TRUE, NOW() - INTERVAL '18 minutes'
),
(
    'e0000001-0000-0000-0000-000000000015',
    'rdp_login', 3,
    '10.0.1.15', '10.0.2.30',
    50000, 3389, 'TCP', 'workstation-15.internal',
    'Login RDP hacia db-server-01 desde workstation comprometida.',
    '{"src_host":"workstation-15","dst_host":"db-server-01","category":"lateral_movement","session_duration_min":12}',
    TRUE, NOW() - INTERVAL '35 minutes'
),
-- ── EVENTOS INFORMATIVOS ─────────────────────────────────────
(
    'e0000001-0000-0000-0000-000000000016',
    'login_success', 1,
    '192.168.1.100', '10.0.1.10',
    60000, 22, 'TCP', 'auth-server-01.internal',
    'Login SSH exitoso — usuario: carlos.ruiz.',
    '{"user":"carlos.ruiz","method":"pubkey","category":"authentication","mfa":true}',
    FALSE, NOW() - INTERVAL '4 hours'
),
(
    'e0000001-0000-0000-0000-000000000017',
    'login_success', 1,
    '192.168.1.101', '10.0.1.10',
    60001, 22, 'TCP', 'auth-server-01.internal',
    'Login SSH exitoso — usuario: ana.gomez.',
    '{"user":"ana.gomez","method":"pubkey","category":"authentication","mfa":true}',
    FALSE, NOW() - INTERVAL '5 hours'
),
(
    'e0000001-0000-0000-0000-000000000018',
    'config_change', 2,
    '192.168.1.1', '10.0.0.1',
    NULL, NULL, NULL, 'router-core-01.internal',
    'Regla de firewall añadida — bloqueo de 185.220.101.0/24.',
    '{"change_type":"firewall_rule","action":"add","rule":"block 185.220.101.0/24","category":"config_change","operator":"admin"}',
    FALSE, NOW() - INTERVAL '1 hour' + INTERVAL '30 minutes'
),
(
    'e0000001-0000-0000-0000-000000000019',
    'backup_complete', 1,
    '10.0.5.10', '10.0.5.20',
    NULL, NULL, NULL, 'backup-server-01.internal',
    'Backup nocturno completado correctamente.',
    '{"backup_type":"full","size_gb":142,"duration_min":87,"category":"system","status":"success"}',
    FALSE, NOW() - INTERVAL '8 hours'
),
(
    'e0000001-0000-0000-0000-000000000020',
    'vuln_scan', 2,
    '10.0.5.5', '10.0.0.1',
    NULL, NULL, NULL, 'scanner-01.internal',
    'Escaneo de vulnerabilidades programado completado.',
    '{"tool":"OpenVAS","hosts_scanned":48,"vulns_found":6,"category":"system","scheduled":true}',
    FALSE, NOW() - INTERVAL '6 hours'
);


-- ============================================================
-- 4. ALERTS
-- ============================================================

INSERT INTO alerts
    (uuid, event_id, title, description, severity, status,
     assigned_to_uuid, false_positive, resolved_at, created_at)
VALUES
(
    'b0000001-0000-0000-0000-000000000001',
    5,
    'Brute Force SSH detectado desde 185.220.101.45',
    '5 intentos fallidos de SSH en 90 segundos desde IP externa. IP pendiente de bloqueo.',
    5, 'open',
    'a1b2c3d4-0002-0002-0002-000000000002',
    FALSE, NULL, NOW() - INTERVAL '2 hours' + INTERVAL '2 minutes'
),
(
    'b0000001-0000-0000-0000-000000000002',
    6,
    'Port Scan TCP desde 203.0.113.77 hacia segmento interno',
    'Barrido SYN hacia 10.0.0.0/24. Incluye puertos de BD (3306, 5432, 1433).',
    3, 'acknowledged',
    'a1b2c3d4-0003-0003-0003-000000000003',
    FALSE, NULL, NOW() - INTERVAL '3 hours' + INTERVAL '5 minutes'
),
(
    'b0000001-0000-0000-0000-000000000003',
    8,
    'Movimiento lateral desde workstation-15 hacia db-server-02',
    'Workstation sin autorización realizó conexión MSSQL a servidor de BD de producción.',
    5, 'investigating',
    'a1b2c3d4-0002-0002-0002-000000000002',
    FALSE, NULL, NOW() - INTERVAL '1 hour' + INTERVAL '12 minutes'
),
(
    'b0000001-0000-0000-0000-000000000004',
    10,
    'Escalación de privilegios en workstation-22',
    'Usuario jsmith ejecutó sudo su - con éxito. No tiene permisos según política.',
    5, 'open',
    NULL,
    FALSE, NULL, NOW() - INTERVAL '45 minutes'
),
(
    'b0000001-0000-0000-0000-000000000005',
    11,
    'CRÍTICO: Ransomware activo en fileserver-03',
    '312 archivos cifrados con extensión .locked. Servidor en proceso de aislamiento.',
    5, 'investigating',
    'a1b2c3d4-0004-0004-0004-000000000004',
    FALSE, NULL, NOW() - INTERVAL '30 minutes'
),
(
    'b0000001-0000-0000-0000-000000000006',
    13,
    'Posible exfiltración de datos desde db-server-01',
    '250 MB transferidos hacia IP externa en Rusia en 5 minutos.',
    4, 'open',
    'a1b2c3d4-0003-0003-0003-000000000003',
    FALSE, NULL, NOW() - INTERVAL '20 minutes'
),
(
    'b0000001-0000-0000-0000-000000000007',
    7,
    'Escaneo interno desde workstation-15',
    'Actividad de reconocimiento previo al lateral movement confirmado.',
    3, 'investigating',
    'a1b2c3d4-0002-0002-0002-000000000002',
    FALSE, NULL, NOW() - INTERVAL '1 hour' + INTERVAL '8 minutes'
),
(
    'b0000001-0000-0000-0000-000000000008',
    20,
    'Escaneo de vulnerabilidades programado',
    'Actividad generada por OpenVAS. Confirmada como legítima.',
    2, 'false_positive',
    'a1b2c3d4-0006-0006-0006-000000000006',
    TRUE,
    NOW() - INTERVAL '5 hours' + INTERVAL '30 minutes',
    NOW() - INTERVAL '6 hours' + INTERVAL '5 minutes'
);


-- ============================================================
-- 5. AUDIT_LOGS
--    15 registros cubriendo todos los roles y acciones.
--    old_values/new_values en JSONB muestran cambios reales.
-- ============================================================

INSERT INTO audit_logs
    (user_uuid, action, target_type, target_id, old_values, new_values, ip_address, occurred_at)
VALUES
(
    'a1b2c3d4-0001-0001-0001-000000000001',
    'login', NULL, NULL, NULL,
    '{"session_started":true,"method":"password","mfa":true}',
    '192.168.1.1', NOW() - INTERVAL '6 hours'
),
(
    'a1b2c3d4-0001-0001-0001-000000000001',
    'rule_create', 'correlation_rules', 4, NULL,
    '{"name":"Ransomware Activity","is_active":true,"threshold":50,"window_secs":60}',
    '192.168.1.1', NOW() - INTERVAL '5 days'
),
(
    'a1b2c3d4-0001-0001-0001-000000000001',
    'rule_update', 'correlation_rules', 7,
    '{"is_active":true}',
    '{"is_active":false,"reason":"replaced_by_WAF"}',
    '192.168.1.1', NOW() - INTERVAL '3 days'
),
(
    'a1b2c3d4-0002-0002-0002-000000000002',
    'alert_acknowledge', 'alerts', 1,
    '{"status":"open","assigned_to_uuid":null}',
    '{"status":"open","assigned_to_uuid":"a1b2c3d4-0002-0002-0002-000000000002"}',
    '10.0.1.50', NOW() - INTERVAL '2 hours' + INTERVAL '5 minutes'
),
(
    'a1b2c3d4-0002-0002-0002-000000000002',
    'incident_create', 'incidents', 3, NULL,
    '{"title":"Brute Force SSH contenido","status":"open","severity":4,"rule_id":1}',
    '10.0.1.50', NOW() - INTERVAL '2 hours' + INTERVAL '10 minutes'
),
(
    'a1b2c3d4-0003-0003-0003-000000000003',
    'alert_status_change', 'alerts', 2,
    '{"status":"open"}',
    '{"status":"acknowledged"}',
    '10.0.1.51', NOW() - INTERVAL '2 hours' + INTERVAL '30 minutes'
),
(
    'a1b2c3d4-0002-0002-0002-000000000002',
    'incident_create', 'incidents', 1, NULL,
    '{"title":"Lateral Movement workstation-15","status":"open","severity":5,"rule_id":3}',
    '10.0.1.50', NOW() - INTERVAL '55 minutes'
),
(
    'a1b2c3d4-0004-0004-0004-000000000004',
    'alert_acknowledge', 'alerts', 5,
    '{"status":"open","assigned_to_uuid":null}',
    '{"status":"investigating","assigned_to_uuid":"a1b2c3d4-0004-0004-0004-000000000004"}',
    '10.0.1.52', NOW() - INTERVAL '29 minutes'
),
(
    'a1b2c3d4-0004-0004-0004-000000000004',
    'incident_create', 'incidents', 2, NULL,
    '{"title":"Ransomware en fileserver-03","status":"open","severity":5,"rule_id":4}',
    '10.0.1.52', NOW() - INTERVAL '28 minutes'
),
(
    'a1b2c3d4-0004-0004-0004-000000000004',
    'host_isolate', 'security_events', 11,
    '{"containment":"none","host":"fileserver-03.internal"}',
    '{"containment":"network_isolated","host":"fileserver-03.internal"}',
    '10.0.1.52', NOW() - INTERVAL '25 minutes'
),
(
    'a1b2c3d4-0003-0003-0003-000000000003',
    'alert_acknowledge', 'alerts', 6,
    '{"status":"open","assigned_to_uuid":null}',
    '{"status":"open","assigned_to_uuid":"a1b2c3d4-0003-0003-0003-000000000003"}',
    '10.0.1.51', NOW() - INTERVAL '19 minutes'
),
(
    'a1b2c3d4-0006-0006-0006-000000000006',
    'alert_view', 'alerts', NULL, NULL, NULL,
    '10.0.1.60', NOW() - INTERVAL '15 minutes'
),
(
    'a1b2c3d4-0006-0006-0006-000000000006',
    'alert_close', 'alerts', 8,
    '{"status":"open","false_positive":false}',
    '{"status":"false_positive","false_positive":true,"reason":"scheduled_scanner"}',
    '10.0.1.60', NOW() - INTERVAL '5 hours' + INTERVAL '30 minutes'
),
(
    'a1b2c3d4-0005-0005-0005-000000000005',
    'incident_view', 'incidents', NULL, NULL, NULL,
    '10.0.1.55', NOW() - INTERVAL '10 minutes'
),
(
    'a1b2c3d4-0002-0002-0002-000000000002',
    'incident_update', 'incidents', 1,
    '{"status":"open"}',
    '{"status":"investigating","notes":"Workstation-15 aislada de red interna"}',
    '10.0.1.50', NOW() - INTERVAL '40 minutes'
);


-- ============================================================
-- 6. VULNERABILITIES
-- ============================================================

INSERT INTO vulnerabilities
    (cve_id, title, cvss_score, affected_asset, asset_ip, status, details, detected_at)
VALUES
(
    'CVE-2023-38408',
    'OpenSSH Remote Code Execution via ssh-agent',
    9.8, 'auth-server-01.internal', '10.0.1.10', 'open',
    '{"vendor":"OpenSSH","version_affected":"< 9.3p2","exploit_available":true,"patch_available":true,"attack_vector":"Network","category":"RCE","priority":"critical"}',
    NOW() - INTERVAL '10 days'
),
(
    'CVE-2024-21351',
    'Microsoft SQL Server Elevation of Privilege',
    7.8, 'db-server-02.internal', '10.0.2.20', 'open',
    '{"vendor":"Microsoft","product":"SQL Server 2019","exploit_available":false,"patch_available":true,"attack_vector":"Local","category":"EoP","priority":"high"}',
    NOW() - INTERVAL '7 days'
),
(
    'CVE-2017-0144',
    'EternalBlue SMBv1 Remote Code Execution',
    9.8, 'fileserver-03.internal', '10.0.3.50', 'open',
    '{"vendor":"Microsoft","product":"Windows SMBv1","exploit_available":true,"known_malware":["WannaCry","NotPetya"],"patch_available":true,"attack_vector":"Network","category":"RCE","priority":"critical"}',
    NOW() - INTERVAL '5 days'
),
(
    'CVE-2023-44487',
    'HTTP/2 Rapid Reset DoS Attack',
    7.5, 'proxy-01.internal', '10.0.0.1', 'mitigated',
    '{"vendor":"Multiple","product":"HTTP/2 servers","exploit_available":true,"mitigation":"rate_limiting_applied","attack_vector":"Network","category":"DoS","priority":"high"}',
    NOW() - INTERVAL '20 days'
),
(
    'CVE-2023-29402',
    'Go cmd/go Directory Traversal',
    4.3, 'build-server-01.internal', '10.0.4.10', 'accepted',
    '{"vendor":"Google","product":"Go toolchain","exploit_available":false,"risk_accepted_by":"security_team","reason":"build_server_not_internet_facing","attack_vector":"Local","category":"path_traversal"}',
    NOW() - INTERVAL '30 days'
),
(
    'CVE-2021-34527',
    'PrintNightmare Windows Print Spooler RCE',
    8.8, 'workstation-15.internal', '10.0.1.15', 'open',
    '{"vendor":"Microsoft","product":"Windows Print Spooler","exploit_available":true,"patch_available":true,"attack_vector":"Network","category":"RCE","priority":"high","related_incident":1}',
    NOW() - INTERVAL '8 days'
);


-- ============================================================
-- 7. INCIDENTS
-- ============================================================

INSERT INTO incidents
    (uuid, rule_id, title, severity, status, affected_assets, mitre_tactics,
     timeline, metadata, assigned_to_uuid, correlation_score, created_at)
VALUES
(
    'c0000001-0000-0000-0000-000000000001',
    3,
    'Lateral Movement desde workstation-15 hacia infraestructura interna',
    5, 'investigating',
    ARRAY['10.0.1.15','10.0.2.20','10.0.2.25','workstation-15.internal','db-server-02.internal'],
    ARRAY['Lateral Movement','Credential Access','Discovery','Collection'],
    tsrange((NOW() - INTERVAL '1 hour')::timestamp, NULL, '[)'),
    '{"category":"lateral_movement","source_alert_id":3,"priority":"P1","containment":"partial","affected_services":["mssql","smb","rdp"],"analyst_notes":"Workstation-15 aislada."}',
    'a1b2c3d4-0002-0002-0002-000000000002',
    78.50, NOW() - INTERVAL '55 minutes'
),
(
    'c0000001-0000-0000-0000-000000000002',
    4,
    'Ransomware activo en fileserver-03 — cifrado masivo en curso',
    5, 'investigating',
    ARRAY['10.0.3.50','fileserver-03.internal'],
    ARRAY['Impact','Inhibit System Recovery','Data Encrypted for Impact'],
    tsrange((NOW() - INTERVAL '30 minutes')::timestamp, NULL, '[)'),
    '{"category":"ransomware","source_alert_id":5,"priority":"P1","files_encrypted":492,"extension":".locked","containment":"server_isolated","backup_status":"in_progress","vector":"EternalBlue CVE-2017-0144"}',
    'a1b2c3d4-0004-0004-0004-000000000004',
    95.00, NOW() - INTERVAL '28 minutes'
),
(
    'c0000001-0000-0000-0000-000000000003',
    1,
    'Brute Force SSH contenido — IP 185.220.101.45 bloqueada',
    4, 'contained',
    ARRAY['10.0.1.10','auth-server-01.internal'],
    ARRAY['Credential Access','Brute Force'],
    tsrange(
        (NOW() - INTERVAL '2 hours')::timestamp,
        (NOW() - INTERVAL '1 hour' - INTERVAL '30 minutes')::timestamp,
        '[)'
    ),
    '{"category":"brute_force","source_alert_id":1,"priority":"P2","attacker_ip":"185.220.101.45","containment":"ip_blocked_firewall","attempts":5,"resolution":"firewall_rule_added"}',
    'a1b2c3d4-0002-0002-0002-000000000002',
    62.00, NOW() - INTERVAL '2 hours' + INTERVAL '3 minutes'
),
(
    'c0000001-0000-0000-0000-000000000004',
    6,
    'Posible exfiltración de datos desde db-server-01 hacia IP externa',
    4, 'open',
    ARRAY['10.0.2.30','db-server-01.internal'],
    ARRAY['Exfiltration','Exfiltration Over C2 Channel','Exfiltration Over Alternative Protocol'],
    tsrange((NOW() - INTERVAL '20 minutes')::timestamp, NULL, '[)'),
    '{"category":"exfiltration","source_alert_id":6,"priority":"P2","dst_ip":"45.33.32.156","dst_country":"RU","bytes_sent":262144000,"techniques":["https_exfil","dns_tunneling"],"containment":"none"}',
    'a1b2c3d4-0003-0003-0003-000000000003',
    55.75, NOW() - INTERVAL '18 minutes'
),
(
    'c0000001-0000-0000-0000-000000000005',
    5,
    'Escalación de privilegios resuelta en workstation-22',
    3, 'resolved',
    ARRAY['10.0.1.22','workstation-22.internal'],
    ARRAY['Privilege Escalation','Valid Accounts'],
    tsrange(
        (NOW() - INTERVAL '45 minutes')::timestamp,
        (NOW() - INTERVAL '15 minutes')::timestamp,
        '[)'
    ),
    '{"category":"privilege_escalation","source_alert_id":4,"priority":"P3","user":"jsmith","resolution":"sudo_access_revoked","containment":"full","root_cause":"misconfigured_sudoers"}',
    'a1b2c3d4-0002-0002-0002-000000000002',
    40.00, NOW() - INTERVAL '43 minutes'
);


-- ============================================================
-- 8. INCIDENT_VULNS
-- ============================================================

INSERT INTO incident_vulns (incident_id, vulnerability_id, linked_at) VALUES
(1, 6, NOW() - INTERVAL '50 minutes'),
(1, 2, NOW() - INTERVAL '50 minutes'),
(2, 3, NOW() - INTERVAL '25 minutes'),
(2, 1, NOW() - INTERVAL '25 minutes'),
(3, 1, NOW() - INTERVAL '115 minutes'),
(4, 2, NOW() - INTERVAL '15 minutes');


-- ============================================================
-- 9. INCIDENT_EVENTS
-- ============================================================

INSERT INTO incident_events
    (incident_id, event_uuid, source_engine, linked_at)
VALUES
(1, 'e0000001-0000-0000-0000-000000000007', 'postgresql', NOW() - INTERVAL '57 minutes'),
(1, 'e0000001-0000-0000-0000-000000000008', 'postgresql', NOW() - INTERVAL '54 minutes'),
(1, 'e0000001-0000-0000-0000-000000000009', 'postgresql', NOW() - INTERVAL '49 minutes'),
(1, 'e0000001-0000-0000-0000-000000000015', 'postgresql', NOW() - INTERVAL '39 minutes'),
(1, 'f1000001-cafe-babe-dead-000000000001', 'mysql',      NOW() - INTERVAL '58 minutes'),
(2, 'e0000001-0000-0000-0000-000000000011', 'postgresql', NOW() - INTERVAL '29 minutes'),
(2, 'e0000001-0000-0000-0000-000000000012', 'postgresql', NOW() - INTERVAL '24 minutes'),
(2, 'f1000001-cafe-babe-dead-000000000002', 'sqlserver',  NOW() - INTERVAL '27 minutes'),
(3, 'e0000001-0000-0000-0000-000000000001', 'postgresql', NOW() - INTERVAL '118 minutes'),
(3, 'e0000001-0000-0000-0000-000000000002', 'postgresql', NOW() - INTERVAL '117 minutes'),
(3, 'e0000001-0000-0000-0000-000000000003', 'postgresql', NOW() - INTERVAL '116 minutes'),
(3, 'e0000001-0000-0000-0000-000000000004', 'postgresql', NOW() - INTERVAL '115 minutes'),
(3, 'e0000001-0000-0000-0000-000000000005', 'postgresql', NOW() - INTERVAL '114 minutes'),
(4, 'e0000001-0000-0000-0000-000000000013', 'postgresql', NOW() - INTERVAL '19 minutes'),
(4, 'e0000001-0000-0000-0000-000000000014', 'postgresql', NOW() - INTERVAL '17 minutes'),
(4, 'f1000001-cafe-babe-dead-000000000003', 'mysql',      NOW() - INTERVAL '19 minutes'),
(5, 'e0000001-0000-0000-0000-000000000010', 'postgresql', NOW() - INTERVAL '44 minutes');

COMMIT;


-- ============================================================
-- DEMOSTRACIÓN 1: pgcrypto — INTEGRIDAD FORENSE
--    SHA-256 de cada audit_log como firma inmutable.
--    Demuestra que pgcrypto sirve para algo más que passwords.
--    MySQL haría SHA2() pero sin bcrypt nativo ni digest().
-- ============================================================

SELECT
    al.id,
    u.username                                      AS analista,
    al.action,
    al.target_type,
    al.ip_address::TEXT,
    al.occurred_at,
    encode(
        digest(
            al.action
            || '|' || COALESCE(al.target_type, 'null')
            || '|' || COALESCE(al.target_id::TEXT, 'null')
            || '|' || al.occurred_at::TEXT
            || '|' || COALESCE(al.user_uuid::TEXT, 'null'),
            'sha256'
        ),
        'hex'
    )                                               AS integrity_hash
FROM audit_logs al
LEFT JOIN users u ON u.uuid = al.user_uuid
ORDER BY al.occurred_at DESC;


-- ============================================================
-- DEMOSTRACIÓN 2: pgcrypto — ANONIMIZACIÓN DE IPs
--    IP real vs hash SHA-256.
--    Mismo hash = misma IP (correlación sin exponer el dato).
-- ============================================================

SELECT
    event_type,
    severity,
    source_ip::TEXT                                     AS ip_real,
    encode(digest(source_ip::TEXT, 'sha256'), 'hex')    AS ip_anonimizada,
    occurred_at
FROM security_events
WHERE source_ip IS NOT NULL
ORDER BY occurred_at DESC;


-- ============================================================
-- DEMOSTRACIÓN 3: CORRELACIÓN CROSS-MOTOR
--    Todo lo que hizo ana.gomez en PostgreSQL usando el UUID
--    que MySQL tiene como fuente de verdad.
--    Mostrar esta query con MySQL abierto al lado — ese es
--    el momento de demostración ante el profesor.
-- ============================================================

SELECT
    'alerta asignada'           AS tipo,
    title                       AS detalle,
    status                      AS estado,
    created_at
FROM alerts
WHERE assigned_to_uuid = 'a1b2c3d4-0002-0002-0002-000000000002'

UNION ALL

SELECT
    'incidente asignado',
    title,
    status::TEXT,
    created_at
FROM incidents
WHERE assigned_to_uuid = 'a1b2c3d4-0002-0002-0002-000000000002'

UNION ALL

SELECT
    'accion auditada',
    action,
    COALESCE(target_type, '-'),
    occurred_at
FROM audit_logs
WHERE user_uuid = 'a1b2c3d4-0002-0002-0002-000000000002'

ORDER BY created_at DESC;


-- ============================================================
-- VERIFICACIÓN FINAL
-- ============================================================

SELECT 'users'              AS tabla, COUNT(*) AS filas FROM users
UNION ALL
SELECT 'security_events',             COUNT(*)          FROM security_events
UNION ALL
SELECT 'alerts',                      COUNT(*)          FROM alerts
UNION ALL
SELECT 'audit_logs',                  COUNT(*)          FROM audit_logs
UNION ALL
SELECT 'correlation_rules',           COUNT(*)          FROM correlation_rules
UNION ALL
SELECT 'vulnerabilities',             COUNT(*)          FROM vulnerabilities
UNION ALL
SELECT 'incidents',                   COUNT(*)          FROM incidents
UNION ALL
SELECT 'incident_vulns',              COUNT(*)          FROM incident_vulns
UNION ALL
SELECT 'incident_events',             COUNT(*)          FROM incident_events
ORDER BY tabla;

-- ============================================================
-- FIN DEL SEED v3.2
-- ============================================================
-- Tabla                Registros
-- ─────────────────── ──────────
-- users                    7
-- correlation_rules         7
-- security_events          20
-- alerts                    8
-- audit_logs               15
-- vulnerabilities           6
-- incidents                 5
-- incident_vulns            6
-- incident_events          17
-- ─────────────────── ──────────
-- TOTAL                    81
-- ============================================================
