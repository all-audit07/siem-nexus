-- v2.0 · Modo auditoría: catálogo de mapeo a controles y hallazgos de auditoría.
-- Idempotente: puede ejecutarse varias veces. El catálogo se actualiza con ON CONFLICT.
-- Se citan solo número y título de los controles ISO/IEC 27001:2022; las descripciones son redacción propia.

BEGIN;

CREATE TABLE IF NOT EXISTS audit_controls (
    framework   VARCHAR(10) NOT NULL,
    control_id  VARCHAR(10) NOT NULL,
    title       TEXT        NOT NULL,
    PRIMARY KEY (framework, control_id)
);

CREATE TABLE IF NOT EXISTS audit_rule_mapping (
    code            VARCHAR(10) PRIMARY KEY,
    finding_type    VARCHAR(12) NOT NULL CHECK (finding_type IN ('deficiencia', 'indicador')),
    iso_controls    TEXT[]      NOT NULL,
    cis_safeguards  TEXT[]      NOT NULL,
    probable_cause  TEXT        NOT NULL,
    verification    TEXT        NOT NULL,
    recommendation  TEXT        NOT NULL,
    version         INTEGER     NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_remediation_sla (
    severity  SMALLINT PRIMARY KEY CHECK (severity BETWEEN 1 AND 5),
    days      INTEGER  NOT NULL CHECK (days > 0)
);

CREATE TABLE IF NOT EXISTS audit_findings (
    id               SERIAL PRIMARY KEY,
    import_id        INTEGER     NOT NULL REFERENCES log_imports(id) ON DELETE CASCADE,
    code             VARCHAR(10) NOT NULL REFERENCES audit_rule_mapping(code),
    mapping_version  INTEGER     NOT NULL,
    finding_type     VARCHAR(12) NOT NULL,
    severity         SMALLINT    NOT NULL,
    iso_controls     TEXT[]      NOT NULL,
    cis_safeguards   TEXT[]      NOT NULL,
    condition        TEXT        NOT NULL,
    effect           TEXT,
    probable_cause   TEXT        NOT NULL,
    verification     TEXT        NOT NULL,
    recommendation   TEXT        NOT NULL,
    alert_ids        INTEGER[]   NOT NULL DEFAULT '{}',
    incident_ids     INTEGER[]   NOT NULL DEFAULT '{}',
    evidence_log_ids TEXT[]      NOT NULL DEFAULT '{}',
    status           VARCHAR(16) NOT NULL DEFAULT 'abierto'
                     CHECK (status IN ('abierto', 'en_remediacion', 'cerrado', 'verificado')),
    owner            TEXT,
    due_date         DATE,
    closed_at        TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (import_id, code)
);
CREATE INDEX IF NOT EXISTS idx_audit_findings_import ON audit_findings(import_id);
CREATE INDEX IF NOT EXISTS idx_audit_findings_iso ON audit_findings USING GIN (iso_controls);

INSERT INTO audit_remediation_sla (severity, days) VALUES
    (5, 15), (4, 30), (3, 60), (2, 90)
ON CONFLICT (severity) DO UPDATE SET days = EXCLUDED.days;

INSERT INTO audit_controls (framework, control_id, title) VALUES
    ('ISO27001', '5.9',  'Inventario de información y otros activos asociados'),
    ('ISO27001', '5.15', 'Control de acceso'),
    ('ISO27001', '5.17', 'Información de autenticación'),
    ('ISO27001', '8.2',  'Derechos de acceso privilegiados'),
    ('ISO27001', '8.3',  'Restricción del acceso a la información'),
    ('ISO27001', '8.5',  'Autenticación segura'),
    ('ISO27001', '8.7',  'Protección contra el malware'),
    ('ISO27001', '8.8',  'Gestión de las vulnerabilidades técnicas'),
    ('ISO27001', '8.9',  'Gestión de la configuración'),
    ('ISO27001', '8.12', 'Prevención de la fuga de datos'),
    ('ISO27001', '8.13', 'Copias de seguridad de la información'),
    ('ISO27001', '8.15', 'Registro de eventos'),
    ('ISO27001', '8.16', 'Actividades de seguimiento'),
    ('ISO27001', '8.18', 'Uso de programas de utilidad con privilegios'),
    ('ISO27001', '8.19', 'Instalación de software en sistemas en producción'),
    ('ISO27001', '8.20', 'Seguridad de redes'),
    ('ISO27001', '8.22', 'Segregación de redes'),
    ('ISO27001', '8.23', 'Filtrado web'),
    ('ISO27001', '8.26', 'Requisitos de seguridad de las aplicaciones')
ON CONFLICT (framework, control_id) DO UPDATE SET title = EXCLUDED.title;

INSERT INTO audit_rule_mapping (code, finding_type, iso_controls, cis_safeguards, probable_cause, verification, recommendation, version) VALUES
('BF-001', 'deficiencia', '{8.5,5.17}', '{6.3,6.4}',
 'Sin bloqueo por intentos fallidos ni MFA en el servicio expuesto; se admiten contraseñas comunes.',
 'Revisar la política de bloqueo del dominio (umbral y duración), si el servicio exige MFA y si existe una lista de contraseñas prohibidas.',
 'Aplicar bloqueo por intentos fallidos, MFA en accesos externos y una lista de contraseñas prohibidas.', 1),
('BF-002', 'deficiencia', '{8.5}', '{6.3,6.4}',
 'Sin bloqueo por intentos fallidos en la cuenta atacada.',
 'Revisar el umbral de bloqueo aplicado a esa cuenta.',
 'Aplicar bloqueo por intentos fallidos y alertar al titular de la cuenta.', 1),
('SL-001', 'deficiencia', '{8.5,5.17}', '{6.3,6.4,6.5}',
 'Contraseña adivinable y autenticación de un solo factor.',
 'Confirmar con el titular si el acceso fue legítimo y revisar el uso de MFA y la fortaleza de la contraseña.',
 'Restablecer la credencial, cerrar las sesiones activas y exigir MFA.', 1),
('SL-002', 'deficiencia', '{8.20,8.5}', '{6.4}',
 'Servicio de autenticación accesible desde Internet sin restricción de origen.',
 'Revisar las reglas de firewall y si el acceso remoto exige VPN.',
 'Permitir el acceso remoto solo por VPN con MFA.', 1),
('PE-001', 'deficiencia', '{8.2,5.15}', '{5.4,6.5}',
 'Cuentas con privilegios administrativos utilizables desde Internet.',
 'Revisar los miembros de los grupos privilegiados y desde qué orígenes pueden iniciar sesión.',
 'Usar cuentas administrativas dedicadas, solo desde equipos de administración y con MFA.', 1),
('PX-001', 'deficiencia', '{8.7,8.18}', '{2.7,8.8}',
 'PowerShell disponible sin restricciones para cualquier usuario.',
 'Revisar la política de ejecución, el modo de lenguaje restringido, AMSI y el registro de Script Block.',
 'Limitar PowerShell a administradores y activar su registro.', 1),
('PX-002', 'deficiencia', '{8.13,8.2,8.7}', '{11.3,11.4,10.7}',
 'Cuenta de servicio con privilegios para borrar instantáneas y copias de seguridad no aisladas.',
 'Revisar los privilegios de la cuenta, la existencia de copias aisladas o inmutables y la última prueba de restauración.',
 'Mantener copias aisladas o inmutables y aplicar mínimo privilegio a las cuentas de servicio.', 1),
('PX-003', 'deficiencia', '{8.8,8.9}', '{7.1,4.1}',
 'Vulnerabilidad o carga de archivos sin control en la aplicación web; la identidad del pool puede lanzar consolas.',
 'Revisar la versión y los parches de la aplicación, la escritura en el directorio web y los permisos del pool.',
 'Parchear, quitar la escritura en el directorio web y restringir la identidad del pool.', 1),
('PX-004', 'indicador', '{8.16}', '{8.11,13.1}',
 'Cuenta ya comprometida operando sin detección temprana.',
 'Revisar si existen alertas en tiempo real para comandos de enumeración.',
 'Configurar alertas de comportamiento y restringir herramientas de enumeración a administradores.', 1),
('PX-005', 'deficiencia', '{8.12}', '{3.13}',
 'Sin controles sobre el empaquetado de información sensible.',
 'Revisar la clasificación de datos y las políticas DLP en los equipos.',
 'Implantar DLP en los equipos y alertar de la compresión en rutas sensibles.', 1),
('PX-006', 'deficiencia', '{8.19,8.9}', '{2.5,2.7}',
 'Se pueden crear tareas que ejecutan scripts desde rutas escribibles y no hay lista blanca de aplicaciones.',
 'Revisar quién puede crear tareas programadas y si existe control de aplicaciones (AppLocker o WDAC).',
 'Aplicar listas blancas de aplicaciones y scripts y revisar las tareas existentes.', 1),
('PX-007', 'deficiencia', '{8.19,8.2}', '{2.5,5.4}',
 'Privilegios para instalar servicios fuera de un cambio aprobado.',
 'Revisar quién puede instalar servicios y el registro de cambios.',
 'Instalar servicios solo mediante cambios aprobados.', 1),
('PX-008', 'deficiencia', '{8.19,8.7}', '{2.5,10.7}',
 'Sin restricción de ejecución en Temp, ProgramData o Public.',
 'Comprobar las reglas de control de aplicaciones para esas rutas.',
 'Bloquear la ejecución de binarios en rutas escribibles.', 1),
('LM-001', 'deficiencia', '{8.22,8.2}', '{13.4,5.4}',
 'Red sin segmentar y credenciales privilegiadas válidas en varios servidores.',
 'Revisar desde qué orígenes se permite SMB o RDP entre servidores y dónde se usan las cuentas administrativas.',
 'Segmentar la red, restringir SMB y RDP entre servidores y separar niveles de administración.', 1),
('AN-001', 'deficiencia', '{8.3,5.15}', '{3.3}',
 'Permisos amplios en recursos compartidos.',
 'Revisar las ACL del recurso y si la cuenta necesita ese acceso.',
 'Aplicar mínimo privilegio en recursos compartidos y alertar de accesos masivos.', 1),
('AN-002', 'deficiencia', '{8.12,8.20}', '{3.13,13.4}',
 'Tráfico de salida sin restricción ni inspección.',
 'Revisar las reglas de salida del firewall o proxy y la DLP de red.',
 'Filtrar la salida por destino, implantar DLP de red y límites de volumen.', 1),
('AN-003', 'deficiencia', '{8.20,8.23}', '{4.4}',
 'Servidores con salida directa a Internet.',
 'Revisar si los servidores salen a Internet directamente o a través de un proxy.',
 'Denegar la salida por defecto en servidores y usar un proxy autenticado.', 1),
('AN-004', 'deficiencia', '{8.8,8.26}', '{13.10}',
 'Aplicación expuesta sin filtrado de capa de aplicación ni límite de solicitudes.',
 'Comprobar si existe WAF y limitación de solicitudes.',
 'Implantar WAF y limitación de solicitudes.', 1),
('T-01', 'deficiencia', '{8.15}', '{8.2,8.5}',
 'No existe política de bloqueo de cuentas o los eventos de bloqueo (4740) no se registran.',
 'Revisar la directiva de auditoría del dominio y la política de bloqueo de cuentas.',
 'Auditar la gestión de cuentas y enviar esos eventos al SIEM.', 1),
('T-02', 'deficiencia', '{5.9}', '{1.1}',
 'Nomenclatura de equipos inconsistente o inventario no conciliado con los registros.',
 'Cotejar los nombres con el inventario de activos y el DNS.',
 'Definir una nomenclatura única y conciliar el inventario con los registros.', 1)
ON CONFLICT (code) DO UPDATE SET
    finding_type   = EXCLUDED.finding_type,
    iso_controls   = EXCLUDED.iso_controls,
    cis_safeguards = EXCLUDED.cis_safeguards,
    probable_cause = EXCLUDED.probable_cause,
    verification   = EXCLUDED.verification,
    recommendation = EXCLUDED.recommendation,
    version        = EXCLUDED.version;

COMMIT;

