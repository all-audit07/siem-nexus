# SIEM NEXUS v2.0

SIEM orientado a **auditoría de seguridad**: analiza logs exportados a Excel (.xlsx), detecta amenazas con reglas deterministas mapeadas a MITRE ATT&CK y convierte cada detección en un **hallazgo de auditoría** evaluado contra **ISO/IEC 27001:2022** y **CIS Controls v8**, con seguimiento hasta su verificación. Todo hallazgo es trazable hasta el Log_ID de la fila original.

## Qué hace

| Área | Implementación |
|---|---|
| Carga de evidencia | Validación fila a fila, hash SHA-256 del archivo y fila original intacta |
| Detección y correlación | 18 reglas (fuerza bruta, inicios sospechosos, escalamiento, procesos, movimiento lateral, anomalías) agrupadas en incidentes por actor |
| Dashboard | KPIs, criticidad, categorías y línea de tiempo interactivos |
| Informe técnico | Resumen, metodología, cobertura, hallazgos y anexos en PDF; redacción opcional con IA validada contra la evidencia |
| **Modo auditoría (v2.0)** | Hallazgos con condición, criterio, causa probable, efecto, verificación y recomendación, por control ISO 27001 |
| **Informe de auditoría (v2.0)** | PDF con conclusión por dominio, matriz de controles, plan de verificación y huellas SHA-256 del archivo y de los hallazgos |
| **Seguimiento (v2.0)** | Responsable, plazo por criticidad, estados con nota de evidencia, segregación de funciones e historial inmutable |

## Principios de auditoría aplicados

- **Condición probada, causa como hipótesis:** los registros prueban lo ocurrido; la causa se confirma con un procedimiento de verificación.
- **Ausencia de evidencia también es evidencia:** por ejemplo, fuerza bruta sin ningún evento de bloqueo de cuenta (4740).
- **Segregación de funciones:** quien cierra un hallazgo no puede verificarlo; solo auditor y admin verifican.
- **Integridad:** historial de seguimiento de solo inserción y huellas SHA-256 en el informe.
- **Límites declarados:** los controles sin hallazgos no se consideran evaluados.

## Arquitectura

| Capa | Tecnología |
|---|---|
| Frontend | Next.js 16, React 19, TypeScript, Tailwind 4 |
| Backend | Node.js 20 + Express (Docker) |
| Identidad | MySQL 8: usuarios, roles (RBAC) y bloqueo de cuentas |
| Análisis y auditoría | PostgreSQL 16: eventos, alertas, incidentes, informes y hallazgos de auditoría |
| SQL Server | Reservado para una bóveda de evidencias (desactivado: `MSSQL_ENABLED=false`) |

## Roles

| Rol | Puede |
|---|---|
| admin | Todo, incluido borrar importaciones |
| analyst | Importar, analizar, generar informes y gestionar la remediación |
| auditor | Generar hallazgos de auditoría y **verificar** su cierre |
| responder | Gestionar la remediación de hallazgos |
| viewer | Solo consulta |

Cada usuario debe tener **un único rol activo**: combinar roles (por ejemplo, analyst y auditor) rompe la segregación de funciones.

## Instalación

1. Variables de entorno: copia `.env.example` a `.env` y genera valores propios (`openssl rand -hex 16`; `JWT_SECRET` con `openssl rand -hex 32`).
2. Contraseñas de usuarios: `db/mysql/seed.sql` trae marcadores `REEMPLAZAR_CON_HASH_BCRYPT`. Genera cada hash con
   `node -e "console.log(require('bcryptjs').hashSync('TuContraseña', 12))"`.
   Carga los scripts de MySQL con `--default-character-set=utf8mb4`.
3. Backend y bases de datos: `docker compose up -d`.
4. Migraciones, en este orden:
   - PostgreSQL: `migration_001_import_analysis.sql`, `migration_003_audit_mode.sql`, `migration_004_audit_followup.sql`
   - MySQL: `migration_002_account_lockout.sql`

   Ejemplo: `docker exec -i siem_postgres psql -v ON_ERROR_STOP=1 -U postgresql -d siem_correlation < db/postgresql/migration_003_audit_mode.sql`
5. Frontend: en `frontend/`, ajusta la IP del backend en `next.config.ts` y ejecuta `npm install && npm run build && npm start -- -H 0.0.0.0`.

## Seguridad

- Ningún secreto en el repositorio: credenciales solo en `.env`, excluido por `.gitignore`.
- Contraseñas con bcrypt; JWT con caducidad; RBAC con 5 roles.
- Bloqueo de cuenta tras 5 fallos durante 15 minutos (`LOGIN_MAX_FAILURES`, `LOGIN_LOCK_MINUTES`) y login sin enumeración de cuentas.
- Bases de datos publicadas solo en 127.0.0.1; firewall nftables con política *drop*; cabeceras de seguridad con helmet.
- Autoauditoría del propio proyecto en `docs/auditoria/autoauditoria-v1.md`.

## Versiones

| Versión | Contenido |
|---|---|
| v1.0 | SIEM: importación, detección, correlación, dashboard, informe técnico y PDF |
| v1.0.1 | Corrección de seguridad: credenciales y acceso demo eliminados del login |
| v2.0 | Modo auditoría: hallazgos ISO 27001 / CIS v8, informe de auditoría, seguimiento y bloqueo de cuentas |
| v2.1 | Revisión independiente con CodeQL: ReDoS, aleatoriedad insegura y límites de peticiones (H-16 a H-21) |

## Próximos pasos

- Impedir en el código combinaciones de roles incompatibles (H-13).
- Proxy inverso que registre la IP real del cliente (H-21).
- Bóveda de evidencias con cadena de custodia en SQL Server.
- Registro de auditoría encadenado por hash.
- Informes firmados digitalmente.
