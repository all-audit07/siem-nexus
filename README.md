# SIEM NEXUS v1.0

SIEM que analiza logs de seguridad exportados a Excel (.xlsx), detecta amenazas con reglas deterministas mapeadas a MITRE ATT&CK, correlaciona alertas en incidentes, clasifica el riesgo con justificación y genera un informe técnico exportable a PDF. Cada hallazgo es trazable hasta el Log_ID de la fila original.

## Funcionalidades

| Requisito | Implementación |
|---|---|
| Carga de Excel | Validación fila a fila, hash SHA-256 del archivo, fila original intacta |
| Análisis y correlación | 18 reglas (fuerza bruta, inicios sospechosos, escalamiento, procesos, movimiento lateral, anomalías); incidentes agrupados por actor |
| Dashboard | KPIs, criticidad, categorías y línea de tiempo interactivos |
| Clasificación de riesgo | Crítico / Alto / Medio / Bajo con justificación y evidencia por alerta |
| Informe técnico | Resumen, metodología, cobertura, hallazgos, recomendaciones y anexos |
| IA (opcional) | Claude redacta resumen y narrativas; un validador descarta todo texto que cite datos fuera de la evidencia |
| PDF | Exportación del informe completo |

## Arquitectura

| Capa | Tecnología |
|---|---|
| Frontend | Next.js 16, React 19, TypeScript, Tailwind 4 |
| Backend | Node.js 20 + Express (Docker) |
| Identidad | MySQL 8: usuarios y roles (RBAC) |
| Análisis | PostgreSQL 16: eventos, alertas, evidencias, incidentes, informes |
| SQL Server | Reservado para la v2.0 (desactivado: `MSSQL_ENABLED=false`) |

## Instalación

1. Variables de entorno: copia `.env.example` a `.env` y genera valores propios (`openssl rand -hex 16`; `JWT_SECRET` con `openssl rand -hex 32`).
2. Contraseñas de usuarios: `db/mysql/seed.sql` trae marcadores `REEMPLAZAR_CON_HASH_BCRYPT`. Genera cada hash con:
   `node -e "console.log(require('bcryptjs').hashSync('TuContraseña', 12))"`
3. Backend y bases de datos: `docker compose up -d`
4. Esquema de análisis: `docker exec -i siem_postgres psql -U postgresql -d siem_correlation < db/postgresql/migration_001_import_analysis.sql`
5. Frontend: en `frontend/`, ajusta la IP del backend en `next.config.ts` y ejecuta `npm install && npm run build && npm start -- -H 0.0.0.0`

## Seguridad

- Ningún secreto en el repositorio: credenciales solo en `.env`, excluido por `.gitignore`.
- Contraseñas con bcrypt; JWT con caducidad; RBAC con 5 roles; límite de intentos de login.
- Bases de datos publicadas solo en 127.0.0.1; firewall nftables con política *drop*.
- Cabeceras HTTP de seguridad con helmet.

## Hoja de ruta: v2.0, auditoría de seguridad

- Hallazgos de auditoría (condición, criterio, causa, efecto, recomendación) mapeados a ISO/IEC 27001:2022, CIS Controls y NIST CSF.
- Bóveda de evidencias con cadena de custodia en SQL Server.
- Registro de auditoría encadenado por hash.
- Informes firmados digitalmente.
