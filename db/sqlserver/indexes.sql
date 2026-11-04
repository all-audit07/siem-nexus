/* ============================================================================
   SIEM Multi-Motor — SQL Server (Motor 02)
   indexes.sql — Covering indexes (INCLUDE) para las queries del dashboard
   ----------------------------------------------------------------------------
   Criterio: cada índice cubre tanto la columna de FILTRADO (clave del índice)
   como las columnas que el dashboard SIEMPRE pide al hacer ese filtro
   (vía INCLUDE), para evitar que SQL Server tenga que volver a la tabla
   (key lookup) después de usar el índice.
   ============================================================================ */

USE siem_events;
GO

-- Requerido por SQL Server para crear índices filtrados (idx_events_original)
SET QUOTED_IDENTIFIER ON;
GO

/* ============================================================================
   security_events — índices esenciales
   ============================================================================ */

-- Panel de eventos en tiempo real (dashboard principal)
-- Filtra/ordena por occurred_at; siempre muestra tipo, severidad e IPs.
CREATE INDEX idx_events_time
ON security_events (occurred_at DESC)
INCLUDE (event_type, severity, source_ip, dest_ip, user_uuid, is_enriched);
GO

-- Panel de categorías — filtrado por tipo de evento
CREATE INDEX idx_events_type
ON security_events (event_type)
INCLUDE (occurred_at, severity);
GO

-- Alertas críticas recientes — compuesto severidad + tiempo
CREATE INDEX idx_events_sev_time
ON security_events (severity, occurred_at DESC)
INCLUDE (event_type, source_ip, user_uuid);
GO

-- Investigación de incidente — búsqueda por IP origen
CREATE INDEX idx_events_srcip
ON security_events (source_ip)
INCLUDE (occurred_at, event_type, severity);
GO

-- Reconstrucción del árbol de versiones de un evento (versionado v2)
-- Acelera "dame todas las versiones derivadas de este evento original".
CREATE INDEX idx_events_original
ON security_events (original_event_id)
INCLUDE (version, occurred_at)
WHERE original_event_id IS NOT NULL;
GO

/* ============================================================================
   alerts — índices esenciales
   ============================================================================ */

-- Cola de trabajo del analista — filtrado por estado
CREATE INDEX idx_alerts_status
ON alerts (status)
INCLUDE (severity, title, assigned_to_uuid, created_at);
GO

-- Alertas asignadas por analista
CREATE INDEX idx_alerts_analyst
ON alerts (assigned_to_uuid)
INCLUDE (status, severity, title, created_at);
GO

-- Query más común del dashboard: alertas críticas abiertas
CREATE INDEX idx_alerts_sev_status
ON alerts (severity, status)
INCLUDE (title, assigned_to_uuid, created_at);
GO

/* ============================================================================
   audit_logs — índices esenciales
   ============================================================================ */

-- Auditoría por analista
CREATE INDEX idx_audit_user
ON audit_logs (user_uuid)
INCLUDE (action, occurred_at, target_table);
GO

-- Filtrado por tipo de acción
CREATE INDEX idx_audit_action
ON audit_logs (action)
INCLUDE (user_uuid, occurred_at);
GO

-- Reportes de auditoría por rango de tiempo
CREATE INDEX idx_audit_time
ON audit_logs (occurred_at DESC)
INCLUDE (user_uuid, action, target_table, target_id);
GO

/* ============================================================================
   NOTA — costo de mantenimiento
   ----------------------------------------------------------------------------
   Los covering indexes aceleran lecturas pero cada uno agrega overhead en
   cada INSERT/UPDATE (deben actualizarse junto con la tabla). audit_logs y
   security_events son las tablas de mayor volumen de escritura del benchmark
   (ver sección de INSERT masivo) — si al medir el benchmark de escritura el
   rendimiento baja demasiado, candidatos a recortar primero:
     - idx_events_srcip   (uso ocasional, solo en investigación puntual)
     - idx_audit_action   (uso ocasional, solo en reportes filtrados)
   ============================================================================ */
