/* ============================================================================
   SIEM Multi-Motor — SQL Server (Motor 02)
   triggers.sql — Inmutabilidad de security_events (gobernanza v3)
   ----------------------------------------------------------------------------
   Regla de oro: nunca se hace UPDATE de un evento original. Excepción única:
   el proceso de enriquecimiento puede actualizar is_enriched/enrichment_data.
   Cualquier otro cambio debe insertarse como un nuevo registro con
   version = version_anterior + 1 y original_event_id apuntando al original.
   ============================================================================ */

USE siem_events;
GO

CREATE TRIGGER trg_security_events_restrict_update
ON security_events
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @msg NVARCHAR(4000);

    -- Si se intenta modificar cualquier columna que NO sea
    -- is_enriched o enrichment_data, se rechaza el UPDATE completo.
    IF UPDATE(id)
       OR UPDATE(event_uuid)
       OR UPDATE(event_type)
       OR UPDATE(severity)
       OR UPDATE(source_ip)
       OR UPDATE(dest_ip)
       OR UPDATE(user_uuid)
       OR UPDATE(description)
       OR UPDATE(raw_payload)
       OR UPDATE(occurred_at)
       OR UPDATE(ingested_at)
       OR UPDATE(version)
       OR UPDATE(original_event_id)
    BEGIN
        ROLLBACK TRANSACTION;

        SET @msg = N'security_events es inmutable, salvo enriquecimiento. ' +
                   N'Solo se permite UPDATE de is_enriched / enrichment_data. ' +
                   N'Para cualquier otro cambio, inserta un nuevo registro con ' +
                   N'version = version_anterior + 1 y original_event_id apuntando al original.';

        RAISERROR (@msg, 16, 1);

        RETURN;
    END
END;
GO
