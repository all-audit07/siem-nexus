/* ============================================================================
   SIEM Multi-Motor - SQL Server (Motor 02)
   encryption.sql - Cifrado por columna (Cell-Level Encryption)
   ----------------------------------------------------------------------------
   Objetivo: cifrar raw_payload y enrichment_data en security_events.

   Jerarquia de claves de SQL Server (de afuera hacia adentro):
       Database Master Key (DMK)
            -> Certificado (protege la symmetric key)
                 -> Symmetric Key (cifra/descifra los datos)
                      -> Columnas cifradas (VARBINARY)

   Orden de ejecucion: despues de seed.sql
   ============================================================================ */

USE siem_events;
GO

-- OBLIGATORIO: security_events tiene un indice filtrado (idx_events_original).
-- SQL Server exige estos SET options en ON para poder hacer UPDATE sobre
-- una tabla con indices filtrados. Sin esto, los UPDATE fallan en silencio.
SET QUOTED_IDENTIFIER ON;
SET ANSI_NULLS ON;
GO

/* ============================================================================
   1. Database Master Key - protege todo lo demas en esta base de datos
   ============================================================================ */
IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
BEGIN
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'CAMBIA_ESTA_CLAVE';
END
GO

/* ============================================================================
   2. Certificado - protege la symmetric key
   ============================================================================ */
IF NOT EXISTS (SELECT * FROM sys.certificates WHERE name = 'SiemEventsCert')
BEGIN
    CREATE CERTIFICATE SiemEventsCert
    WITH SUBJECT = 'Certificado para cifrado de eventos sensibles - SIEM',
         EXPIRY_DATE = '2030-12-31';
END
GO

/* ============================================================================
   3. Symmetric Key - la clave real que cifra/descifra (AES_256)
   ============================================================================ */
IF NOT EXISTS (SELECT * FROM sys.symmetric_keys WHERE name = 'SiemEventsKey')
BEGIN
    CREATE SYMMETRIC KEY SiemEventsKey
    WITH ALGORITHM = AES_256
    ENCRYPTION BY CERTIFICATE SiemEventsCert;
END
GO

/* ============================================================================
   4. Agregar columnas cifradas (VARBINARY) junto a las columnas en claro
   ============================================================================ */
ALTER TABLE security_events ADD raw_payload_enc       VARBINARY(MAX) NULL;
ALTER TABLE security_events ADD enrichment_data_enc   VARBINARY(MAX) NULL;
GO

/* ============================================================================
   5. Migrar los datos existentes a las columnas cifradas
   ============================================================================ */
OPEN SYMMETRIC KEY SiemEventsKey
DECRYPTION BY CERTIFICATE SiemEventsCert;

UPDATE security_events
SET raw_payload_enc = ENCRYPTBYKEY(KEY_GUID('SiemEventsKey'), raw_payload)
WHERE raw_payload IS NOT NULL;

UPDATE security_events
SET enrichment_data_enc = ENCRYPTBYKEY(KEY_GUID('SiemEventsKey'), enrichment_data)
WHERE enrichment_data IS NOT NULL;

CLOSE SYMMETRIC KEY SiemEventsKey;
GO

/* ============================================================================
   6. Verificacion visual: texto plano vs cifrado (captura esto para el informe)
   ============================================================================ */
SELECT TOP 5
    id,
    raw_payload,
    raw_payload_enc
FROM security_events
WHERE raw_payload IS NOT NULL;
GO

/* ============================================================================
   7. Eliminar columnas en texto plano (irreversible)
   ============================================================================ */
ALTER TABLE security_events DROP COLUMN raw_payload;
ALTER TABLE security_events DROP COLUMN enrichment_data;
GO

EXEC sp_rename 'security_events.raw_payload_enc', 'raw_payload', 'COLUMN';
EXEC sp_rename 'security_events.enrichment_data_enc', 'enrichment_data', 'COLUMN';
GO

/* ============================================================================
   8. Como leer los datos cifrados (descifrado) - patron para el backend
   ============================================================================ */
OPEN SYMMETRIC KEY SiemEventsKey
DECRYPTION BY CERTIFICATE SiemEventsCert;

SELECT TOP 10
    id,
    event_type,
    severity,
    CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(raw_payload))       AS raw_payload_legible,
    CONVERT(NVARCHAR(MAX), DECRYPTBYKEY(enrichment_data))   AS enrichment_data_legible
FROM security_events
ORDER BY occurred_at DESC;

CLOSE SYMMETRIC KEY SiemEventsKey;
GO

/* ============================================================================
   FIN encryption.sql
   ============================================================================ */
