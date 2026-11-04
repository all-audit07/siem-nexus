// src/config/sqlserver.js
// Pool de conexion a SQL Server (motor de eventos del SIEM)
// Conexion perezosa y opcional: solo conecta si MSSQL_ENABLED=true

const sql = require('mssql');

const config = {
  server: process.env.MSSQL_HOST || 'sqlserver',
  port: parseInt(process.env.MSSQL_PORT, 10) || 1433,
  database: process.env.MSSQL_DATABASE || 'siem_events',
  user: process.env.MSSQL_USER || 'sa',
  password: process.env.MSSQL_PASSWORD,
  options: {
    // Contenedor con certificado autofirmado
    encrypt: false,
    trustServerCertificate: true,
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000,
  },
};

const ENABLED = process.env.MSSQL_ENABLED === 'true';
let poolPromise = null;

// Conexión perezosa: solo conecta si está habilitado y cuando se necesita
function getPool() {
  if (!ENABLED) return Promise.reject(new Error('SQL Server deshabilitado (MSSQL_ENABLED=false)'));
  if (!poolPromise) {
    poolPromise = new sql.ConnectionPool(config).connect()
      .then(pool => { console.log('[sqlserver] Pool de conexion establecido'); return pool; })
      .catch(err => { poolPromise = null; throw err; }); // permite reintentar
  }
  return poolPromise;
}

/**
 * Ejecuta una query simple.
 */
async function query(queryText, params = {}) {
  const pool = await getPool();
  const request = pool.request();

  Object.entries(params).forEach(([key, value]) => {
    request.input(key, value);
  });

  return request.query(queryText);
}

/**
 * Ejecuta una query que necesita leer raw_payload o enrichment_data
 * (columnas cifradas). Abre y cierra la SYMMETRIC KEY dentro de la
 * misma transaccion.
 */
async function queryWithDecryption(queryText, params = {}) {
  const pool = await getPool();
  const transaction = new sql.Transaction(pool);

  await transaction.begin();
  try {
    const request = new sql.Request(transaction);

    await request.query(`
      OPEN SYMMETRIC KEY SiemEventsKey
      DECRYPTION BY CERTIFICATE SiemEventsCert;
    `);

    const dataRequest = new sql.Request(transaction);
    Object.entries(params).forEach(([key, value]) => {
      dataRequest.input(key, value);
    });
    const result = await dataRequest.query(queryText);

    await request.query('CLOSE SYMMETRIC KEY SiemEventsKey;');
    await transaction.commit();

    return result;
  } catch (err) {
    await transaction.rollback();
    throw err;
  }
}

/**
 * Inserta un security_event con raw_payload cifrado con ENCRYPTBYKEY.
 */
async function insertEncryptedEvent({
  eventType, severity, sourceIp, destIp, userUuid,
  description, rawPayload, occurredAt,
}) {
  const pool = await getPool();
  const transaction = new sql.Transaction(pool);

  await transaction.begin();
  try {
    const openKeyReq = new sql.Request(transaction);
    await openKeyReq.query(`
      OPEN SYMMETRIC KEY SiemEventsKey
      DECRYPTION BY CERTIFICATE SiemEventsCert;
    `);

    const insertReq = new sql.Request(transaction);
    insertReq.input('eventType', sql.NVarChar(60), eventType);
    insertReq.input('severity', sql.TinyInt, severity);
    insertReq.input('sourceIp', sql.NVarChar(45), sourceIp);
    insertReq.input('destIp', sql.NVarChar(45), destIp);
    insertReq.input('userUuid', sql.UniqueIdentifier, userUuid || null);
    insertReq.input('description', sql.NVarChar(sql.MAX), description);
    insertReq.input('rawPayload', sql.NVarChar(sql.MAX), rawPayload);
    insertReq.input('occurredAt', sql.DateTimeOffset, occurredAt);

    const result = await insertReq.query(`
      INSERT INTO security_events
        (event_type, severity, source_ip, dest_ip, user_uuid,
         description, raw_payload, occurred_at)
      OUTPUT INSERTED.id
      VALUES
        (@eventType, @severity, @sourceIp, @destIp, @userUuid,
         @description, ENCRYPTBYKEY(KEY_GUID('SiemEventsKey'), @rawPayload), @occurredAt);
    `);

    const closeKeyReq = new sql.Request(transaction);
    await closeKeyReq.query('CLOSE SYMMETRIC KEY SiemEventsKey;');

    await transaction.commit();
    return result.recordset[0].id;
  } catch (err) {
    await transaction.rollback();
    throw err;
  }
}

const testSqlServer = async () => {
  if (!ENABLED) { console.log('⏸️  SQL Server deshabilitado'); return; }
  const pool = await getPool();
  await pool.request().query('SELECT 1 AS test');
  console.log('✅ SQL Server conectado');
};

module.exports = {
  sql,
  getPool,
  query,
  queryWithDecryption,
  insertEncryptedEvent,
  testSqlServer,
};
