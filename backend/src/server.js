// src/server.js
require('dotenv').config();
process.on('uncaughtException', e => console.error('UNCAUGHT:', e.message));
process.on('unhandledRejection', e => console.error('UNHANDLED:', e?.message || e));

const app = require('./app');
const { testMySQL }     = require('./config/mysql');
const { testPostgres }  = require('./config/postgres');
const { testSqlServer } = require('./config/sqlserver');

const PORT = process.env.PORT || 3000;
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Reintenta la conexión (las BD pueden tardar en estar listas al arrancar Docker)
const withRetry = async (name, fn, tries = 10, delayMs = 3000) => {
  for (let i = 1; i <= tries; i++) {
    try { await fn(); return true; }
    catch (err) {
      console.error(`❌ ${name} (intento ${i}/${tries}): ${err.message}`);
      if (i < tries) await sleep(delayMs);
    }
  }
  return false;
};

const start = async () => {
  console.log('\n🛡️  SIEM Multi-Motor Backend — Iniciando...\n');

  // El servidor arranca SIEMPRE, independientemente del estado de las BD
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Servidor escuchando en puerto ${PORT}`);
  });

  await Promise.all([
    withRetry('MySQL', testMySQL),
    withRetry('PostgreSQL', testPostgres),
  ]);
  await withRetry('SQL Server', testSqlServer, 1); // opcional: un solo intento
};

start();
