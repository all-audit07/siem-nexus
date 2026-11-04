const { Pool } = require('pg');

const pool = new Pool({
    host:     process.env.PG_HOST     || 'localhost',
    port:     parseInt(process.env.PG_PORT || '5432'),
    database: process.env.PG_DATABASE || 'siem_correlation',
    user:     process.env.PG_USER     || 'postgresql',
    password: process.env.PG_PASSWORD,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

const testPostgres = async () => {
    try {
        const client = await pool.connect();
        await client.query('SELECT 1');
        client.release();
        console.log('✅ PostgreSQL conectado');
    } catch (err) {
        console.error('❌ PostgreSQL error:', err.message);
    }
};

module.exports = { pool, testPostgres };
