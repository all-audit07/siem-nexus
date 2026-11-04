const mysql = require('mysql2/promise');

const pool = mysql.createPool({
    host:     process.env.MYSQL_HOST     || 'localhost',
    port:     parseInt(process.env.MYSQL_PORT || '3306'),
    database: process.env.MYSQL_DATABASE || 'siem_benchmark',
    user:     process.env.MYSQL_USER     || 'siem_user',
    password: process.env.MYSQL_PASSWORD,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    timezone: 'Z',
});

const testMySQL = async () => {
    try {
        const conn = await pool.getConnection();
        await conn.ping();
        conn.release();
        console.log('✅ MySQL conectado');
    } catch (err) {
        console.error('❌ MySQL error:', err.message);
    }
};

module.exports = { pool, testMySQL };
