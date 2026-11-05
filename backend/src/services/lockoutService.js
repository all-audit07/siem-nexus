// Bloqueo de cuenta por intentos fallidos (v2.0 · H-09)
const { pool } = require('../config/mysql');

const MAX_FAILURES = parseInt(process.env.LOGIN_MAX_FAILURES || '5', 10);
const LOCK_MINUTES = parseInt(process.env.LOGIN_LOCK_MINUTES || '15', 10);

const isLocked = async (username) => {
    const [rows] = await pool.execute(
        'SELECT (locked_until IS NOT NULL AND locked_until > UTC_TIMESTAMP()) AS locked FROM users WHERE username = ? LIMIT 1',
        [username]
    );
    return Boolean(rows[0] && rows[0].locked);
};

// Suma un fallo; al llegar al máximo bloquea la cuenta y reinicia el contador
const registerFailure = async (username) => {
    await pool.execute(
        `UPDATE users
            SET locked_until    = IF(failed_attempts + 1 >= ?, UTC_TIMESTAMP() + INTERVAL ? MINUTE, locked_until),
                failed_attempts = IF(failed_attempts + 1 >= ?, 0, failed_attempts + 1)
          WHERE username = ?`,
        [MAX_FAILURES, LOCK_MINUTES, MAX_FAILURES, username]
    );
    return isLocked(username);
};

const reset = (username) => pool.execute(
    'UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = UTC_TIMESTAMP() WHERE username = ?',
    [username]
);

module.exports = { isLocked, registerFailure, reset, MAX_FAILURES, LOCK_MINUTES };
