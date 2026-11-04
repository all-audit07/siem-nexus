-- v2.0 · H-09: bloqueo de cuenta por intentos fallidos. Idempotente.
SET @c := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'failed_attempts');
SET @s := IF(@c = 0, 'ALTER TABLE users ADD COLUMN failed_attempts TINYINT UNSIGNED NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
SET @c := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'locked_until');
SET @s := IF(@c = 0, 'ALTER TABLE users ADD COLUMN locked_until DATETIME NULL', 'SELECT 1');
PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st;
