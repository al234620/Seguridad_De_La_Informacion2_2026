
PRAGMA foreign_keys = ON;


CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'CLIENTE'
                    CHECK (role IN ('CLIENTE', 'OPERADOR', 'ADMINISTRADOR')),
    status          TEXT    NOT NULL DEFAULT 'ACTIVO'
                    CHECK (status IN ('ACTIVO', 'DESACTIVADO')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT    NOT NULL,
    last_login      TEXT
);

-- Sesiones del lado servidor: se guarda el SHA-256 del token, nunca el
-- token. Permite que el ADMINISTRADOR revoque sesiones.
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT    PRIMARY KEY,           -- SHA-256(token) en hex
    user_id     INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    ip          TEXT,
    user_agent  TEXT,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Tokens de recuperación: se guarda solo su hash, expiran y son de un uso.
CREATE TABLE IF NOT EXISTS password_resets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    token_hash  TEXT    NOT NULL UNIQUE,
    created_at  TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    used_at     TEXT
);

-- ---------------------------------------------------------------------
-- Catálogo. file_name apunta al archivo CIFRADO (AES-256-GCM) en
-- productos/; file_hash es el SHA-256 del archivo original en claro.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    price       INTEGER NOT NULL CHECK (price >= 0),   -- centavos
    file_name   TEXT    NOT NULL UNIQUE,
    file_hash   TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'ACTIVO'
                CHECK (status IN ('ACTIVO', 'INACTIVO')),
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS cart_items (
    user_id     INTEGER NOT NULL REFERENCES users(id),
    product_id  INTEGER NOT NULL REFERENCES products(id),
    added_at    TEXT    NOT NULL,
    PRIMARY KEY (user_id, product_id)
);

-- ---------------------------------------------------------------------
-- Órdenes. order_items conserva el precio histórico.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS orders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    total       INTEGER NOT NULL CHECK (total >= 0),   -- centavos
    status      TEXT    NOT NULL DEFAULT 'PENDIENTE'
                CHECK (status IN ('PENDIENTE', 'PAGADA', 'RECHAZADA',
                                  'ENTREGADA', 'CANCELADA')),
    created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);

CREATE TABLE IF NOT EXISTS order_items (
    order_id    INTEGER NOT NULL REFERENCES orders(id),
    product_id  INTEGER NOT NULL REFERENCES products(id),
    price       INTEGER NOT NULL CHECK (price >= 0),   -- precio al comprar
    PRIMARY KEY (order_id, product_id)
);

-- Pagos SIMULADOS: no hay columnas para tarjeta, CVV ni cuentas.
CREATE TABLE IF NOT EXISTS payments (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id              INTEGER NOT NULL REFERENCES orders(id),
    transaction_reference TEXT    NOT NULL UNIQUE,
    amount                INTEGER NOT NULL,           -- centavos
    status                TEXT    NOT NULL CHECK (status IN ('APROBADO', 'RECHAZADO')),
    created_at            TEXT    NOT NULL
);

-- Comprobante firmado: contenido canónico (JSON) + firma RSA-PSS.
CREATE TABLE IF NOT EXISTS receipts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id    INTEGER NOT NULL UNIQUE REFERENCES orders(id),
    content     TEXT    NOT NULL,
    signature   TEXT    NOT NULL,    -- Base64
    algorithm   TEXT    NOT NULL,
    key_id      TEXT    NOT NULL,    -- SHA-256 de la clave pública
    created_at  TEXT    NOT NULL
);

-- Cada descarga = una copia personalizada con su fingerprint.
CREATE TABLE IF NOT EXISTS downloads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    order_id    INTEGER NOT NULL REFERENCES orders(id),
    product_id  INTEGER NOT NULL REFERENCES products(id),
    fingerprint TEXT    NOT NULL UNIQUE,
    copy_hash   TEXT    NOT NULL,    -- SHA-256 de la copia entregada
    ip          TEXT,
    created_at  TEXT    NOT NULL
);

-- ---------------------------------------------------------------------
-- Bitácora de seguridad. Encadenada con SHA-256 (cada registro incluye
-- el hash del anterior) y protegida contra UPDATE/DELETE por triggers.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    email       TEXT,
    event       TEXT    NOT NULL,
    result      TEXT    NOT NULL,
    source      TEXT    NOT NULL,     -- IP de origen o 'sistema'
    details     TEXT,
    created_at  TEXT    NOT NULL,
    prev_hash   TEXT    NOT NULL,
    hash        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_event ON security_events(event);

CREATE TRIGGER IF NOT EXISTS trg_events_no_update
BEFORE UPDATE ON security_events
BEGIN
    SELECT RAISE(ABORT, 'security_events es de solo insercion');
END;

CREATE TRIGGER IF NOT EXISTS trg_events_no_delete
BEFORE DELETE ON security_events
BEGIN
    SELECT RAISE(ABORT, 'security_events es de solo insercion');
END;

-- Configuración de seguridad administrable por el ADMINISTRADOR.
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);
INSERT OR IGNORE INTO settings(key, value) VALUES
    ('max_intentos_login', '5'),
    ('minutos_bloqueo', '15'),
    ('minutos_inactividad_sesion', '30'),
    ('horas_vida_sesion', '8'),
    ('minutos_token_recuperacion', '20');
