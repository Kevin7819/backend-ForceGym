-- Script para crear la tabla de recuperación de contraseña para clientes
-- Tabla tbClientPasswordRecovery

CREATE TABLE IF NOT EXISTS tbClientPasswordRecovery (
    idPasswordRecovery BIGINT AUTO_INCREMENT PRIMARY KEY,
    idClient INT NOT NULL,
    recoveryToken VARCHAR(255) NOT NULL UNIQUE,
    timeCreated DATETIME NOT NULL,
    expiryDate DATETIME NOT NULL,
    clientFingerprint VARCHAR(512) NOT NULL,
    salt VARCHAR(512) NOT NULL,
    verificationHash VARCHAR(512) NOT NULL,
    isUsed BOOLEAN DEFAULT FALSE,
    CONSTRAINT fk_client_password_recovery 
        FOREIGN KEY (idClient) 
        REFERENCES tbClient(idClient)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Crear índice para mejorar la búsqueda por token
CREATE INDEX idx_recovery_token ON tbClientPasswordRecovery(recoveryToken);

-- Crear índice para mejorar la búsqueda por cliente
CREATE INDEX idx_client_id ON tbClientPasswordRecovery(idClient);
