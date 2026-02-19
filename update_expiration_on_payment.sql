-- Script para actualizar el stored procedure prInsertEconomicIncome
-- para que actualice la fecha de expiración de membresía del cliente automáticamente

-- ============================================
-- PASO 1: Agregar columna durationDays a tbActivityType
-- ============================================
ALTER TABLE tbActivityType 
ADD COLUMN IF NOT EXISTS durationDays INT DEFAULT 0 COMMENT 'Días de duración de la membresía';

-- Actualizar los valores iniciales para los tipos existentes
UPDATE tbActivityType SET durationDays = 30 WHERE idActivityType = 1;  -- Membresía
UPDATE tbActivityType SET durationDays = 15 WHERE idActivityType = 3;  -- Quincenal
UPDATE tbActivityType SET durationDays = 7  WHERE idActivityType = 4;  -- Semanal
UPDATE tbActivityType SET durationDays = 1  WHERE idActivityType = 5;  -- Sesión Diaria
UPDATE tbActivityType SET durationDays = 30 WHERE idActivityType = 6;  -- Membresía Limitada

-- ============================================
-- PASO 2: Actualizar el stored procedure
-- ============================================
DELIMITER $$

DROP PROCEDURE IF EXISTS prInsertEconomicIncome$$

CREATE PROCEDURE prInsertEconomicIncome(
    IN pIdClient INT,
    IN pRegistrationDate DATE,
    IN pVoucherNumber VARCHAR(100),
    IN pDetail TEXT,
    IN pIdMeanOfPayment INT,
    IN pAmount DECIMAL(10,2),
    IN pIdActivityType INT,
    IN pDelayDays INT,
    IN pLoggedIdUser INT,
    OUT result INT
)
BEGIN
    DECLARE v_days_to_add INT DEFAULT 0;
    DECLARE v_current_expiration DATE;
    DECLARE v_new_expiration DATE;
    
    -- Inicializar resultado
    SET result = 0;
    
    -- Verificar si el voucher ya existe
    IF pVoucherNumber IS NOT NULL AND pVoucherNumber != '' THEN
        IF EXISTS (SELECT 1 FROM tbEconomicIncome WHERE voucherNumber = pVoucherNumber AND isDeleted = 0) THEN
            SET result = -1;
            -- SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Voucher duplicado';
        END IF;
    END IF;
    
    IF result != -1 THEN
        -- Insertar el registro de ingreso económico
        INSERT INTO tbEconomicIncome (
            idActivityType,
            idClient,
            registrationDate,
            voucherNumber,
            detail,
            amount,
            idMeanOfPayment,
            delayDays,
            createdByUser,
            isDeleted
        ) VALUES (
            pIdActivityType,
            pIdClient,
            pRegistrationDate,
            pVoucherNumber,
            pDetail,
            pAmount,
            pIdMeanOfPayment,
            pDelayDays,
            pLoggedIdUser,
            0
        );
        
        -- Solo actualizar fecha de expiración si hay un cliente asociado
        IF pIdClient IS NOT NULL AND pIdClient > 0 THEN
            -- Obtener los días de duración desde tbActivityType (dinámico)
            SELECT COALESCE(durationDays, 0) INTO v_days_to_add
            FROM tbActivityType
            WHERE idActivityType = pIdActivityType;
            
            -- Si el tipo de actividad tiene días asignados, actualizar expiración
            IF v_days_to_add > 0 THEN
                -- Restar los días de retraso (si vino sin pagar, esos días ya los usó)
                IF pDelayDays IS NOT NULL AND pDelayDays > 0 THEN
                    SET v_days_to_add = v_days_to_add - pDelayDays;
                    -- Asegurar que no sea negativo
                    IF v_days_to_add < 0 THEN
                        SET v_days_to_add = 0;
                    END IF;
                END IF;
                
                -- Solo actualizar si quedan días por agregar
                IF v_days_to_add > 0 THEN
                    -- Obtener la fecha de expiración actual del cliente
                    SELECT expirationMembershipDate INTO v_current_expiration
                    FROM tbClient
                    WHERE idClient = pIdClient;
                    
                    -- Calcular nueva fecha de expiración:
                    -- Si está vencida o es NULL, usar la fecha actual como base
                    -- Si no está vencida, sumar a la fecha existente
                    IF v_current_expiration IS NULL OR v_current_expiration < CURDATE() THEN
                        SET v_new_expiration = DATE_ADD(CURDATE(), INTERVAL v_days_to_add DAY);
                    ELSE
                        SET v_new_expiration = DATE_ADD(v_current_expiration, INTERVAL v_days_to_add DAY);
                    END IF;
                    
                    -- Actualizar la fecha de expiración del cliente
                    UPDATE tbClient
                    SET expirationMembershipDate = v_new_expiration
                    WHERE idClient = pIdClient;
                END IF;
            END IF;
        END IF;
        
        SET result = 1;
    END IF;
END$$

DELIMITER ;
