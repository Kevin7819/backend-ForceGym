-- =====================================================
-- Stored Procedure CORREGIDO: prInsertEconomicIncome
-- CAMBIO: Usar meses en lugar de días para membresías mensuales
-- Esto mantiene el mismo día del mes para pagos recurrentes
-- =====================================================

USE dbforcegym;

DROP PROCEDURE IF EXISTS `prInsertEconomicIncome`;

DELIMITER $$

CREATE DEFINER=`root`@`%` PROCEDURE `prInsertEconomicIncome`(
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
    DECLARE v_months_to_add INT DEFAULT 0;
    DECLARE v_current_expiration DATE;
    DECLARE v_new_expiration DATE;
    DECLARE v_use_months BOOLEAN DEFAULT FALSE;
    
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
            
            -- ✅ NUEVO: Determinar si es membresía mensual (30 días o múltiplos de 30)
            -- Si es múltiplo de 30, usar cálculo por meses para mantener el día fijo
            IF v_days_to_add > 0 AND (v_days_to_add % 30 = 0) THEN
                SET v_use_months = TRUE;
                SET v_months_to_add = v_days_to_add DIV 30;
            END IF;
            
            -- Si el tipo de actividad tiene días asignados, actualizar expiración
            IF v_days_to_add > 0 THEN
                -- Restar los días de retraso (si vino sin pagar, esos días ya los usó)
                IF pDelayDays IS NOT NULL AND pDelayDays > 0 THEN
                    SET v_days_to_add = v_days_to_add - pDelayDays;
                    -- Si usamos meses, recalcular
                    IF v_use_months THEN
                        SET v_months_to_add = v_days_to_add DIV 30;
                        -- Si queda menos de 30 días, usar días
                        IF v_months_to_add = 0 THEN
                            SET v_use_months = FALSE;
                        END IF;
                    END IF;
                    
                    -- Asegurar que no sea negativo
                    IF v_days_to_add < 0 THEN
                        SET v_days_to_add = 0;
                        SET v_months_to_add = 0;
                    END IF;
                END IF;
                
                -- Solo actualizar si quedan días por agregar
                IF v_days_to_add > 0 THEN
                    -- Obtener la fecha de expiración actual del cliente
                    SELECT expirationMembershipDate INTO v_current_expiration
                    FROM tbClient
                    WHERE idClient = pIdClient;
                    
                    -- Calcular nueva fecha de expiración:
                    -- Si está vencida o es NULL, usar la FECHA DE REGISTRO (pRegistrationDate) como base
                    -- Si no está vencida, sumar a la fecha existente
                    IF v_current_expiration IS NULL OR v_current_expiration < pRegistrationDate THEN
                        -- ✅ CAMBIO: Usar meses si es membresía mensual, desde la fecha de pago
                        IF v_use_months THEN
                            SET v_new_expiration = DATE_ADD(pRegistrationDate, INTERVAL v_months_to_add MONTH);
                        ELSE
                            SET v_new_expiration = DATE_ADD(pRegistrationDate, INTERVAL v_days_to_add DAY);
                        END IF;
                    ELSE
                        -- ✅ CAMBIO: Usar meses si es membresía mensual
                        IF v_use_months THEN
                            SET v_new_expiration = DATE_ADD(v_current_expiration, INTERVAL v_months_to_add MONTH);
                        ELSE
                            SET v_new_expiration = DATE_ADD(v_current_expiration, INTERVAL v_days_to_add DAY);
                        END IF;
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

-- =====================================================
-- Verificación
-- =====================================================

SELECT ROUTINE_NAME, ROUTINE_TYPE, CREATED, LAST_ALTERED 
FROM information_schema.ROUTINES 
WHERE ROUTINE_SCHEMA = 'dbforcegym' 
  AND ROUTINE_NAME = 'prInsertEconomicIncome';

SELECT '✅ Stored Procedure prInsertEconomicIncome actualizado correctamente' AS Mensaje;

-- =====================================================
-- Ejemplos de cómo funcionará:
-- =====================================================
-- Caso 1: Cliente paga el 30 de enero
--   Antes: 30 enero + 30 días = 1 marzo (se pierde el día 30)
--   Ahora: 30 enero + 1 mes = 28/29 febrero → próximo pago 30 marzo
--
-- Caso 2: Cliente paga el 15 de marzo  
--   Antes: 15 marzo + 30 días = 14 abril (se pierde el día 15)
--   Ahora: 15 marzo + 1 mes = 15 abril (mantiene el día 15)
--
-- Caso 3: Cliente paga 3 meses (90 días)
--   Antes: fecha + 90 días (desface acumulado)
--   Ahora: fecha + 3 meses (mantiene el día fijo)
--
-- Caso 4: Pago por día (no membresía, ej: 1 día)
--   Comportamiento: Sigue usando días (no cambia)
-- =====================================================
