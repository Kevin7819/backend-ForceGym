-- =====================================================
-- Stored Procedure CORREGIDO: prDeleteEconomicIncome
-- PROBLEMA: Causaba expulsión al login al intentar eliminar
-- SOLUCIÓN: Remover RESIGNAL, agregar LEAVE, usar estructura correcta
-- =====================================================

USE dbforcegym;

DROP PROCEDURE IF EXISTS `prDeleteEconomicIncome`;

DELIMITER $$

CREATE DEFINER=`root`@`%` PROCEDURE `prDeleteEconomicIncome`(
    IN `pIdEconomicIncome` INT, 
    IN `pLoggedIdUser` INT, 
    OUT `result` INT
)
prDeleteEconomicIncome: BEGIN
    DECLARE idCount INT;
    DECLARE clientId INT;
    DECLARE activityTypeId INT;
    DECLARE shouldUpdateMembership INT;
    DECLARE newExpirationDate DATE;
    
    -- ✅ CAMBIO: Remover RESIGNAL para evitar que propague excepciones
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        
        GET DIAGNOSTICS CONDITION 1 
            @sqlstate = RETURNED_SQLSTATE, 
            @mysql_errno = MYSQL_ERRNO, 
            @message_text = MESSAGE_TEXT;
        
        INSERT INTO tbError (
            executionDate, 
            codeCaused, 
            message,
            description, 
            nameProcedure
        ) VALUES (
            NOW(), 
            @mysql_errno, 
            @message_text, 
            CONCAT("ERROR ", @mysql_errno, " (", @sqlstate, "): ", @message_text),
            'prDeleteEconomicIncome'
        );
        
        SET result = 0;
    END;
    
    START TRANSACTION;
    
    -- ✅ CAMBIO: Separar las consultas para evitar error SQL
    -- Primero verificar si existe el registro
    SELECT COUNT(*) INTO idCount
    FROM tbEconomicIncome 
    WHERE idEconomicIncome = pIdEconomicIncome;
    
    -- ✅ CAMBIO: Agregar LEAVE para salir correctamente del procedimiento
    IF idCount = 0 THEN
        INSERT INTO tbError (
            executionDate, 
            codeCaused, 
            message,
            description, 
            nameProcedure
        ) VALUES (
            NOW(), 
            NULL, 
            'ID no encontrado', 
            CONCAT('No se encontró el ID: ', pIdEconomicIncome, ' proporcionado para eliminar en la tabla EconomicIncome'),
            'prDeleteEconomicIncome'
        );
        
        ROLLBACK;  -- ✅ CAMBIO: Hacer rollback explícito antes de salir
        SET result = -1;
        LEAVE prDeleteEconomicIncome;  -- ✅ CAMBIO: Salir del procedimiento
    END IF;
    
    -- Si existe, obtener los valores de cliente y tipo de actividad
    SELECT COALESCE(idClient, 0), COALESCE(idActivityType, 0)
    INTO clientId, activityTypeId
    FROM tbEconomicIncome 
    WHERE idEconomicIncome = pIdEconomicIncome;
    
    -- Marcar como eliminado
    UPDATE tbEconomicIncome 
    SET isDeleted = TRUE, updatedByUser = pLoggedIdUser 
    WHERE idEconomicIncome = pIdEconomicIncome;
    
    -- Verificar si la actividad requiere actualizar la fecha de membresía
    IF clientId IS NOT NULL AND clientId > 0 THEN
        SELECT COALESCE(shouldUpdateMembership, 0) INTO shouldUpdateMembership 
        FROM tbActivityType 
        WHERE idActivityType = activityTypeId;
        
        IF shouldUpdateMembership = 1 THEN
            SET newExpirationDate = DATE_SUB(NOW(), INTERVAL 1 YEAR);
            
            UPDATE tbClient 
            SET expirationMembershipDate = newExpirationDate
            WHERE idClient = clientId;
        END IF;
    END IF;
    
    COMMIT;
    SET result = 1;

END$$

DELIMITER ;

-- =====================================================
-- Verificación
-- =====================================================

SELECT ROUTINE_NAME, ROUTINE_TYPE, CREATED, LAST_ALTERED 
FROM information_schema.ROUTINES 
WHERE ROUTINE_SCHEMA = 'dbforcegym' 
  AND ROUTINE_NAME = 'prDeleteEconomicIncome';

SELECT '✅ Stored Procedure prDeleteEconomicIncome ha sido corregido' AS Mensaje;
