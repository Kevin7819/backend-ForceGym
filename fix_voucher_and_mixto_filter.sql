-- Script para hacer el voucher opcional en ingresos y arreglar el filtro de "Mixto"
-- Fecha: 2026-04-15

USE dbforcegym;

-- 1. Hacer que voucherNumber sea opcional en tbEconomicIncome
ALTER TABLE tbEconomicIncome 
MODIFY COLUMN voucherNumber varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL;

-- 2. Arreglar el stored procedure de filtro de ingresos para incluir "Mixto" (idMeanOfPayment = 3)
DROP PROCEDURE IF EXISTS prGetEconomicIncome;

DELIMITER $$

CREATE DEFINER=`root`@`%` PROCEDURE `prGetEconomicIncome`(
    IN `p_page` INT, 
    IN `p_limit` INT, 
    IN `p_searchType` INT, 
    IN `p_searchTerm` VARCHAR(255), 
    IN `p_orderBy` VARCHAR(63), 
    IN `p_directionOrderBy` VARCHAR(15), 
    IN `p_filterByStatus` VARCHAR(31), 
    IN `p_filterByAmountRangeMin` DECIMAL(10,2), 
    IN `p_filterByAmountRangeMax` DECIMAL(10,2), 
    IN `p_filterByDateRangeStart` DATE, 
    IN `p_filterByDateRangeEnd` DATE, 
    IN `p_filterByMeanOfPayment` INT, 
    IN `p_filterByClientType` INT, 
    OUT `p_totalRecords` INT
)
BEGIN
    DECLARE auxFilters TEXT DEFAULT '';
    DECLARE sqlQuery TEXT;
    DECLARE totalQuery TEXT;
    DECLARE p_offset INT;
    
    DECLARE sqlstate_code CHAR(5);
    DECLARE mysql_errno INT;
    DECLARE message_text TEXT;
    
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
        
        GET DIAGNOSTICS CONDITION 1 
            sqlstate_code = RETURNED_SQLSTATE, 
            mysql_errno = MYSQL_ERRNO, 
            message_text = MESSAGE_TEXT;
        
        INSERT INTO tbError (
            executionDate, codeCaused, message, description, nameProcedure
        ) VALUES (
            NOW(), mysql_errno, message_text, 
            CONCAT('ERROR ', mysql_errno, ' (', sqlstate_code, '): ', message_text),
            'prGetEconomicIncome'
        );
    END;
    
    SET p_offset = (p_page - 1) * p_limit; 
    
    IF p_filterByStatus = '' OR p_filterByStatus = 'Activos' THEN
        SET auxFilters = ' e.isDeleted = FALSE ';
    ELSEIF p_filterByStatus = 'Inactivos' THEN
        SET auxFilters = ' e.isDeleted = TRUE ';
    ELSEIF p_filterByStatus = 'Todos' THEN
        SET auxFilters = ' 1=1 ';
    END IF;
    
    IF p_filterByAmountRangeMin IS NOT NULL AND p_filterByAmountRangeMax IS NOT NULL THEN
        SET auxFilters = CONCAT(auxFilters, ' AND e.amount BETWEEN ', p_filterByAmountRangeMin, ' AND ', p_filterByAmountRangeMax);
    END IF;
    
    IF p_filterByDateRangeStart IS NOT NULL AND p_filterByDateRangeEnd IS NOT NULL THEN
        SET auxFilters = CONCAT(auxFilters, ' AND e.registrationDate BETWEEN "', p_filterByDateRangeStart, '" AND "', p_filterByDateRangeEnd, '"');
    END IF;
    
    -- CAMBIO IMPORTANTE: Ahora acepta 1, 2 y 3 (Sinpe, Efectivo y Mixto)
    IF p_filterByMeanOfPayment IN (1, 2, 3) THEN
        SET auxFilters = CONCAT(auxFilters, ' AND e.idMeanOfPayment = ', p_filterByMeanOfPayment);
    END IF;
    
    IF p_filterByClientType IS NOT NULL AND p_filterByClientType != -1 THEN
        SET auxFilters = CONCAT(auxFilters, ' AND tc.idClientType = ', p_filterByClientType);
    END IF;
    
    IF p_searchTerm IS NOT NULL AND p_searchTerm != '' THEN
        IF p_searchType = 1 THEN 
            SET auxFilters = CONCAT(auxFilters, ' AND e.voucherNumber LIKE "%', p_searchTerm, '%"');
        ELSEIF p_searchType = 2 THEN 
            SET auxFilters = CONCAT(auxFilters, ' AND e.detail LIKE "%', p_searchTerm, '%"');
        ELSEIF p_searchType = 3 THEN
            SET auxFilters = CONCAT(auxFilters, 
                ' AND (p.name LIKE "%', p_searchTerm, '%"',
                ' OR p.firstLastName LIKE "%', p_searchTerm, '%"',
                ' OR p.secondLastName LIKE "%', p_searchTerm, '%"',
                ' OR p.identificationNumber LIKE "%', p_searchTerm, '%"',
                ' OR p.phoneNumber LIKE "%', p_searchTerm, '%")'
            );
       	END IF;
    END IF;
    
    SET sqlQuery = CONCAT(
        'SELECT e.idEconomicIncome, e.idClient, e.registrationDate, e.voucherNumber, ',
        'e.detail, e.idMeanOfPayment, e.amount, e.idActivityType, e.delayDays, e.isDeleted ',
        'FROM tbEconomicIncome e ',
        'INNER JOIN tbClient c ON e.idClient = c.idClient ',
        'INNER JOIN tbClientType tc ON c.idClientType = tc.idClientType ',
        'INNER JOIN tbPerson p ON c.idPerson = p.idPerson ',
        'WHERE ', auxFilters
    );
    
    IF p_orderBy IS NOT NULL AND p_orderBy != '' THEN
        IF p_directionOrderBy NOT IN ('ASC', 'DESC') THEN
            SET p_directionOrderBy = 'ASC';
        END IF;
        SET sqlQuery = CONCAT(sqlQuery, ' ORDER BY e.', p_orderBy, ' ', p_directionOrderBy);
    END IF;
    

    SET @sqlQuery = CONCAT(sqlQuery, ' LIMIT ', p_offset, ', ', p_limit);
    
    SET @totalQuery = CONCAT('SELECT COUNT(*) INTO @total FROM tbEconomicIncome e ',
        'INNER JOIN tbClient c ON e.idClient = c.idClient ',
        'INNER JOIN tbClientType tc ON c.idClientType = tc.idClientType ',     
        'INNER JOIN tbPerson p ON c.idPerson = p.idPerson ',
    	'WHERE ', auxFilters);
    
    PREPARE countStmt FROM @totalQuery;
    EXECUTE countStmt;
    DEALLOCATE PREPARE countStmt;
    
    SET p_totalRecords = @total;
    
    PREPARE stmt FROM @sqlQuery;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
END$$

DELIMITER ;

-- 3. Arreglar también el stored procedure de filtro de gastos para incluir "Mixto"
DROP PROCEDURE IF EXISTS prGetEconomicExpense;

DELIMITER $$

CREATE PROCEDURE `prGetEconomicExpense`(
    IN `p_page` INT, 
    IN `p_limit` INT, 
    IN `p_searchType` INT, 
    IN `p_searchTerm` VARCHAR(255), 
    IN `p_orderBy` VARCHAR(63), 
    IN `p_directionOrderBy` VARCHAR(15), 
    IN `p_filterByStatus` VARCHAR(31), 
    IN `p_filterByAmountRangeMin` DECIMAL(10,2), 
    IN `p_filterByAmountRangeMax` DECIMAL(10,2), 
    IN `p_filterByDateRangeStart` DATE, 
    IN `p_filterByDateRangeEnd` DATE, 
    IN `p_filterByMeanOfPayment` INT, 
    IN `p_filterByCategory` INT, 
    OUT `p_totalRecords` INT
)
BEGIN
    DECLARE auxFilters TEXT DEFAULT '';
    DECLARE sqlQuery TEXT;
    DECLARE totalQuery TEXT;
    DECLARE p_offset INT;
    
    SET p_offset = (p_page - 1) * p_limit; 
    
    IF p_filterByStatus = '' OR p_filterByStatus = 'Activos' THEN
        SET auxFilters = ' e.isDeleted = FALSE ';
    ELSEIF p_filterByStatus = 'Inactivos' THEN
        SET auxFilters = ' e.isDeleted = TRUE ';
    ELSEIF p_filterByStatus = 'Todos' THEN
        SET auxFilters = ' 1=1 ';
    END IF;
    
    IF p_filterByAmountRangeMin IS NOT NULL AND p_filterByAmountRangeMax IS NOT NULL THEN
        SET auxFilters = CONCAT(auxFilters, ' AND e.amount BETWEEN ', p_filterByAmountRangeMin, ' AND ', p_filterByAmountRangeMax);
    END IF;
    
    IF p_filterByDateRangeStart IS NOT NULL AND p_filterByDateRangeEnd IS NOT NULL THEN
        SET auxFilters = CONCAT(auxFilters, ' AND e.registrationDate BETWEEN "', p_filterByDateRangeStart, '" AND "', p_filterByDateRangeEnd, '"');
    END IF;
    
    -- CAMBIO IMPORTANTE: Ahora acepta 1, 2 y 3 (Sinpe, Efectivo y Mixto)
    IF p_filterByMeanOfPayment IN (1, 2, 3) THEN
        SET auxFilters = CONCAT(auxFilters, ' AND e.idMeanOfPayment = ', p_filterByMeanOfPayment);
    END IF;
    
    IF p_filterByCategory IS NOT NULL AND p_filterByCategory != -1 THEN
        SET auxFilters = CONCAT(auxFilters, ' AND e.idCategory = ', p_filterByCategory);
    END IF;
    
    IF p_searchTerm IS NOT NULL AND p_searchTerm != '' THEN
        IF p_searchType = 1 THEN 
            SET auxFilters = CONCAT(auxFilters, ' AND e.voucherNumber LIKE "%', p_searchTerm, '%"');
        ELSEIF p_searchType = 2 THEN 
            SET auxFilters = CONCAT(auxFilters, ' AND e.detail LIKE "%', p_searchTerm, '%"');
        ELSEIF p_searchType = 3 THEN
            SET auxFilters = CONCAT(auxFilters, 
                ' AND (u.username LIKE "%', p_searchTerm, '%"',
                ' OR p.name LIKE "%', p_searchTerm, '%"',
                ' OR p.firstLastName LIKE "%', p_searchTerm, '%"',
                ' OR p.secondLastName LIKE "%', p_searchTerm, '%")'
            );
       	END IF;
    END IF;
    
    SET sqlQuery = CONCAT(
        'SELECT e.idEconomicExpense, e.idUser, e.idCategory, e.registrationDate, ',
        'e.voucherNumber, e.detail, e.idMeanOfPayment, e.amount, e.isDeleted ',
        'FROM tbEconomicExpense e ',
        'INNER JOIN tbUser u ON e.idUser = u.idUser ',
        'INNER JOIN tbPerson p ON u.idPerson = p.idPerson ',
        'WHERE ', auxFilters
    );
    
    IF p_orderBy IS NOT NULL AND p_orderBy != '' THEN
        IF p_directionOrderBy NOT IN ('ASC', 'DESC') THEN
            SET p_directionOrderBy = 'ASC';
        END IF;
        SET sqlQuery = CONCAT(sqlQuery, ' ORDER BY e.', p_orderBy, ' ', p_directionOrderBy);
    END IF;
    
    SET @sqlQuery = CONCAT(sqlQuery, ' LIMIT ', p_offset, ', ', p_limit);
    
    SET @totalQuery = CONCAT('SELECT COUNT(*) INTO @total FROM tbEconomicExpense e ',
        'INNER JOIN tbUser u ON e.idUser = u.idUser ',
        'INNER JOIN tbPerson p ON u.idPerson = p.idPerson ',
    	'WHERE ', auxFilters);
    
    PREPARE countStmt FROM @totalQuery;
    EXECUTE countStmt;
    DEALLOCATE PREPARE countStmt;
    
    SET p_totalRecords = @total;
    
    PREPARE stmt FROM @sqlQuery;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
END$$

DELIMITER ;

SELECT 'Script ejecutado exitosamente. Cambios aplicados:' AS Resumen;
SELECT '1. voucherNumber en tbEconomicIncome ahora es opcional (NULL)' AS Cambio_1;
SELECT '2. Filtro de "Mixto" (id=3) habilitado en ingresos y gastos' AS Cambio_2;
