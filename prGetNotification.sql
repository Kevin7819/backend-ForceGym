DELIMITER $$

DROP PROCEDURE IF EXISTS `prGetNotification`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `prGetNotification`(
    IN `p_page` INT,
    IN `p_limit` INT,
    IN `p_searchType` INT,
    IN `p_searchTerm` VARCHAR(255),
    IN `p_orderBy` VARCHAR(63),
    IN `p_directionOrderBy` VARCHAR(15),
    IN `p_filterByStatus` VARCHAR(31),
    OUT `p_totalRecords` INT
)
BEGIN
    -- Variables
    DECLARE auxFilters TEXT;
    DECLARE sqlQuery TEXT;
    DECLARE totalQuery TEXT;
    DECLARE p_offset INT;

    -- Manejador de errores
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        GET DIAGNOSTICS CONDITION 1 
            @sqlstate = RETURNED_SQLSTATE, 
            @errno = MYSQL_ERRNO, 
            @text = MESSAGE_TEXT;
            
        INSERT INTO tbError (
            executionDate, 
            codeCaused, 
            message,
            description, 
            nameProcedure
        ) VALUES (
            NOW(), 
            @errno, 
            @text, 
            CONCAT('ERROR ', @errno, ' (', @sqlstate, '): ', @text),
            'prGetNotification'
        );
        
        RESIGNAL;
    END;

    -- Validación de parámetros
    IF p_page IS NULL OR p_page < 1 THEN SET p_page = 1; END IF;
    IF p_limit IS NULL OR p_limit < 1 THEN SET p_limit = 10; END IF;
    IF p_directionOrderBy NOT IN ('ASC', 'DESC') THEN SET p_directionOrderBy = 'ASC'; END IF;

    -- Cálculo del OFFSET
    SET p_offset = (p_page - 1) * p_limit; 

    -- Iniciar transacción
    START TRANSACTION;
    
    -- Construcción de filtros base
    -- IMPORTANTE: Filtrar clientes eliminados (inactivos)
    IF p_filterByStatus = '' OR p_filterByStatus IS NULL THEN
        SET auxFilters = 'n.isDeleted = FALSE AND c.isDeleted = FALSE';
    ELSEIF p_filterByStatus = 'Inactivos' THEN
        SET auxFilters = 'n.isDeleted = TRUE AND c.isDeleted = FALSE';
    ELSEIF p_filterByStatus = 'Todos' THEN
        SET auxFilters = 'c.isDeleted = FALSE';  -- Siempre excluir clientes inactivos
    ELSE
        SET auxFilters = 'n.isDeleted = FALSE AND c.isDeleted = FALSE'; -- Default
    END IF;

    -- Filtro por búsqueda
    IF p_searchTerm IS NOT NULL AND p_searchTerm != '' THEN
        IF p_searchType = 1 THEN -- Búsqueda por ID de notificación
            IF p_searchTerm REGEXP '^[0-9]+$' THEN
                SET auxFilters = CONCAT(auxFilters, ' AND n.idNotification = ', p_searchTerm);
            END IF;
        ELSEIF p_searchType = 2 THEN -- Búsqueda por nombre de cliente
            SET auxFilters = CONCAT(auxFilters, ' AND (p.name LIKE ''%', p_searchTerm, '%'' OR p.firstLastName LIKE ''%', p_searchTerm, '%'' OR p.secondLastName LIKE ''%', p_searchTerm, '%'')');
        END IF;
    END IF;
    
    -- Construcción de consulta principal con JOIN
    SET @sqlQuery = CONCAT(
        'SELECT n.idNotification, n.idClient, n.idNotificationType, n.sendDate, n.isDeleted ',
        'FROM tbNotification n ',
        'INNER JOIN tbClient c ON n.idClient = c.idClient ',
        'INNER JOIN tbPerson p ON c.idPerson = p.idPerson ',
        'WHERE ', auxFilters
    );

    -- Ordenamiento
    IF p_orderBy IS NOT NULL AND p_orderBy != '' THEN
        -- Validar que el campo de ordenamiento es seguro
        IF p_orderBy IN ('idNotification', 'sendDate', 'idClient', 'idNotificationType') THEN
            SET @sqlQuery = CONCAT(@sqlQuery, ' ORDER BY n.', p_orderBy, ' ', p_directionOrderBy);
        END IF;
    ELSE
        -- Ordenamiento por defecto: más recientes primero
        SET @sqlQuery = CONCAT(@sqlQuery, ' ORDER BY n.sendDate DESC');
    END IF;

    -- Paginación
    SET @sqlQuery = CONCAT(@sqlQuery, ' LIMIT ', p_offset, ', ', p_limit);

    -- Consulta para total de registros
    SET @totalQuery = CONCAT(
        'SELECT COUNT(*) INTO @total FROM tbNotification n ',
        'INNER JOIN tbClient c ON n.idClient = c.idClient ',
        'INNER JOIN tbPerson p ON c.idPerson = p.idPerson ',
        'WHERE ', auxFilters
    );
    
    PREPARE countStmt FROM @totalQuery;
    EXECUTE countStmt;
    DEALLOCATE PREPARE countStmt;
    SET p_totalRecords = @total;

    -- Ejecutar consulta principal
    PREPARE stmt FROM @sqlQuery;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    COMMIT;
END$$

DELIMITER ;
