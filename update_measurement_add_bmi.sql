-- =============================================
-- Script para agregar campo BMI a las medidas
-- =============================================

-- Desactivar safe update mode temporalmente
SET SQL_SAFE_UPDATES = 0;

-- 1. Agregar columna BMI a la tabla tbMeasurement
-- Verificar si la columna ya existe antes de agregarla
SET @dbname = DATABASE();
SET @tablename = 'tbMeasurement';
SET @columnname = 'bmi';
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      (table_name = @tablename)
      AND (table_schema = @dbname)
      AND (column_name = @columnname)
  ) > 0,
  'SELECT 1',
  'ALTER TABLE tbMeasurement ADD COLUMN bmi FLOAT NULL AFTER height'
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 2. Actualizar procedimiento almacenado prInsertMeasurement
DROP PROCEDURE IF EXISTS prInsertMeasurement;

DELIMITER $$

CREATE PROCEDURE prInsertMeasurement(
    IN pIdClient BIGINT,
    IN pMeasurementDate DATE,
    IN pWeight FLOAT,
    IN pHeight FLOAT,
    IN pBmi FLOAT,
    IN pMuscleMass FLOAT,
    IN pBodyFatPercentage FLOAT,
    IN pVisceralFatPercentage FLOAT,
    IN pChestSize FLOAT,
    IN pBackSize FLOAT,
    IN pHipSize FLOAT,
    IN pWaistSize FLOAT,
    IN pLeftLegSize FLOAT,
    IN pRightLegSize FLOAT,
    IN pLeftCalfSize FLOAT,
    IN pRightCalfSize FLOAT,
    IN pLeftForeArmSize FLOAT,
    IN pRightForeArmSize FLOAT,
    IN pLeftArmSize FLOAT,
    IN pRightArmSize FLOAT,
    IN pParamLoggedIdUser BIGINT,
    OUT result INT
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        SET result = 0;
        ROLLBACK;
    END;

    START TRANSACTION;

    -- Verificar que el cliente existe
    IF NOT EXISTS (SELECT 1 FROM tbClient WHERE idClient = pIdClient AND isDeleted = 0) THEN
        SET result = -1;
        ROLLBACK;
    ELSE
        -- Insertar la nueva medida
        INSERT INTO tbMeasurement (
            idClient,
            measurementDate,
            weight,
            height,
            bmi,
            muscleMass,
            bodyFatPercentage,
            visceralFatPercentage,
            chestSize,
            backSize,
            hipSize,
            waistSize,
            leftLegSize,
            rightLegSize,
            leftCalfSize,
            rightCalfSize,
            leftForeArmSize,
            rightForeArmSize,
            leftArmSize,
            rightArmSize,
            createdByUser,
            updatedByUser,
            isDeleted
        ) VALUES (
            pIdClient,
            pMeasurementDate,
            pWeight,
            pHeight,
            COALESCE(pBmi, 0),
            pMuscleMass,
            pBodyFatPercentage,
            pVisceralFatPercentage,
            pChestSize,
            pBackSize,
            pHipSize,
            pWaistSize,
            pLeftLegSize,
            pRightLegSize,
            pLeftCalfSize,
            pRightCalfSize,
            pLeftForeArmSize,
            pRightForeArmSize,
            pLeftArmSize,
            pRightArmSize,
            pParamLoggedIdUser,
            pParamLoggedIdUser,
            0
        );

        SET result = 1;
        COMMIT;
    END IF;
END$$

DELIMITER ;

-- 2. Actualizar procedimiento almacenado prGetMeasurement (para consultas)
DROP PROCEDURE IF EXISTS prGetMeasurement;

DELIMITER $$

CREATE PROCEDURE prGetMeasurement(
    IN p_idClient INT,
    IN p_page INT,
    IN p_limit INT,
    IN p_searchType INT,
    IN p_searchTerm VARCHAR(255),
    IN p_orderBy VARCHAR(255),
    IN p_directionOrderBy VARCHAR(10),
    IN p_filterByStatus VARCHAR(50),
    IN p_filterByDateRangeStart DATE,
    IN p_filterByDateRangeEnd DATE,
    OUT p_totalRecords INT
)
BEGIN
    DECLARE v_offset INT;
    
    SET v_offset = (p_page - 1) * p_limit;
    
    -- Contar total de registros
    SELECT COUNT(*) INTO p_totalRecords
    FROM tbMeasurement m
    WHERE m.idClient = p_idClient
    AND (
        -- Si filterByStatus está vacío, mostrar solo activos (isDeleted = 0)
        (p_filterByStatus = '' AND m.isDeleted = 0) OR
        -- Si filterByStatus es 'Inactivos', mostrar solo inactivos (isDeleted = 1)
        (p_filterByStatus = 'Inactivos' AND m.isDeleted = 1) OR
        -- Si filterByStatus es 'Todos', mostrar todos los registros
        (p_filterByStatus = 'Todos')
    )
    AND (p_filterByDateRangeStart IS NULL OR m.measurementDate >= p_filterByDateRangeStart)
    AND (p_filterByDateRangeEnd IS NULL OR m.measurementDate <= p_filterByDateRangeEnd)
    AND (
        p_searchTerm = '' OR
        (p_searchType = 1 AND CAST(m.weight AS CHAR) LIKE CONCAT('%', p_searchTerm COLLATE utf8mb4_0900_ai_ci, '%')) OR
        (p_searchType = 2 AND DATE_FORMAT(m.measurementDate, '%Y-%m-%d') LIKE CONCAT('%', p_searchTerm COLLATE utf8mb4_0900_ai_ci, '%'))
    );
    
    -- Seleccionar datos paginados con todas las columnas explícitas
    SET @sql = CONCAT(
        'SELECT m.idMeasurement, m.idClient, m.measurementDate, m.weight, m.height, m.bmi, ',
        'm.muscleMass, m.bodyFatPercentage, m.visceralFatPercentage, m.chestSize, m.backSize, ',
        'm.hipSize, m.waistSize, m.leftLegSize, m.rightLegSize, m.leftCalfSize, m.rightCalfSize, ',
        'm.leftForeArmSize, m.rightForeArmSize, m.leftArmSize, m.rightArmSize, m.isDeleted ',
        'FROM tbMeasurement m ',
        'WHERE m.idClient = ', p_idClient,
        CASE 
            WHEN p_filterByStatus = '' THEN ' AND m.isDeleted = 0'
            WHEN p_filterByStatus = 'Inactivos' THEN ' AND m.isDeleted = 1'
            WHEN p_filterByStatus = 'Todos' THEN ''
            ELSE ''
        END,
        CASE WHEN p_filterByDateRangeStart IS NOT NULL THEN CONCAT(' AND m.measurementDate >= ''', p_filterByDateRangeStart, '''') ELSE '' END,
        CASE WHEN p_filterByDateRangeEnd IS NOT NULL THEN CONCAT(' AND m.measurementDate <= ''', p_filterByDateRangeEnd, '''') ELSE '' END,
        CASE 
            WHEN p_searchTerm != '' THEN
                CASE 
                    WHEN p_searchType = 1 THEN CONCAT(' AND CAST(m.weight AS CHAR) LIKE ''%', REPLACE(p_searchTerm, '''', ''''''), '%''')
                    WHEN p_searchType = 2 THEN CONCAT(' AND DATE_FORMAT(m.measurementDate, ''%Y-%m-%d'') LIKE ''%', REPLACE(p_searchTerm, '''', ''''''), '%''')
                    ELSE ''
                END
            ELSE ''
        END,
        CASE 
            WHEN p_orderBy != '' THEN CONCAT(' ORDER BY ', p_orderBy, ' ', p_directionOrderBy)
            ELSE ' ORDER BY m.measurementDate DESC'
        END,
        ' LIMIT ', p_limit, ' OFFSET ', v_offset
    );
    
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END$$

DELIMITER ;

-- 4. Actualizar procedimiento almacenado prUpdateMeasurement
DROP PROCEDURE IF EXISTS prUpdateMeasurement;

DELIMITER $$

CREATE PROCEDURE prUpdateMeasurement(
    IN pIdMeasurement BIGINT,
    IN pIdClient BIGINT,
    IN pMeasurementDate DATE,
    IN pWeight FLOAT,
    IN pHeight FLOAT,
    IN pBmi FLOAT,
    IN pMuscleMass FLOAT,
    IN pBodyFatPercentage FLOAT,
    IN pVisceralFatPercentage FLOAT,
    IN pChestSize FLOAT,
    IN pBackSize FLOAT,
    IN pHipSize FLOAT,
    IN pWaistSize FLOAT,
    IN pLeftLegSize FLOAT,
    IN pRightLegSize FLOAT,
    IN pLeftCalfSize FLOAT,
    IN pRightCalfSize FLOAT,
    IN pLeftForeArmSize FLOAT,
    IN pRightForeArmSize FLOAT,
    IN pLeftArmSize FLOAT,
    IN pRightArmSize FLOAT,
    IN pIsDeleted BIGINT,
    IN pParamLoggedIdUser BIGINT,
    OUT result INT
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        SET result = 0;
        ROLLBACK;
    END;

    START TRANSACTION;

    -- Verificar que la medida existe
    IF NOT EXISTS (SELECT 1 FROM tbMeasurement WHERE idMeasurement = pIdMeasurement) THEN
        SET result = -1;
        ROLLBACK;
    -- Verificar que el cliente existe
    ELSEIF NOT EXISTS (SELECT 1 FROM tbClient WHERE idClient = pIdClient AND isDeleted = 0) THEN
        SET result = -2;
        ROLLBACK;
    ELSE
        -- Actualizar la medida
        UPDATE tbMeasurement
        SET
            idClient = pIdClient,
            measurementDate = pMeasurementDate,
            weight = pWeight,
            height = pHeight,
            bmi = COALESCE(pBmi, 0),
            muscleMass = pMuscleMass,
            bodyFatPercentage = pBodyFatPercentage,
            visceralFatPercentage = pVisceralFatPercentage,
            chestSize = pChestSize,
            backSize = pBackSize,
            hipSize = pHipSize,
            waistSize = pWaistSize,
            leftLegSize = pLeftLegSize,
            rightLegSize = pRightLegSize,
            leftCalfSize = pLeftCalfSize,
            rightCalfSize = pRightCalfSize,
            leftForeArmSize = pLeftForeArmSize,
            rightForeArmSize = pRightForeArmSize,
            leftArmSize = pLeftArmSize,
            rightArmSize = pRightArmSize,
            updatedByUser = pParamLoggedIdUser,
            isDeleted = pIsDeleted
        WHERE idMeasurement = pIdMeasurement;

        SET result = 1;
        COMMIT;
    END IF;
END$$

DELIMITER ;

-- Verificar cambios
SELECT 'Script ejecutado correctamente. Columna BMI agregada y procedimientos actualizados.' AS Resultado;

-- 5. Calcular BMI para registros existentes que no lo tienen
-- Este UPDATE calcula el BMI automáticamente para medidas antiguas
UPDATE tbMeasurement
SET bmi = ROUND(weight / POWER(height / 100, 2), 2)
WHERE bmi IS NULL AND weight IS NOT NULL AND height IS NOT NULL AND height > 0;

SELECT CONCAT('Se actualizaron ', ROW_COUNT(), ' registros con BMI calculado automáticamente.') AS Info;

-- Reactivar safe update mode
SET SQL_SAFE_UPDATES = 1;

