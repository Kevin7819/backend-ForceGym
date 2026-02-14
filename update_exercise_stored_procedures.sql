-- Actualizar stored procedures para incluir el campo videoUrl

-- =====================================================
-- 1. DROP PROCEDURES EXISTENTES
-- =====================================================
DROP PROCEDURE IF EXISTS prGetExercise;
DROP PROCEDURE IF EXISTS prGetAllExercise;
DROP PROCEDURE IF EXISTS prInsertExercise;
DROP PROCEDURE IF EXISTS prUpdateExercise;

-- =====================================================
-- 2. RECREAR prGetExercise con videoUrl
-- =====================================================
DELIMITER $$
CREATE PROCEDURE prGetExercise(
    IN p_page INT,
    IN p_limit INT,
    IN p_searchType INT,
    IN p_searchTerm VARCHAR(100),
    IN p_orderBy VARCHAR(50),
    IN p_directionOrderBy VARCHAR(4),
    IN p_filterByStatus VARCHAR(20),
    IN p_filterByDifficulty VARCHAR(50),
    IN p_filterByCategory INT,
    OUT p_totalRecords INT
)
BEGIN
    DECLARE v_offset INT;
    SET v_offset = (p_page - 1) * p_limit;

    -- Contar total de registros
    SELECT COUNT(*) INTO p_totalRecords
    FROM tbExercise e
    INNER JOIN tbUser u ON e.idUser = u.idUser
    INNER JOIN tbExerciseCategory ec ON e.idExerciseCategory = ec.idExerciseCategory
    INNER JOIN tbExerciseDifficulty ed ON e.idExerciseDifficulty = ed.idExerciseDifficulty
    WHERE (p_searchType = 1 OR 
           (p_searchType = 2 AND e.name LIKE CONCAT('%', p_searchTerm, '%')) OR
           (p_searchType = 3 AND e.description LIKE CONCAT('%', p_searchTerm, '%')))
    AND (p_filterByStatus = 'all' OR 
         (p_filterByStatus = 'active' AND e.isDeleted = 0) OR
         (p_filterByStatus = 'deleted' AND e.isDeleted = 1))
    AND (p_filterByDifficulty = 'all' OR ed.difficulty = p_filterByDifficulty)
    AND (p_filterByCategory IS NULL OR e.idExerciseCategory = p_filterByCategory);

    -- Seleccionar registros con videoUrl
    SELECT 
        e.idExercise,
        e.idUser,
        e.idExerciseCategory,
        e.idExerciseDifficulty,
        e.name,
        e.description,
        e.videoUrl,
        e.isDeleted
    FROM tbExercise e
    INNER JOIN tbUser u ON e.idUser = u.idUser
    INNER JOIN tbExerciseCategory ec ON e.idExerciseCategory = ec.idExerciseCategory
    INNER JOIN tbExerciseDifficulty ed ON e.idExerciseDifficulty = ed.idExerciseDifficulty
    WHERE (p_searchType = 1 OR 
           (p_searchType = 2 AND e.name LIKE CONCAT('%', p_searchTerm, '%')) OR
           (p_searchType = 3 AND e.description LIKE CONCAT('%', p_searchTerm, '%')))
    AND (p_filterByStatus = 'all' OR 
         (p_filterByStatus = 'active' AND e.isDeleted = 0) OR
         (p_filterByStatus = 'deleted' AND e.isDeleted = 1))
    AND (p_filterByDifficulty = 'all' OR ed.difficulty = p_filterByDifficulty)
    AND (p_filterByCategory IS NULL OR e.idExerciseCategory = p_filterByCategory)
    ORDER BY
        CASE WHEN p_orderBy = 'name' AND p_directionOrderBy = 'ASC' THEN e.name END ASC,
        CASE WHEN p_orderBy = 'name' AND p_directionOrderBy = 'DESC' THEN e.name END DESC,
        CASE WHEN p_orderBy = 'difficulty' AND p_directionOrderBy = 'ASC' THEN ed.difficulty END ASC,
        CASE WHEN p_orderBy = 'difficulty' AND p_directionOrderBy = 'DESC' THEN ed.difficulty END DESC,
        CASE WHEN p_orderBy = 'category' AND p_directionOrderBy = 'ASC' THEN ec.name END ASC,
        CASE WHEN p_orderBy = 'category' AND p_directionOrderBy = 'DESC' THEN ec.name END DESC,
        e.idExercise DESC
    LIMIT p_limit OFFSET v_offset;
END$$
DELIMITER ;

-- =====================================================
-- 3. RECREAR prGetAllExercise con videoUrl
-- =====================================================
DELIMITER $$
CREATE PROCEDURE prGetAllExercise()
BEGIN
    SELECT 
        e.idExercise,
        e.idUser,
        e.idExerciseCategory,
        e.idExerciseDifficulty,
        e.name,
        e.description,
        e.videoUrl,
        e.isDeleted
    FROM tbExercise e
    WHERE e.isDeleted = 0
    ORDER BY e.name ASC;
END$$
DELIMITER ;

-- =====================================================
-- 4. RECREAR prInsertExercise con videoUrl
-- =====================================================
DELIMITER $$
CREATE PROCEDURE prInsertExercise(
    IN pName VARCHAR(100),
    IN pDescription VARCHAR(255),
    IN pVideoUrl VARCHAR(500),
    IN pIdExerciseDifficulty BIGINT,
    IN pIdExerciseCategory BIGINT,
    IN pLoggedIdUser BIGINT,
    OUT result INT
)
BEGIN
    DECLARE nameExists INT;
    DECLARE newId BIGINT;
    
    -- Verificar si el nombre ya existe
    SELECT COUNT(*) INTO nameExists 
    FROM tbExercise 
    WHERE name = pName AND isDeleted = 0;
    
    IF nameExists > 0 THEN
        SET result = -2; -- Nombre duplicado
    ELSE
        -- Obtener nuevo ID
        SELECT COALESCE(MAX(idExercise), 0) + 1 INTO newId FROM tbExercise;
        
        -- Insertar ejercicio
        INSERT INTO tbExercise (
            idExercise, 
            name, 
            description, 
            videoUrl,
            idExerciseDifficulty, 
            idExerciseCategory, 
            idUser, 
            isDeleted
        )
        VALUES (
            newId, 
            pName, 
            pDescription, 
            pVideoUrl,
            pIdExerciseDifficulty, 
            pIdExerciseCategory, 
            pLoggedIdUser, 
            0
        );
        
        SET result = 1; -- Éxito
    END IF;
END$$
DELIMITER ;

-- =====================================================
-- 5. RECREAR prUpdateExercise con videoUrl
-- =====================================================
DELIMITER $$
CREATE PROCEDURE prUpdateExercise(
    IN pIdExercise INT,
    IN pName VARCHAR(100),
    IN pDescription VARCHAR(255),
    IN pVideoUrl VARCHAR(500),
    IN pIdExerciseDifficulty BIGINT,
    IN pIdExerciseCategory BIGINT,
    IN pIsDeleted BIGINT,
    IN pLoggedIdUser BIGINT,
    OUT result INT
)
BEGIN
    DECLARE exerciseExists INT;
    DECLARE nameExists INT;
    
    -- Verificar si el ejercicio existe
    SELECT COUNT(*) INTO exerciseExists 
    FROM tbExercise 
    WHERE idExercise = pIdExercise;
    
    IF exerciseExists = 0 THEN
        SET result = -1; -- No existe
    ELSE
        -- Verificar si el nombre ya existe en otro ejercicio
        SELECT COUNT(*) INTO nameExists 
        FROM tbExercise 
        WHERE name = pName 
        AND idExercise != pIdExercise 
        AND isDeleted = 0;
        
        IF nameExists > 0 THEN
            SET result = -2; -- Nombre duplicado
        ELSE
            -- Actualizar ejercicio
            UPDATE tbExercise 
            SET 
                name = pName,
                description = pDescription,
                videoUrl = pVideoUrl,
                idExerciseDifficulty = pIdExerciseDifficulty,
                idExerciseCategory = pIdExerciseCategory,
                isDeleted = pIsDeleted,
                idUser = pLoggedIdUser
            WHERE idExercise = pIdExercise;
            
            SET result = 1; -- Éxito
        END IF;
    END IF;
END$$
DELIMITER ;
