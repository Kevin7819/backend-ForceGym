-- Script de actualización de stored procedures para incluir columna password
-- Ejecutar este script en la base de datos dbforcegym

USE dbforcegym;

-- ============================================
-- 1. Actualizar prGetAllClient
-- ============================================
DROP PROCEDURE IF EXISTS prGetAllClient;

DELIMITER $$

CREATE PROCEDURE prGetAllClient()
BEGIN
    SELECT 
        c.idClient,
        c.idPerson,
        c.idClientType,
        c.idHealthQuestionnaire,
        c.idUser,
        c.registrationDate,
        c.expirationMembershipDate,
        c.phoneNumberContactEmergency,
        c.nameEmergencyContact,
        c.signatureImage,
        c.isDeleted,
        c.password  -- Nueva columna agregada
    FROM tbClient c
    WHERE c.isDeleted = 0
    ORDER BY c.idClient DESC;
END$$

DELIMITER ;

-- ============================================
-- 2. Actualizar prGetClient (con paginación y filtros)
-- ============================================
DROP PROCEDURE IF EXISTS prGetClient;

DELIMITER $$

CREATE PROCEDURE prGetClient(
    IN p_page INT,
    IN p_limit INT,
    IN p_searchType INT,
    IN p_searchTerm VARCHAR(50),
    IN p_orderBy VARCHAR(50),
    IN p_directionOrderBy VARCHAR(4),
    IN p_filterByStatus VARCHAR(10),
    IN p_filterByDiabetes BOOLEAN,
    IN p_filterByHypertension BOOLEAN,
    IN p_filterByMuscleInjuries BOOLEAN,
    IN p_filterByBoneJointIssues BOOLEAN,
    IN p_filterByBalanceLoss BOOLEAN,
    IN p_filterByCardiovascularDisease BOOLEAN,
    IN p_filterByBreathingIssues BOOLEAN,
    IN p_filterByDateBirthStart DATE,
    IN p_filterByDateBirthEnd DATE,
    IN p_filterByClientType INT,
    OUT p_totalRecords INT
)
BEGIN
    DECLARE v_offset INT;
    DECLARE v_sql TEXT;
    
    SET v_offset = (p_page - 1) * p_limit;

    -- Contar el total de registros
    SELECT COUNT(*) INTO p_totalRecords
    FROM tbClient c
    INNER JOIN tbPerson p ON c.idPerson = p.idPerson
    LEFT JOIN tbHealthQuestionnaire hq ON c.idHealthQuestionnaire = hq.idHealthQuestionnaire
    WHERE (
        CASE p_filterByStatus
            WHEN '' THEN c.isDeleted = 0
            WHEN 'Inactivos' THEN c.isDeleted = 1
            WHEN 'Todos' THEN 1=1
        END
    )
    AND (p_searchType = 0 OR 
         (p_searchType = 1 AND p.name LIKE CONCAT('%', COALESCE(p_searchTerm, ''), '%')) OR
         (p_searchType = 2 AND p.identificationNumber LIKE CONCAT('%', COALESCE(p_searchTerm, ''), '%')))
    AND (p_filterByClientType = -1 OR c.idClientType = p_filterByClientType)
    AND (p_filterByDiabetes IS NULL OR hq.diabetes = p_filterByDiabetes)
    AND (p_filterByHypertension IS NULL OR hq.hypertension = p_filterByHypertension)
    AND (p_filterByMuscleInjuries IS NULL OR hq.muscleInjuries = p_filterByMuscleInjuries)
    AND (p_filterByBoneJointIssues IS NULL OR hq.boneJointIssues = p_filterByBoneJointIssues)
    AND (p_filterByBalanceLoss IS NULL OR hq.balanceLoss = p_filterByBalanceLoss)
    AND (p_filterByCardiovascularDisease IS NULL OR hq.cardiovascularDisease = p_filterByCardiovascularDisease)
    AND (p_filterByBreathingIssues IS NULL OR hq.breathingIssues = p_filterByBreathingIssues)
    AND (p_filterByDateBirthStart IS NULL OR p.birthday >= p_filterByDateBirthStart)
    AND (p_filterByDateBirthEnd IS NULL OR p.birthday <= p_filterByDateBirthEnd);

    -- Obtener los registros paginados
    SELECT 
        c.idClient,
        c.idPerson,
        c.idClientType,
        c.idHealthQuestionnaire,
        c.idUser,
        c.registrationDate,
        c.expirationMembershipDate,
        c.phoneNumberContactEmergency,
        c.nameEmergencyContact,
        c.signatureImage,
        c.isDeleted,
        c.password
    FROM tbClient c
    INNER JOIN tbPerson p ON c.idPerson = p.idPerson
    LEFT JOIN tbHealthQuestionnaire hq ON c.idHealthQuestionnaire = hq.idHealthQuestionnaire
    WHERE (
        CASE p_filterByStatus
            WHEN '' THEN c.isDeleted = 0
            WHEN 'Inactivos' THEN c.isDeleted = 1
            WHEN 'Todos' THEN 1=1
        END
    )
    AND (p_searchType = 0 OR 
         (p_searchType = 1 AND p.name LIKE CONCAT('%', COALESCE(p_searchTerm, ''), '%')) OR
         (p_searchType = 2 AND p.identificationNumber LIKE CONCAT('%', COALESCE(p_searchTerm, ''), '%')))
    AND (p_filterByClientType = -1 OR c.idClientType = p_filterByClientType)
    AND (p_filterByDiabetes IS NULL OR hq.diabetes = p_filterByDiabetes)
    AND (p_filterByHypertension IS NULL OR hq.hypertension = p_filterByHypertension)
    AND (p_filterByMuscleInjuries IS NULL OR hq.muscleInjuries = p_filterByMuscleInjuries)
    AND (p_filterByBoneJointIssues IS NULL OR hq.boneJointIssues = p_filterByBoneJointIssues)
    AND (p_filterByBalanceLoss IS NULL OR hq.balanceLoss = p_filterByBalanceLoss)
    AND (p_filterByCardiovascularDisease IS NULL OR hq.cardiovascularDisease = p_filterByCardiovascularDisease)
    AND (p_filterByBreathingIssues IS NULL OR hq.breathingIssues = p_filterByBreathingIssues)
    AND (p_filterByDateBirthStart IS NULL OR p.birthday >= p_filterByDateBirthStart)
    AND (p_filterByDateBirthEnd IS NULL OR p.birthday <= p_filterByDateBirthEnd)
    ORDER BY 
        CASE WHEN COALESCE(p_orderBy, '') = 'name' AND COALESCE(p_directionOrderBy, '') = 'ASC' THEN p.name END ASC,
        CASE WHEN COALESCE(p_orderBy, '') = 'name' AND COALESCE(p_directionOrderBy, '') = 'DESC' THEN p.name END DESC,
        CASE WHEN COALESCE(p_orderBy, '') = 'expirationDate' AND COALESCE(p_directionOrderBy, '') = 'ASC' THEN c.expirationMembershipDate END ASC,
        CASE WHEN COALESCE(p_orderBy, '') = 'expirationDate' AND COALESCE(p_directionOrderBy, '') = 'DESC' THEN c.expirationMembershipDate END DESC,
        c.idClient DESC
    LIMIT v_offset, p_limit;
END$$

DELIMITER ;

-- Verificación
SELECT 'Stored procedures actualizados correctamente' as Mensaje;
