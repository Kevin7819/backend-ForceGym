-- =====================================================
-- Stored Procedure CORREGIDO: prInsertClient
-- CAMBIO: Línea 119 - Remover IFNULL para mantener NULL en expirationMembershipDate
-- =====================================================

USE dbforcegym;

DROP PROCEDURE IF EXISTS `prInsertClient`;

DELIMITER $$

CREATE DEFINER=`root`@`%` PROCEDURE `prInsertClient`(
    IN `pName` VARCHAR(50), 
    IN `pFirstLastName` VARCHAR(50), 
    IN `pSecondLastName` VARCHAR(50), 
    IN `pBirthday` DATE, 
    IN `pIdentificationNumber` VARCHAR(20), 
    IN `pPhoneNumber` VARCHAR(20), 
    IN `pEmail` VARCHAR(100), 
    IN `pIdGender` INT, 
    IN `pIdClientType` INT, 
    IN `pDiabetes` BOOLEAN, 
    IN `pHypertension` BOOLEAN, 
    IN `pMuscleInjuries` BOOLEAN, 
    IN `pBoneJointIssues` BOOLEAN, 
    IN `pBalanceLoss` BOOLEAN, 
    IN `pCardiovascularDisease` BOOLEAN, 
    IN `pBreathingIssues` BOOLEAN, 
    IN `pIdUser` INT,
    IN `pRegistrationDate` DATE, 
    IN `pExpirationMembershipDate` DATE, 
    IN `pPhoneNumberContactEmergency` VARCHAR(100), 
    IN `pNameEmergencyContact` VARCHAR(100), 
    IN `pSignatureImage` LONGTEXT, 
    IN `pLoggedIdUser` INT, 
    OUT `result` INT
)
prInsertClient: BEGIN

    DECLARE sqlstate_code CHAR(5);
    DECLARE mysql_errno INT;
    DECLARE message_text TEXT;

    DECLARE genIdPerson INT DEFAULT NULL;
    DECLARE genIdClient INT DEFAULT NULL;
    DECLARE genIdHealthQuestionnaire INT DEFAULT NULL;

    DECLARE phone_exists INT DEFAULT 0;
    DECLARE email_exists INT DEFAULT 0;

    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;

        GET DIAGNOSTICS CONDITION 1
            sqlstate_code = RETURNED_SQLSTATE,
            mysql_errno = MYSQL_ERRNO,
            message_text = MESSAGE_TEXT;

        INSERT INTO tbError(
            executionDate, codeCaused, message, description, nameProcedure
        )
        VALUES(
            NOW(),
            mysql_errno,
            IFNULL(message_text, 'Error interno sin mensaje'),
            CONCAT(
                'ERROR ', mysql_errno, 
                ' (', IFNULL(sqlstate_code,'N/A'), '): ', 
                IFNULL(message_text,'')
            ),
            'prInsertClient'
        );

        SET result = 0;
    END;

    SELECT idPerson INTO genIdPerson
    FROM tbPerson
    WHERE identificationNumber = pIdentificationNumber
    LIMIT 1;

    SELECT COUNT(*) INTO phone_exists
    FROM tbPerson
    WHERE phoneNumber = pPhoneNumber;

    SELECT COUNT(*) INTO email_exists
    FROM tbPerson
    WHERE email = pEmail;

    IF genIdPerson IS NOT NULL THEN
        SET result = -1;
        LEAVE prInsertClient;

    ELSEIF phone_exists > 0 THEN
        SET result = -2;
        LEAVE prInsertClient;

    ELSEIF email_exists > 0 THEN
        SET result = -3;
        LEAVE prInsertClient;
    END IF;

    START TRANSACTION;

    INSERT INTO tbPerson(
        name, firstLastName, secondLastName, birthday, identificationNumber,
        phoneNumber, email, idGender,
        createdByUser, createdAt, updatedByUser, updatedAt, isDeleted
    )
    VALUES(
        pName, pFirstLastName, pSecondLastName, pBirthday, pIdentificationNumber,
        pPhoneNumber, pEmail, pIdGender,
        pLoggedIdUser, NOW(), pLoggedIdUser, NOW(), 0
    );

    SET genIdPerson = LAST_INSERT_ID();

    INSERT INTO tbClient(
        idPerson, idHealthQuestionnaire, idClientType, idUser,
        registrationDate, expirationMembershipDate,
        signatureImage, phoneNumberContactEmergency, nameEmergencyContact,
        createdByUser, createdAt, updatedByUser, updatedAt, isDeleted
    )
    VALUES(
        genIdPerson, NULL, pIdClientType, pIdUser,
        pRegistrationDate, pExpirationMembershipDate,  -- ✅ CAMBIO AQUÍ: Removido IFNULL para mantener NULL
        pSignatureImage, pPhoneNumberContactEmergency, pNameEmergencyContact,
        pLoggedIdUser, NOW(), pLoggedIdUser, NOW(), 0
    );

    SET genIdClient = LAST_INSERT_ID();

    INSERT INTO tbHealthQuestionnaire(
        idClient, diabetes, hypertension, muscleInjuries, boneJointIssues,
        balanceLoss, cardiovascularDisease, breathingIssues,
        createdByUser, createdAt, updatedByUser, updatedAt, isDeleted
    )
    VALUES(
        genIdClient, pDiabetes, pHypertension, pMuscleInjuries, pBoneJointIssues,
        pBalanceLoss, pCardiovascularDisease, pBreathingIssues,
        pLoggedIdUser, NOW(), pLoggedIdUser, NOW(), 0
    );

    SET genIdHealthQuestionnaire = LAST_INSERT_ID();

    UPDATE tbClient
    SET idHealthQuestionnaire = genIdHealthQuestionnaire
    WHERE idClient = genIdClient;

    COMMIT;

    SET result = 1;

END$$

DELIMITER ;

-- =====================================================
-- Verificación
-- =====================================================

-- Verificar que se creó correctamente
SELECT ROUTINE_NAME, ROUTINE_TYPE, CREATED, LAST_ALTERED 
FROM information_schema.ROUTINES 
WHERE ROUTINE_SCHEMA = 'dbforcegym' 
  AND ROUTINE_NAME = 'prInsertClient';

-- Asegurar que la columna permita NULL
ALTER TABLE tbClient MODIFY COLUMN expirationMembershipDate DATE NULL;

-- Verificar la estructura de la tabla
DESCRIBE tbClient;

SELECT 'Stored Procedure prInsertClient ha sido actualizado correctamente' AS Mensaje;
