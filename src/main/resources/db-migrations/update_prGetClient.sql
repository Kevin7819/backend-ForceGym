-- Actualizar el stored procedure prGetClient para incluir la columna password

DROP PROCEDURE IF EXISTS prGetClient;

DELIMITER $$

CREATE PROCEDURE prGetClient(
    IN pIdentificationType INT,
    IN pIdGender INT,
    IN pSearchType INT,
    IN pSearchValue VARCHAR(50),
    IN pIdClientType INT,
    IN pPhoneNumberContactEmergency VARCHAR(50),
    IN pNameEmergencyContact VARCHAR(100),
    IN pSignatureImage VARCHAR(255),
    IN pIdUser INT,
    IN pRegistrationDate DATE,
    IN pExpirationMembershipDate DATE,
    IN pHealthQuestionnaireId INT,
    IN pDiabetes BOOLEAN,
    IN pHypertension BOOLEAN,
    IN pMuscleInjuries BOOLEAN,
    IN pBoneJointIssues BOOLEAN,
    IN pBalanceLoss BOOLEAN,
    IN pCardiovascularDisease BOOLEAN
)
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
        c.password,  -- Nueva columna agregada
        p.name,
        p.firstLastName,
        p.secondLastName,
        p.birthday,
        p.identificationNumber,
        p.phoneNumber,
        p.email,
        p.idGender,
        ct.name as clientTypeName,
        hq.diabetes,
        hq.hypertension,
        hq.muscleInjuries,
        hq.boneJointIssues,
        hq.balanceLoss,
        hq.cardiovascularDisease,
        hq.breathingIssues
    FROM tbClient c
    INNER JOIN tbPerson p ON c.idPerson = p.idPerson
    LEFT JOIN tbClientType ct ON c.idClientType = ct.idClientType
    LEFT JOIN tbHealthQuestionnaire hq ON c.idHealthQuestionnaire = hq.idHealthQuestionnaire
    WHERE c.isDeleted = 0
    AND (pSearchType = 0 OR 
         (pSearchType = 1 AND p.name LIKE CONCAT('%', pSearchValue, '%')) OR
         (pSearchType = 2 AND p.identificationNumber LIKE CONCAT('%', pSearchValue, '%')))
    AND (pIdClientType = 0 OR c.idClientType = pIdClientType)
    ORDER BY c.idClient DESC;
END$$

DELIMITER ;
