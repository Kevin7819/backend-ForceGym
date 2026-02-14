-- Actualizar el stored procedure prGetAllClient para incluir la columna password

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
    ORDER BY c.idClient DESC;
END$$

DELIMITER ;
