USE dbforcegym;

DROP PROCEDURE IF EXISTS prInsertNotification;

DELIMITER //

CREATE PROCEDURE prInsertNotification(
    IN pIdClient INT,
    IN pIdNotificationType INT,
    IN pLoggedIdUser INT,
    OUT result INT
)
prInsertNotification:BEGIN
    DECLARE sqlstate_code CHAR(5);
    DECLARE mysql_errno INT;
    DECLARE message_text TEXT;

    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        GET DIAGNOSTICS CONDITION 1 
            sqlstate_code = RETURNED_SQLSTATE, 
            mysql_errno = MYSQL_ERRNO, 
            message_text = MESSAGE_TEXT;
         
        INSERT INTO tbError (
            executionDate, 
            codeCaused, 
            message,
            description, 
            nameProcedure
        ) VALUES (
            NOW(), 
            mysql_errno, 
            message_text, 
            CONCAT('ERROR ', mysql_errno, ' (', sqlstate_code, '): ', message_text),
            'prInsertNotification'
        );

        SET result = 0;
    END;

    -- Verificar que el cliente existe
    IF pIdClient IS NULL OR NOT EXISTS (SELECT 1 FROM tbClient WHERE idClient = pIdClient AND isDeleted = 0) THEN
        INSERT INTO tbError (
            executionDate,
            codeCaused,
            message,
            description,
            nameProcedure
        ) VALUES (
            NOW(),
            NULL,
            'ID de Cliente inválido',
            CONCAT('Se proporcionó un ID de Cliente inválido: ', pIdClient, ' para la inserción en la tabla tbNotification'),
            'prInsertNotification'
        );
        SET result = -1;
        LEAVE prInsertNotification;
    END IF;
    
    -- Verificar que el tipo de notificación existe
    IF pIdNotificationType IS NULL OR NOT EXISTS (SELECT 1 FROM tbNotificationType WHERE idNotificationType = pIdNotificationType AND isDeleted = 0) THEN
        INSERT INTO tbError (
            executionDate,
            codeCaused,
            message,
            description,
            nameProcedure
        ) VALUES (
            NOW(),
            NULL,
            'ID de Tipo de Notificación inválido',
            CONCAT('Se proporcionó un ID de Tipo de Notificación inválido: ', pIdNotificationType, ' para la inserción en la tabla tbNotification'),
            'prInsertNotification'
        );
        SET result = -2;
        LEAVE prInsertNotification;
    END IF;

    START TRANSACTION;

    -- Inserción solo en los campos que existen en la tabla
    INSERT INTO tbNotification (
        idClient, 
        idNotificationType, 
        isDeleted
    ) VALUES (
        pIdClient,
        pIdNotificationType, 
        0
    );

    SET result = 1;
    COMMIT;
END//

DELIMITER ;
