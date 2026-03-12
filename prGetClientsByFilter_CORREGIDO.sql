DELIMITER $$

DROP PROCEDURE IF EXISTS `prGetClientsByFilter`$$

CREATE DEFINER=`root`@`%` PROCEDURE `prGetClientsByFilter`(IN `pFilterType` INT)
BEGIN
    -- Obtener fecha actual (ignora los parámetros de fecha)
    DECLARE Today DATE;
    SET Today = CURDATE();

    IF pFilterType = 3 THEN
        -- Filtrar clientes por aniversario (Fecha de Registro hoy)
        -- MODIFICADO: Agregado c.isDeleted = 0 para excluir clientes eliminados
        SELECT 
            c.idClient, 
            p.name, 
            p.firstLastName, 
            p.secondLastName,
            p.email,
            p.phoneNumber,
            c.registrationDate AS additionalInfo,
            TIMESTAMPDIFF(YEAR, c.registrationDate, Today) AS yearsSinceRegistration
        FROM tbClient c
        JOIN tbPerson p ON c.idPerson = p.idPerson
        WHERE DATE_FORMAT(c.registrationDate, '%m-%d') = DATE_FORMAT(Today, '%m-%d')
        AND c.isDeleted = 0  -- Solo clientes activos
        AND NOT EXISTS (
            SELECT 1 FROM tbNotification n
            WHERE n.idClient = c.idClient
            AND n.idNotificationType = pFilterType
            AND n.sendDate >= DATE_SUB(Today, INTERVAL 7 DAY)
        );

    ELSEIF pFilterType = 2 THEN
        -- Filtrar clientes por cumpleaños (Fecha de Nacimiento hoy)
        -- MODIFICADO: Agregado c.isDeleted = 0 para excluir clientes eliminados
        SELECT 
            c.idClient, 
            p.name, 
            p.firstLastName, 
            p.secondLastName,
            p.email,
            p.phoneNumber,
            p.birthday AS additionalInfo,
            TIMESTAMPDIFF(YEAR, p.birthday, Today) AS age
        FROM tbClient c
        JOIN tbPerson p ON c.idPerson = p.idPerson
        WHERE DATE_FORMAT(p.birthday, '%m-%d') = DATE_FORMAT(Today, '%m-%d')
        AND c.isDeleted = 0  -- Solo clientes activos
        AND NOT EXISTS (
            SELECT 1 FROM tbNotification n
            WHERE n.idClient = c.idClient
            AND n.idNotificationType = pFilterType
            AND n.sendDate >= DATE_SUB(Today, INTERVAL 7 DAY)
        );

    ELSEIF pFilterType = 1 THEN
        -- Filtrar clientes con membresía vencida (hoy o antes)
        -- MODIFICADO: Agregado c.isDeleted = 0 para excluir clientes eliminados
        SELECT 
            c.idClient, 
            p.name, 
            p.firstLastName, 
            p.secondLastName,
            p.email,
            p.phoneNumber,
            c.expirationMembershipDate AS additionalInfo
        FROM tbClient c
        JOIN tbPerson p ON c.idPerson = p.idPerson
        WHERE c.expirationMembershipDate <= Today
        AND c.isDeleted = 0  -- Solo clientes activos
        AND NOT EXISTS (
            SELECT 1 FROM tbNotification n
            WHERE n.idClient = c.idClient
            AND n.idNotificationType = pFilterType
            AND n.sendDate >= DATE_SUB(Today, INTERVAL 7 DAY)
        );

    ELSE
        -- Si el filtro no es válido, lanzar un error
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Tipo de filtro no válido. Valores aceptados: 1 (Mensualidades), 2 (Cumpleaños) o 3 (Aniversarios)';
    END IF;
END$$

DELIMITER ;
