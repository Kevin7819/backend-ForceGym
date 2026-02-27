package una.force_gym.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.query.Procedure;
import org.springframework.data.repository.query.Param;

import una.force_gym.domain.Notification;

public interface NotificationRepository extends JpaRepository<Notification, Long> {
    
    @Procedure(procedureName = "prInsertNotification", outputParameterName = "result")
    int addNotification(
        @Param("pIdClient") Long pIdClient,
        @Param("pIdNotificationType") Long pIdNotificationType,
        @Param("pLoggedIdUser") Long pLoggedIdUser
    );

    @Procedure(procedureName = "prUpdateNotification", outputParameterName = "result")
    int updateNotification(
        @Param("pIdNotification") Long pIdNotification,
        @Param("pIdClient") Long pIdClient,
        @Param("pIdNotificationTemplate") Long pIdNotificationType,
        @Param("pIsDeleted") Long pIsDeleted
    );

    @Procedure(procedureName = "prDeleteNotification", outputParameterName = "result")
    int deleteNotification(  @Param("pIdNotification") Long pIdNotification);
}
