package una.force_gym.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import una.force_gym.dto.NotificationDTO;
import una.force_gym.dto.ParamLoggedIdUserDTO;
import una.force_gym.exception.AppException;
import una.force_gym.service.NotificationService;
import una.force_gym.util.ApiResponse;

@RestController
@RequestMapping("/notification")
public class NotificationController {

    @Autowired
    private NotificationService notificationService;

    @GetMapping("/list")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getNotifications(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "1") int searchType,
            @RequestParam(defaultValue = "") String searchTerm,
            @RequestParam(defaultValue = "") String orderBy,
            @RequestParam(defaultValue = "") String directionOrderBy,
            @RequestParam(defaultValue = "") String filterByStatus
    ) {
        try {
            Map<String, Object> responseData = notificationService.getProductsInventory(page, size, searchType, searchTerm, orderBy, directionOrderBy, filterByStatus);
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Notificaciones obtenidas correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (RuntimeException e) {
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ocurrió un error al solicitar los datos de las notificaciones.", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @PostMapping("/add")
    public ResponseEntity<ApiResponse<String>> addNotification(@RequestBody NotificationDTO notificationDTO) {
        int result = notificationService.addNotification(
                notificationDTO.getIdClient(),
                notificationDTO.getIdNotificationType(),
                notificationDTO.getParamLoggedIdUser()
        );

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Notificacion agregado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            // error de MySQL
            case 0 ->
                throw new AppException("Ocurrió un error al agregar la nuevo notificacion.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idUser
            case -1 ->
                throw new AppException("No se pudo agregar la nueva notificacion debido a que el usuario asociado no está registrado.", HttpStatus.INTERNAL_SERVER_ERROR);

            default ->
                throw new AppException("Notificacion no agregada debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @PutMapping("/update")
    public ResponseEntity<ApiResponse<String>> updateNotification(@RequestBody NotificationDTO notificationDTO) {
        int result = notificationService.updateNotification(
                notificationDTO.getIdNotification(),
                notificationDTO.getIdClient(),
                notificationDTO.getIdNotificationType(),
                notificationDTO.getIsDeleted()
        );

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Notificacion actualizado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            // error de MySQL
            case 0 ->
                throw new AppException("Ocurrió un error al actualizar el notificacion.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idNotification
            case -1 ->
                throw new AppException("No se pudo actualizar el notificacion debido a que no se encuentra el registro.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idUser
            case -2 ->
                throw new AppException("No se pudo actualizar el notificacion debido a que el usuario asociado no está registrado.", HttpStatus.INTERNAL_SERVER_ERROR);

            default ->
                throw new AppException("Notificacion no actualizado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @DeleteMapping("/delete/{idNotification}")
    public ResponseEntity<ApiResponse<String>> deleteNotification(@PathVariable("idNotification") Long idNotification, @RequestBody ParamLoggedIdUserDTO paramLoggedIdUser) {
        int result = notificationService.deleteNotification(idNotification);

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Notificacion eliminado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            // error de MySQL
            case 0 ->
                throw new AppException("Ocurrió un error al eliminar el notificacion.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idNotification
            case -1 ->
                throw new AppException("No se pudo eliminar el notificacion debido a que no se encuentra el registro.", HttpStatus.INTERNAL_SERVER_ERROR);

            default ->
                throw new AppException("Notificacion no eliminado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }
}
