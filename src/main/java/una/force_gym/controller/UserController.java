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

import una.force_gym.dto.ParamLoggedIdUserDTO;
import una.force_gym.dto.UserFormDTO;
import una.force_gym.exception.AppException;
import una.force_gym.service.UserService;
import una.force_gym.util.ApiResponse;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/list")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUsers(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "1") int searchType,
            @RequestParam(defaultValue = "") String searchTerm,
            @RequestParam(defaultValue = "") String orderBy,
            @RequestParam(defaultValue = "") String directionOrderBy,
            @RequestParam(defaultValue = "") String filterByStatus,
            @RequestParam(defaultValue = "") String filterByRole) {
        try {
            Map<String, Object> responseData = userService.getUsers(page, size, searchType, searchTerm, orderBy, directionOrderBy, filterByStatus, filterByRole);
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Usuarios obtenidos correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (RuntimeException e) {
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ocurrió un error al solicitar los datos de los usuarios", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/{idUser}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUserById(@PathVariable("idUser") Long idUser) {
        try {
            Map<String, Object> responseData = userService.getUserById(idUser);
            
            if(responseData == null || responseData.isEmpty()) {
                throw new AppException("No se encontró el usuario solicitado.", HttpStatus.NOT_FOUND);
            }
            
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Usuario obtenido correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (AppException e) {
            throw e;
        } catch (RuntimeException e) {
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ocurrió un error al solicitar los datos del usuario", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/add")
    public ResponseEntity<ApiResponse<String>> addUser(@RequestBody UserFormDTO userForm) {
        int result = userService.addUser(
                userForm.getIdRole(),
                userForm.getName(),
                userForm.getFirstLastName(),
                userForm.getSecondLastName(),
                userForm.getBirthday(),
                userForm.getIdentificationNumber(),
                userForm.getPhoneNumber(),
                userForm.getEmail(),
                userForm.getIdGender(),
                userForm.getUsername(),
                userForm.getPassword(),
                userForm.getParamLoggedIdUser()
        );

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Usuario agregado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            // error de mysql
            case 0 ->
                throw new AppException("Ocurrió un error al agregar el nuevo usuario.", HttpStatus.INTERNAL_SERVER_ERROR);

            // se encontró un idPerson previo
            case -1 ->
                throw new AppException("No se pudo agregar el nuevo usuario debido a que ya existe un usuario para la persona asociada.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idRole
            case -2 ->
                throw new AppException("No se pudo agregar el nuevo usuario debido a que el rol asociado no está registrado.", HttpStatus.INTERNAL_SERVER_ERROR);

            // username duplicado
            case -3 ->
                throw new AppException("No se pudo agregar el nuevo usuario debido a que el nombre de usuario ya existe.", HttpStatus.INTERNAL_SERVER_ERROR);

            case -4 ->
                throw new AppException("No se pudo actualizar el usuario el número de teléfono ya está en uso.", HttpStatus.INTERNAL_SERVER_ERROR);
            
            // email duplicado
            case -5 ->
                throw new AppException("No se pudo agregar el nuevo usuario debido a que el email ya está asociado a otro usuario.", HttpStatus.INTERNAL_SERVER_ERROR);

            default ->
                throw new AppException("Usuario no agregado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @PutMapping("/update")
    public ResponseEntity<ApiResponse<String>> updateUser(@RequestBody UserFormDTO userForm) {
        int result = userService.updateUser(
                userForm.getIdUser(),
                userForm.getIdRole(),
                userForm.getIdPerson(),
                userForm.getName(),
                userForm.getFirstLastName(),
                userForm.getSecondLastName(),
                userForm.getBirthday(),
                userForm.getIdentificationNumber(),
                userForm.getPhoneNumber(),
                userForm.getEmail(),
                userForm.getIdGender(),
                userForm.getUsername(),
                userForm.getPassword(),
                userForm.getIsDeleted(),
                userForm.getParamLoggedIdUser()
        );

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Usuario actualizado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            // error de mysql
            case 0 ->
                throw new AppException("Ocurrió un error al actualizar el usuario.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idUser
            case -1 ->
                throw new AppException("No se pudo actualizar el usuario debido a que no se encuentra el registro.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idPerson
            case -2 ->
                throw new AppException("No se pudo actualizar el usuario debido a que la persona asociada no está registrada.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idRole
            case -3 ->
                throw new AppException("No se pudo actualizar el usuario debido a que el rol asociado no está registrado.", HttpStatus.INTERNAL_SERVER_ERROR);

            // cedula
            case -4 ->
                throw new AppException("No se pudo actualizar el usuario debido a que la cédula ya existe.", HttpStatus.INTERNAL_SERVER_ERROR);
            
            case -5 ->
                throw new AppException("No se pudo actualizar el usuario debido a que el nombre de usuario ya está en uso.", HttpStatus.INTERNAL_SERVER_ERROR);
            
            case -6 ->
                throw new AppException("No se pudo actualizar el usuario debido a que el número de teléfono ya está en uso.", HttpStatus.INTERNAL_SERVER_ERROR);
            
            case -7 ->
                throw new AppException("No se pudo actualizar el usuario debido a que el correo electrónico ya está en uso.", HttpStatus.INTERNAL_SERVER_ERROR);
            
            default ->
                throw new AppException("Usuario no actualizado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/delete/{idUser}")
    public ResponseEntity<ApiResponse<String>> deleteUser(@PathVariable("idUser") Long idUser, @RequestBody ParamLoggedIdUserDTO paramLoggedIdUser) {
        int result = userService.deleteUser(idUser, paramLoggedIdUser.getParamLoggedIdUser());

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Usuario eliminado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            // error de mysql
            case 0 ->
                throw new AppException("Ocurrió un error al eliminar el usuario.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idUser
            case -1 ->
                throw new AppException("No se pudo eliminar el usuario debido a que no se encuentra el registro.", HttpStatus.INTERNAL_SERVER_ERROR);

            default ->
                throw new AppException("Usuario no eliminado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @DeleteMapping("/delete-permanent/{idUser}")
    public ResponseEntity<ApiResponse<String>> deleteUserPermanently(@PathVariable("idUser") Long idUser, @RequestBody ParamLoggedIdUserDTO paramLoggedIdUser) {
        try {
            userService.deleteUserPermanently(idUser, paramLoggedIdUser.getParamLoggedIdUser());
            ApiResponse<String> response = new ApiResponse<>("Usuario eliminado permanentemente.", null);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e) {
            // Retornar BAD_REQUEST para errores de validación de negocio
            ApiResponse<String> response = new ApiResponse<>(e.getMessage(), null);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

}
