package una.force_gym.controller;

import java.util.List;
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

import una.force_gym.domain.Exercise;
import una.force_gym.dto.ExerciseDTO;
import una.force_gym.exception.AppException;
import una.force_gym.service.ExerciseService;
import una.force_gym.util.ApiResponse;

@RestController
@RequestMapping("/exercise")
public class ExerciseController {

    @Autowired
    private ExerciseService exerciseService;

    @GetMapping("/listAll")
    public ResponseEntity<ApiResponse<List<Exercise>>> getExercises() {
        try {
            List<Exercise> exercises = exerciseService.getAllExercises();
            ApiResponse<List<Exercise>> response = new ApiResponse<>("Ejercicios obtenidos correctamente.", exercises);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e) {
            ApiResponse<List<Exercise>> response = new ApiResponse<>("Ocurrió un error al solicitar los ejercicios.", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/list")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getExercises(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "1") int searchType,
            @RequestParam(defaultValue = "") String searchTerm,
            @RequestParam(defaultValue = "") String orderBy,
            @RequestParam(defaultValue = "") String directionOrderBy,
            @RequestParam(defaultValue = "") String filterByStatus,
            @RequestParam(defaultValue = "") String filterByDifficulty,
            @RequestParam(defaultValue = "0") Integer filterByCategory
    ) {
        try {
            Map<String, Object> responseData = exerciseService.getExercises(
                    page, size, searchType, searchTerm, orderBy, directionOrderBy,
                    filterByStatus, filterByDifficulty, filterByCategory
            );

            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ejercicios obtenidos correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e) {
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ocurrió un error al solicitar los ejercicios.", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/add")
    public ResponseEntity<ApiResponse<String>> addExercise(@RequestBody ExerciseDTO exerciseDTO) {
        int result = exerciseService.addExercise(
                exerciseDTO.getName(),
                exerciseDTO.getDescription(),
                exerciseDTO.getVideoUrl(),
                exerciseDTO.getIdExerciseDifficulty(),
                exerciseDTO.getIdExerciseCategory(),
                exerciseDTO.getParamLoggedIdUser()
        );

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Ejercicio agregado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }
            case 0 ->
                throw new AppException("Ocurrió un error al agregar el ejercicio.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -2 -> // name ya existe
                throw new AppException("No se pudo agregar el ejercicio debido a que el nombre ya fue asignado a otro ejercicio", HttpStatus.INTERNAL_SERVER_ERROR);
            default ->
                throw new AppException("Ejercicio no agregado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/update/{id}")
    public ResponseEntity<ApiResponse<String>> updateExercise(@PathVariable int id, @RequestBody ExerciseDTO exerciseDTO) {
        int result = exerciseService.updateExercise(
                id,
                exerciseDTO.getName(),
                exerciseDTO.getDescription(),
                exerciseDTO.getVideoUrl(),
                exerciseDTO.getIdExerciseDifficulty(),
                exerciseDTO.getIdExerciseCategory(),
                exerciseDTO.getIsDeleted(),
                exerciseDTO.getParamLoggedIdUser()
        );

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Ejercicio actualizado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }
            case 0 ->
                throw new AppException("Ocurrió un error al actualizar el ejercicio.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -1 ->
                throw new AppException("El ejercicio a actualizar no existe.", HttpStatus.NOT_FOUND);
            case -2 -> // name ya existe
                throw new AppException("No se pudo actualizar el ejercicio debido a que el nuevo nombre ya fue asignado a otro ejercicio", HttpStatus.INTERNAL_SERVER_ERROR);
            default ->
                throw new AppException("No se pudo actualizar el ejercicio debido a un error en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<ApiResponse<String>> deleteExercise(@PathVariable int id, @RequestParam int deletedByUser) {
        int result = exerciseService.deleteExercise(id, deletedByUser);

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Ejercicio eliminado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }
            case 0 ->
                throw new AppException("Ocurrió un error al eliminar el ejercicio.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -1 ->
                throw new AppException("El ejercicio a eliminar no existe.", HttpStatus.NOT_FOUND);
            default ->
                throw new AppException("No se pudo eliminar el ejercicio debido a un error en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
