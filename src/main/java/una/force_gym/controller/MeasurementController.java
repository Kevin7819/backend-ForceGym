package una.force_gym.controller;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
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
import org.springframework.web.multipart.MultipartFile;

import una.force_gym.dto.MeasurementDTO;
import una.force_gym.dto.ParamLoggedIdUserDTO;
import una.force_gym.exception.AppException;
import una.force_gym.service.MeasurementService;
import una.force_gym.util.ApiResponse;


@RestController
@RequestMapping("/measurement")
public class MeasurementController {
    
    @Autowired
    private MeasurementService measurementService;


    @GetMapping("/list")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getMeasurements(
            @RequestParam(defaultValue = "") int idClient, 
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "1") int searchType,
            @RequestParam(defaultValue = "") String searchTerm,
            @RequestParam(defaultValue = "") String orderBy,
            @RequestParam(defaultValue = "") String directionOrderBy,
            @RequestParam(defaultValue = "") String filterByStatus,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate filterByDateRangeMin,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate filterByDateRangeMax
            
            )  {
        try {
            // Mapear Min/Max a Start/End para el servicio
            Map<String, Object> responseData = measurementService.getMeasurements(
                idClient, page, size, searchType, searchTerm, orderBy, directionOrderBy, 
                filterByStatus, filterByDateRangeMin, filterByDateRangeMax
            );
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Medidas obtenidas correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK); 

        } catch (RuntimeException e) {
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ocurrió un error al solicitar los datos de las medidas.", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR); 
        }

    }
    

    @PostMapping("/add")
    public ResponseEntity<ApiResponse<String>> addMeasurement(@RequestBody MeasurementDTO measurementDTO) {
        int result = measurementService.addMeasurement(
            measurementDTO.getIdClient(),
            measurementDTO.getMeasurementDate(),
            measurementDTO.getWeight(),
            measurementDTO.getHeight(),
            measurementDTO.getBmi(),
            measurementDTO.getMuscleMass(),
            measurementDTO.getBodyFatPercentage(),
            measurementDTO.getVisceralFatPercentage(),
            measurementDTO.getChestSize(),
            measurementDTO.getBackSize(),
            measurementDTO.getHipSize(),
            measurementDTO.getWaistSize(),
            measurementDTO.getLeftLegSize(),
            measurementDTO.getRightLegSize(),
            measurementDTO.getLeftCalfSize(),
            measurementDTO.getRightCalfSize(),
            measurementDTO.getLeftForeArmSize(),
            measurementDTO.getRightForeArmSize(),
            measurementDTO.getLeftArmSize(),
            measurementDTO.getRightArmSize(),
            measurementDTO.getParamLoggedIdUser()
        );

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Medidas agregado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            case 0 -> throw new AppException("Ocurrió un error al agregar las nuevas medidas.", HttpStatus.INTERNAL_SERVER_ERROR);

            case -1 -> throw new AppException("No se pudo agregar las nuevas medidas debido a que el usuario asociado no está registrado.", HttpStatus.INTERNAL_SERVER_ERROR);

            default -> throw new AppException("Medidas no agregadas debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @PutMapping("/update")
    public ResponseEntity<ApiResponse<String>> updateMeasurement(@RequestBody MeasurementDTO measurementDTO) {
        int result = measurementService.updateMeasurement(
            measurementDTO.getIdMeasurement(),
            measurementDTO.getIdClient(),
            measurementDTO.getMeasurementDate(),
            measurementDTO.getWeight(),
            measurementDTO.getHeight(),
            measurementDTO.getBmi(),
            measurementDTO.getMuscleMass(),
            measurementDTO.getBodyFatPercentage(),
            measurementDTO.getVisceralFatPercentage(),
            measurementDTO.getChestSize(),
            measurementDTO.getBackSize(),
            measurementDTO.getHipSize(),
            measurementDTO.getWaistSize(),
            measurementDTO.getLeftLegSize(),
            measurementDTO.getRightLegSize(),
            measurementDTO.getLeftCalfSize(),
            measurementDTO.getRightCalfSize(),
            measurementDTO.getLeftForeArmSize(),
            measurementDTO.getRightForeArmSize(),
            measurementDTO.getLeftArmSize(),
            measurementDTO.getRightArmSize(),
            measurementDTO.getIsDeleted(),
            measurementDTO.getParamLoggedIdUser()
        );

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Medidas actualizado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            case 0 -> throw new AppException("Ocurrió un error al actualizar las medidas.", HttpStatus.INTERNAL_SERVER_ERROR);

            case -1 -> throw new AppException("No se pudo actualizar las medidas debido a que no se encuentra el registro.", HttpStatus.INTERNAL_SERVER_ERROR);

            case -2 -> throw new AppException("No se pudo actualizar las medidas debido a que el usuario asociado no está registrado.", HttpStatus.INTERNAL_SERVER_ERROR);

            default -> throw new AppException("Medidas no actualizado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @PostMapping("/import")
    public ResponseEntity<ApiResponse<Map<String, Object>>> importMeasurementsFromExcel(
            @RequestParam("file") MultipartFile file,
            @RequestParam("idClient") Long idClient) {
        try {
            int importedCount = measurementService.importMeasurementsFromExcel(file, idClient);
            
            Map<String, Object> data = new HashMap<>();
            data.put("imported", importedCount);
            
            ApiResponse<Map<String, Object>> response = new ApiResponse<>(
                "Medidas importadas correctamente desde Excel.", 
                data
            );
            return new ResponseEntity<>(response, HttpStatus.OK);
            
        } catch (Exception e) {
            throw new AppException(
                "Error al importar medidas desde Excel: " + e.getMessage(), 
                HttpStatus.BAD_REQUEST
            );
        }
    }

    @DeleteMapping("/delete/{idMeasurement}")
    public ResponseEntity<ApiResponse<String>> deleteMeasurement(@PathVariable("idMeasurement") Long idMeasurement, @RequestBody ParamLoggedIdUserDTO paramLoggedIdUser) {
        int result = measurementService.deleteMeasurement(idMeasurement, paramLoggedIdUser.getParamLoggedIdUser());
        
        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Medidas eliminado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            case 0 -> throw new AppException("Ocurrió un error al eliminar las medidas.", HttpStatus.INTERNAL_SERVER_ERROR);

            case -1 -> throw new AppException("No se pudo eliminar las medidas debido a que no se encuentra el registro.", HttpStatus.INTERNAL_SERVER_ERROR);

            default -> throw new AppException("Medidas no eliminado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }


}
