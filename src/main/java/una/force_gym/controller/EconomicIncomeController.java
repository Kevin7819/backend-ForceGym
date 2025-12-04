package una.force_gym.controller;

import java.time.LocalDate;
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

import una.force_gym.dto.EconomicIncomeDTO;
import una.force_gym.dto.ParamLoggedIdUserDTO;
import una.force_gym.exception.AppException;
import una.force_gym.service.EconomicIncomeService;
import una.force_gym.util.ApiResponse;

@RestController
@RequestMapping("/economicIncome")
public class EconomicIncomeController {

    @Autowired
    private EconomicIncomeService economicIncomeService;

    @GetMapping("/list")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getEconomicIncomes( 
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "1") int searchType,
            @RequestParam(defaultValue = "") String searchTerm,
            @RequestParam(defaultValue = "") String orderBy,
            @RequestParam(defaultValue = "") String directionOrderBy,
            @RequestParam(defaultValue = "") String filterByStatus,
            @RequestParam(required = false) Long filterByAmountRangeMin,
            @RequestParam(required = false) Long filterByAmountRangeMax,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate filterByDateRangeMin,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate filterByDateRangeMax,
            @RequestParam(defaultValue = "-1") int filterByMeanOfPayment,
            @RequestParam(defaultValue = "-1") int filterByClientType){ 
        try {
            Map<String, Object> responseData = economicIncomeService.getEconomicIncomes(page, size, searchType, searchTerm, orderBy, directionOrderBy, filterByStatus, filterByAmountRangeMin, filterByAmountRangeMax, filterByDateRangeMin, filterByDateRangeMax, filterByMeanOfPayment, filterByClientType);
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ingresos económicos obtenidos correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK); 

        } catch (RuntimeException e) {
            System.out.print("aca: " + e);
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ocurrió un error al solicitar los datos de los ingresos económicos.", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR); 
        }

    } 

    @GetMapping("/listAll")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getAllEconomicIncomes( 
            @RequestParam(defaultValue = "") String filterByStatus,
            @RequestParam(required = false) Long filterByAmountRangeMin,
            @RequestParam(required = false) Long filterByAmountRangeMax,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate filterByDateRangeMin,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate filterByDateRangeMax,
            @RequestParam(defaultValue = "-1") int filterByMeanOfPayment){ 
        try {
            Map<String, Object> responseData = economicIncomeService.getAllEconomicIncomes(filterByStatus, filterByAmountRangeMin, filterByAmountRangeMax, filterByDateRangeMin, filterByDateRangeMax, filterByMeanOfPayment);
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ingresos económicos obtenidos correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK); 

        } catch (RuntimeException e) {
            System.out.print("aca: " + e);
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ocurrió un error al solicitar los datos de los ingresos económicos.", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR); 
        }

    } 
    
    @PostMapping("/add")
    public ResponseEntity<ApiResponse<String>> addEconomicIncome(@RequestBody EconomicIncomeDTO economicIncomeDTO) {
        int result = economicIncomeService.addEconomicIncome(
            economicIncomeDTO.getIdClient(), 
            economicIncomeDTO.getRegistrationDate(), 
            economicIncomeDTO.getVoucherNumber(), 
            economicIncomeDTO.getDetail(), 
            economicIncomeDTO.getIdMeanOfPayment(), 
            economicIncomeDTO.getAmount(), 
            economicIncomeDTO.getIdActivityType(), 
            economicIncomeDTO.getDelayDays(),
            economicIncomeDTO.getParamLoggedIdUser()
        );

        switch(result) {
            case 1 -> 
            { 
                ApiResponse<String> response = new ApiResponse<>("Ingreso económico agregado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK); 
            }

            // error de MySQL
            case 0 -> throw new AppException("Ocurrió un error al agregar el nuevo ingreso económico.", HttpStatus.INTERNAL_SERVER_ERROR);
            
            // voucher duplicado
            case -1 -> throw new AppException("No se pudo agregar el nuevo ingreso económico debido a que el voucher ingresado ya está asociado a otro registro", HttpStatus.INTERNAL_SERVER_ERROR);
            
            default -> throw new AppException("Ingreso económico no agregado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @PutMapping("/update")
    public ResponseEntity<ApiResponse<String>> updateEconomicIncome(@RequestBody EconomicIncomeDTO economicIncomeDTO) {
        int result = economicIncomeService.updateEconomicIncome(
            economicIncomeDTO.getIdEconomicIncome(), 
            economicIncomeDTO.getIdClient(), 
            economicIncomeDTO.getRegistrationDate(), 
            economicIncomeDTO.getVoucherNumber(), 
            economicIncomeDTO.getDetail(), 
            economicIncomeDTO.getIdMeanOfPayment(), 
            economicIncomeDTO.getAmount(), 
            economicIncomeDTO.getIdActivityType(), 
            economicIncomeDTO.getDelayDays(),
            economicIncomeDTO.getIsDeleted(),
            economicIncomeDTO.getParamLoggedIdUser()
        );

        switch(result) {
            case 1 -> 
            { 
                ApiResponse<String> response = new ApiResponse<>("Ingreso económico actualizado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK); 
            }

            // error de MySQL
            case 0 -> throw new AppException("Ocurrió un error al actualizar el ingreso económico.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idEconomicIncome
            case -1 -> throw new AppException("No se pudo actualizar el ingreso económico debido a que no se encuentra el registro.", HttpStatus.INTERNAL_SERVER_ERROR);

            // se encontró un voucher previo y que no correspondía
            case -2 -> throw new AppException("No se pudo actualizar el ingreso económico debido a que ya existe un ingreso registrado con el mismo voucher", HttpStatus.INTERNAL_SERVER_ERROR);

            default -> throw new AppException("Ingreso económico no actualizado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @DeleteMapping("/delete/{idEconomicIncome}")
    public ResponseEntity<ApiResponse<String>> deleteEconomicIncome(@PathVariable("idEconomicIncome") Long idEconomicIncome, @RequestBody ParamLoggedIdUserDTO paramLoggedIdUser) {
        int result = economicIncomeService.deleteEconomicIncome(idEconomicIncome, paramLoggedIdUser.getParamLoggedIdUser());
       
        switch(result) {
            case 1 -> 
            { 
                ApiResponse<String> response = new ApiResponse<>("Ingreso económico eliminado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK); 
            }

            // error de MySQL
            case 0 -> throw new AppException("Ocurrió un error al eliminar el ingreso económico.", HttpStatus.INTERNAL_SERVER_ERROR);

            // no se encuentra el idEconomicIncome
            case -1 -> throw new AppException("No se pudo eliminar el ingreso económico debido a que no se encuentra el registro.", HttpStatus.INTERNAL_SERVER_ERROR);

            default -> throw new AppException("Ingreso económico no eliminado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

}
