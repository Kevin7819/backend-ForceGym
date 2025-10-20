package una.force_gym.controller;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
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

import una.force_gym.domain.Client;
import una.force_gym.dto.ClientDTO;
import una.force_gym.dto.ParamLoggedIdUserDTO;
import una.force_gym.exception.AppException;
import una.force_gym.service.ClientService;
import una.force_gym.util.ApiResponse;

@RestController
@RequestMapping("/client")
public class ClientController {

    @Autowired
    private ClientService clientService;

    @GetMapping("/list")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getClients(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "1") int searchType,
            @RequestParam(defaultValue = "") String searchTerm,
            @RequestParam(defaultValue = "") String orderBy,
            @RequestParam(defaultValue = "") String directionOrderBy,
            @RequestParam(defaultValue = "") String filterByStatus,
            @RequestParam(required = false) Boolean filterByDiabetes,
            @RequestParam(required = false) Boolean filterByHypertension,
            @RequestParam(required = false) Boolean filterByMuscleInjuries,
            @RequestParam(required = false) Boolean filterByBoneJointIssues,
            @RequestParam(required = false) Boolean filterByBalanceLoss,
            @RequestParam(required = false) Boolean filterByCardiovascularDisease,
            @RequestParam(required = false) Boolean filterByBreathingIssues,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate filterByDateBirthStart,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate filterByDateBirthEnd,
            @RequestParam(defaultValue = "-1") int filterByTypeClient
    ) {
        try {
            System.out.println("page: " + page);
            System.out.println("size: " + size);
            System.out.println("searchType: " + searchType);
            System.out.println("searchTerm: " + searchTerm);
            System.out.println("orderBy: " + orderBy);
            System.out.println("directionOrderBy: " + directionOrderBy);
            System.out.println("filterByStatus: " + filterByStatus);

            System.out.println("filterByDiabetes: " + filterByDiabetes);
            System.out.println("filterByHypertension: " + filterByHypertension);
            System.out.println("filterByMuscleInjuries: " + filterByMuscleInjuries);
            System.out.println("filterByBoneJointIssues: " + filterByBoneJointIssues);
            System.out.println("filterByBalanceLoss: " + filterByBalanceLoss);
            System.out.println("filterByCardiovascularDisease: " + filterByCardiovascularDisease);
            System.out.println("filterByBreathingIssues: " + filterByBreathingIssues);

            System.out.println("filterByDateBirthStart: " + (filterByDateBirthStart != null ? filterByDateBirthStart : "null"));
            System.out.println("filterByDateBirthEnd: " + (filterByDateBirthEnd != null ? filterByDateBirthEnd : "null"));

            System.out.println("filterByTypeClient: " + filterByTypeClient);

            Map<String, Object> responseData = clientService.getClients(page, size, searchType, searchTerm, orderBy, directionOrderBy, filterByStatus, filterByDiabetes, filterByHypertension, filterByMuscleInjuries, filterByBoneJointIssues, filterByBalanceLoss, filterByCardiovascularDisease, filterByBreathingIssues, filterByDateBirthStart, filterByDateBirthEnd, filterByTypeClient);
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Clientes obtenidos correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (RuntimeException e) {
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Ocurrió un error al solicitar los datos de los clientes." + e.getMessage(), null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/listAll")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllClients() {
        try {
            List<Client> clients = clientService.getAllClients();
            List<Map<String, Object>> responseData = new ArrayList<>();

            for (Client client : clients) {
                Map<String, Object> map = new HashMap<>();
                map.put("value", client.getIdClient());
                map.put("label", client.getPerson().getName() + " "
                        + client.getPerson().getFirstLastName() + " "
                        + client.getPerson().getSecondLastName());
                map.put("idClientType", client.getClientType().getIdClientType());
                responseData.add(map);
            }

            ApiResponse<List<Map<String, Object>>> response
                    = new ApiResponse<>("Clientes obtenidos correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (RuntimeException e) {
            ApiResponse<List<Map<String, Object>>> response
                    = new ApiResponse<>("Ocurrió un error al solicitar los datos de los clientes.", null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/filter")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getClientsByFilter(
            @RequestParam Integer filterType) {

        try {
            Map<String, Object> responseData = clientService.getClientsByFilter(filterType);
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Clientes obtenidos correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Error al obtener clientes: " + e.getMessage(), null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/add")
    public ResponseEntity<ApiResponse<String>> addClient(@RequestBody ClientDTO clientDTO) {
        int result = clientService.addClient(
                //Person
                clientDTO.getName(),
                clientDTO.getFirstLastName(),
                clientDTO.getSecondLastName(),
                clientDTO.getBirthday(),
                clientDTO.getIdentificationNumber(),
                clientDTO.getPhoneNumber(),
                clientDTO.getEmail(),
                clientDTO.getIdGender(),
                clientDTO.getIdClientType(),
                //HealtQuestionnare
                clientDTO.getDiabetes(),
                clientDTO.getHypertension(),
                clientDTO.getMuscleInjuries(),
                clientDTO.getBoneJointIssues(),
                clientDTO.getBalanceLoss(),
                clientDTO.getCardiovascularDisease(),
                clientDTO.getBreathingIssues(),
                clientDTO.getIdUser(),
                clientDTO.getRegistrationDate(),
                clientDTO.getExpirationMembershipDate(),
                clientDTO.getPhoneNumberContactEmergency(),
                clientDTO.getNameEmergencyContact(),
                clientDTO.getSignatureImage(),
                clientDTO.getParamLoggedIdUser()
        );

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Cliente agregado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }
            case 0 ->
                throw new AppException("Ocurrió un error al agregar el nuevo cliente.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -1 ->
                throw new AppException("No se pudo agregar el nuevo cliente debido a que el número de cedula ya está en uso.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -2 ->
                throw new AppException("No se pudo agregar el nuevo cliente debido a que el número de teléfono ya está en uso.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -3 ->
                throw new AppException("No se pudo agregar el nuevo cliente debido a que el correo electronico ya está en uso.", HttpStatus.INTERNAL_SERVER_ERROR);
            default ->
                throw new AppException("Cliente no agregado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PutMapping("/update")
    public ResponseEntity<ApiResponse<String>> updateClient(@RequestBody ClientDTO clientDTO) {
        int result = clientService.updateClient(
                clientDTO.getIdClient(),
                //Person
                clientDTO.getIdPerson(),
                clientDTO.getName(),
                clientDTO.getFirstLastName(),
                clientDTO.getSecondLastName(),
                clientDTO.getBirthday(),
                clientDTO.getIdentificationNumber(),
                clientDTO.getPhoneNumber(),
                clientDTO.getEmail(),
                clientDTO.getIdGender(),
                clientDTO.getIdTypeClient(),
                //HealtQuestionnare
                clientDTO.getIdHealthQuestionnaire(),
                clientDTO.getDiabetes(),
                clientDTO.getHypertension(),
                clientDTO.getMuscleInjuries(),
                clientDTO.getBoneJointIssues(),
                clientDTO.getBalanceLoss(),
                clientDTO.getCardiovascularDisease(),
                clientDTO.getBreathingIssues(),
                clientDTO.getIdUser(),
                clientDTO.getRegistrationDate(),
                clientDTO.getExpirationMembershipDate(),
                clientDTO.getPhoneNumberContactEmergency(),
                clientDTO.getNameEmergencyContact(),
                clientDTO.getSignatureImage(),
                clientDTO.getIsDeleted(),
                clientDTO.getParamLoggedIdUser()
        );

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Cliente actualizado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }
            case 0 ->
                throw new AppException("Ocurrió un error al actualizar el cliente.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -1 ->
                throw new AppException("No se pudo actualizar el cliente porque no se encuentra el registro.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -4 ->
                throw new AppException("No se pudo actualizar el cliente porque la cédula ya está en uso.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -5 ->
                throw new AppException("No se pudo actualizar el cliente porque el número de teléfono ya está en uso.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -6 ->
                throw new AppException("No se pudo actualizar el cliente porque el correo electrónico ya está en uso.", HttpStatus.INTERNAL_SERVER_ERROR);
            default ->
                throw new AppException("Cliente no actualizado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/delete/{idClient}")
    public ResponseEntity<ApiResponse<String>> deleteClient(@PathVariable("idClient") Long idClient, @RequestBody ParamLoggedIdUserDTO paramLoggedIdUser) {
        int result = clientService.deleteClient(idClient, paramLoggedIdUser.getParamLoggedIdUser());

        switch (result) {
            case 1 -> {
                ApiResponse<String> response = new ApiResponse<>("Cliente eliminado correctamente.", null);
                return new ResponseEntity<>(response, HttpStatus.OK);
            }
            case 0 ->
                throw new AppException("Ocurrió un error al eliminar el cliente.", HttpStatus.INTERNAL_SERVER_ERROR);
            case -1 ->
                throw new AppException("No se pudo eliminar el cliente porque no se encuentra el registro.", HttpStatus.INTERNAL_SERVER_ERROR);
            default ->
                throw new AppException("Cliente no eliminado debido a problemas en la consulta.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
