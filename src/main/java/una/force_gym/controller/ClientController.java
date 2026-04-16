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
            @RequestParam(defaultValue = "-1") int filterByClientType
    ) {
        try {
            Map<String, Object> responseData = clientService.getClients(page, size, searchType, searchTerm, orderBy, directionOrderBy, filterByStatus, filterByDiabetes, filterByHypertension, filterByMuscleInjuries, filterByBoneJointIssues, filterByBalanceLoss, filterByCardiovascularDisease, filterByBreathingIssues, filterByDateBirthStart, filterByDateBirthEnd, filterByClientType);
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
                clientDTO.getIdClientType(),
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

    @DeleteMapping("/delete-permanent/{idClient}")
    public ResponseEntity<ApiResponse<String>> deleteClientPermanently(@PathVariable("idClient") Long idClient, @RequestBody ParamLoggedIdUserDTO paramLoggedIdUser) {
        try {
            clientService.deleteClientPermanently(idClient, paramLoggedIdUser.getParamLoggedIdUser());
            ApiResponse<String> response = new ApiResponse<>("Cliente eliminado permanentemente.", null);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e) {
            // Retornar BAD_REQUEST para errores de validación de negocio (como cliente con ingresos)
            ApiResponse<String> response = new ApiResponse<>(e.getMessage(), null);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/membership-expirations")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getMembershipExpirations(
            @RequestParam int year,
            @RequestParam int month
    ) {
        try {
            List<Client> clients = clientService.getClientsByMembershipExpiration(year, month);
            
            // Agrupar clientes por día de vencimiento
            Map<Integer, List<Map<String, Object>>> clientsByDay = new HashMap<>();
            
            for (Client client : clients) {
                if (client.getExpirationMembershipDate() != null) {
                    // Convertir Date a LocalDate para obtener el día
                    LocalDate expirationDate = new java.sql.Date(client.getExpirationMembershipDate().getTime()).toLocalDate();
                    int day = expirationDate.getDayOfMonth();
                    
                    Map<String, Object> clientInfo = new HashMap<>();
                    clientInfo.put("idClient", client.getIdClient());
                    clientInfo.put("name", client.getPerson().getName() + " " + client.getPerson().getFirstLastName());
                    clientInfo.put("phone", client.getPerson().getPhoneNumber());
                    clientInfo.put("email", client.getPerson().getEmail());
                    clientInfo.put("expirationDate", expirationDate.toString());
                    clientInfo.put("clientType", client.getClientType() != null ? client.getClientType().getName() : "N/A");
                    
                    clientsByDay.computeIfAbsent(day, k -> new ArrayList<>()).add(clientInfo);
                }
            }
            
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("clientsByDay", clientsByDay);
            responseData.put("year", year);
            responseData.put("month", month);
            responseData.put("totalClients", clients.size());
            
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Vencimientos de membresía obtenidos correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK);
            
        } catch (RuntimeException e) {
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Error al obtener vencimientos de membresía: " + e.getMessage(), null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/birthdays")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getClientBirthdays(
            @RequestParam int year,
            @RequestParam int month
    ) {
        try {
            List<Client> clients = clientService.getClientsByBirthday(month);
            
            // Agrupar clientes por día de cumpleaños
            Map<Integer, List<Map<String, Object>>> clientsByDay = new HashMap<>();
            
            for (Client client : clients) {
                if (client.getPerson() != null && client.getPerson().getBirthday() != null) {
                    LocalDate birthday = client.getPerson().getBirthday();
                    int day = birthday.getDayOfMonth();
                    
                    // Calcular edad
                    LocalDate currentDate = LocalDate.of(year, month, day);
                    int age = currentDate.getYear() - birthday.getYear();
                    
                    Map<String, Object> clientInfo = new HashMap<>();
                    clientInfo.put("idClient", client.getIdClient());
                    clientInfo.put("name", client.getPerson().getName() + " " + client.getPerson().getFirstLastName());
                    clientInfo.put("phone", client.getPerson().getPhoneNumber());
                    clientInfo.put("email", client.getPerson().getEmail());
                    clientInfo.put("birthday", birthday.toString());
                    clientInfo.put("clientType", client.getClientType() != null ? client.getClientType().getName() : "N/A");
                    clientInfo.put("age", age);
                    
                    clientsByDay.computeIfAbsent(day, k -> new ArrayList<>()).add(clientInfo);
                }
            }
            
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("clientsByDay", clientsByDay);
            responseData.put("year", year);
            responseData.put("month", month);
            responseData.put("totalClients", clients.size());
            
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Cumpleaños obtenidos correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK);
            
        } catch (RuntimeException e) {
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Error al obtener cumpleaños: " + e.getMessage(), null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/expiration-reminders")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getExpirationReminders(
            @RequestParam int year,
            @RequestParam int month
    ) {
        try {
            List<Client> clients = clientService.getClientsByMembershipExpiration(year, month);
            
            // Agrupar clientes por el día ANTERIOR a su vencimiento
            // Si vence el día 15, aparece en el día 14 (para recordar un día antes)
            Map<Integer, List<Map<String, Object>>> clientsByDay = new HashMap<>();
            
            for (Client client : clients) {
                if (client.getExpirationMembershipDate() != null) {
                    LocalDate expirationDate = new java.sql.Date(client.getExpirationMembershipDate().getTime()).toLocalDate();
                    
                    // Calcular el día anterior (día del recordatorio)
                    LocalDate reminderDate = expirationDate.minusDays(1);
                    
                    // Solo incluir si el día del recordatorio está en el mes solicitado
                    if (reminderDate.getYear() == year && reminderDate.getMonthValue() == month) {
                        int reminderDay = reminderDate.getDayOfMonth();
                        
                        Map<String, Object> clientInfo = new HashMap<>();
                        clientInfo.put("idClient", client.getIdClient());
                        clientInfo.put("name", client.getPerson().getName() + " " + client.getPerson().getFirstLastName());
                        clientInfo.put("phone", client.getPerson().getPhoneNumber());
                        clientInfo.put("email", client.getPerson().getEmail());
                        clientInfo.put("expirationDate", expirationDate.toString());
                        clientInfo.put("clientType", client.getClientType() != null ? client.getClientType().getName() : "N/A");
                        
                        clientsByDay.computeIfAbsent(reminderDay, k -> new ArrayList<>()).add(clientInfo);
                    }
                }
            }
            
            Map<String, Object> responseData = new HashMap<>();
            responseData.put("clientsByDay", clientsByDay);
            responseData.put("year", year);
            responseData.put("month", month);
            responseData.put("totalClients", clientsByDay.values().stream().mapToInt(List::size).sum());
            
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Recordatorios de vencimiento obtenidos correctamente.", responseData);
            return new ResponseEntity<>(response, HttpStatus.OK);
            
        } catch (RuntimeException e) {
            ApiResponse<Map<String, Object>> response = new ApiResponse<>("Error al obtener recordatorios: " + e.getMessage(), null);
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
