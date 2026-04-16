package una.force_gym.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import una.force_gym.config.UserAuthenticationProvider;
import una.force_gym.domain.Client;
import una.force_gym.domain.ClientExerciseNote;
import una.force_gym.domain.Measurement;
import una.force_gym.domain.RoutineAssignment;
import una.force_gym.domain.RoutineExercise;
import una.force_gym.dto.ClientCredentialsDTO;
import una.force_gym.dto.ClientExerciseNoteDTO;
import una.force_gym.dto.ClientLoginDTO;
import una.force_gym.dto.ChangeClientPasswordDTO;
import una.force_gym.dto.ForgotPasswordRequestDTO;
import una.force_gym.dto.ResetPasswordDTO;
import una.force_gym.repository.ClientRepository;
import una.force_gym.repository.ClientExerciseNoteRepository;
import una.force_gym.repository.RoutineExerciseRepository;
import una.force_gym.service.ClientAuthService;
import una.force_gym.service.PdfGeneratorService;
import una.force_gym.service.ExcelGeneratorService;
import una.force_gym.service.ClientPasswordResetService;
import una.force_gym.service.LoginAttemptService;
import una.force_gym.domain.ClientPasswordResetToken;
import una.force_gym.util.ApiResponse;
import una.force_gym.util.IpUtils;
import java.util.Optional;

@RestController
@RequestMapping("/client-portal")
public class ClientPortalController {

    @Autowired
    private ClientAuthService clientAuthService;

    @Autowired
    private PdfGeneratorService pdfGeneratorService;

    @Autowired
    private ExcelGeneratorService excelGeneratorService;

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private ClientExerciseNoteRepository clientExerciseNoteRepository;

    @Autowired
    private RoutineExerciseRepository routineExerciseRepository;

    @Autowired
    private UserAuthenticationProvider userAuthenticationProvider;

    @Autowired
    private ClientPasswordResetService clientPasswordResetService;

    @Autowired
    private LoginAttemptService loginAttemptService;

    /**
     * Endpoint para login de clientes usando número de cédula y contraseña
     */
    @PostMapping("/login")
    public ResponseEntity<?> loginClient(
            @RequestBody @Valid ClientCredentialsDTO credentials,
            HttpServletRequest request) {
        // Obtener IP del cliente
        String clientIp = IpUtils.getClientIp(request);
        
        try {
            // Verificar si la IP está bloqueada
            if (loginAttemptService.isBlocked(clientIp)) {
                long remainingTime = loginAttemptService.getRemainingBlockTime(clientIp);
                ApiResponse<String> errorResponse = new ApiResponse<>();
                errorResponse.setMessage(
                    String.format("Demasiados intentos fallidos. Por favor, intente nuevamente en %d minutos.", 
                    remainingTime)
                );
                return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(errorResponse);
            }

            ClientLoginDTO loginDTO = clientAuthService.login(credentials);
            
            // Login exitoso: limpiar intentos de esta IP
            loginAttemptService.loginSucceeded(clientIp);
            
            // Generar token usando el número de cédula como identificador
            String token = userAuthenticationProvider.createToken(credentials.getIdentificationNumber());
            loginDTO.setToken(token);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("loggedClient", loginDTO);
            responseData.put("message", "Login exitoso");

            ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>();
            apiResponse.setData(responseData);
            apiResponse.setMessage("Login exitoso");

            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            // Login fallido: registrar intento
            loginAttemptService.loginFailed(clientIp);
            
            int remainingAttempts = loginAttemptService.getRemainingAttempts(clientIp);
            String errorMessage = e.getMessage();
            
            if (remainingAttempts > 0) {
                errorMessage = String.format("%s. Intentos restantes: %d", errorMessage, remainingAttempts);
            } else {
                errorMessage = "Demasiados intentos fallidos. Cuenta bloqueada temporalmente por 5 minutos.";
            }
            
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage(errorMessage);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        }
    }

    /**
     * Endpoint para recuperación de contraseña de clientes
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(
            @RequestBody ForgotPasswordRequestDTO request, 
            HttpServletRequest httpRequest) {
        try {
            // Buscar cliente por email
            List<Client> allClients = clientRepository.findAll();
            Client client = allClients.stream()
                    .filter(c -> c.getPerson() != null && 
                               c.getPerson().getEmail() != null &&
                               c.getPerson().getEmail().equalsIgnoreCase(request.getEmail()) &&
                               Long.valueOf(0L).equals(c.getIsDeleted()))
                    .findFirst()
                    .orElse(null);

            if (client == null) {
                ApiResponse<String> responseNotFound = new ApiResponse<>("El correo electrónico no está registrado", null);
                return new ResponseEntity<>(responseNotFound, HttpStatus.BAD_REQUEST);
            }

            // Generar token y enviar email
            clientPasswordResetService.generateAndSendResetToken(client, httpRequest);

            ApiResponse<String> response = new ApiResponse<>("Se ha enviado un enlace de recuperación a tu correo electrónico", null);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>("Error al procesar la solicitud: " + e.getMessage(), null);
            return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Endpoint para restablecer la contraseña del cliente mediante token
     */
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<String>> resetPassword(
            @RequestBody ResetPasswordDTO request,
            HttpServletRequest httpRequest) {
        try {
            // 1. Validar token con todas las comprobaciones
            Optional<ClientPasswordResetToken> resetToken = clientPasswordResetService.validatePasswordResetToken(
                request.getToken(), 
                httpRequest
            );
            
            if (!resetToken.isPresent()) {
                ApiResponse<String> response = new ApiResponse<>("El enlace de recuperación no es válido o ha expirado. Por favor, solicita un nuevo enlace.", null);
                return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
            }
            
            // 2. Cambiar contraseña
            clientPasswordResetService.resetPassword(resetToken, request.getNewPassword());
            
            ApiResponse<String> response = new ApiResponse<>("Contraseña restablecida exitosamente", null);
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>("Error al restablecer la contraseña: " + e.getMessage(), null);
            return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Endpoint para obtener las rutinas del cliente autenticado
     */
    @GetMapping("/my-routines")
    public ResponseEntity<?> getMyRoutines(@RequestHeader("Authorization") String authHeader) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            List<RoutineAssignment> routines = clientAuthService.getClientRoutines(clientId);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("routines", routines);
            responseData.put("totalRecords", routines.size());

            ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>();
            apiResponse.setData(responseData);
            apiResponse.setMessage("Rutinas obtenidas exitosamente");

            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al obtener rutinas: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para obtener las medidas del cliente autenticado
     */
    @GetMapping("/my-measurements")
    public ResponseEntity<?> getMyMeasurements(@RequestHeader("Authorization") String authHeader) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            List<Measurement> measurements = clientAuthService.getClientMeasurements(clientId);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("measurements", measurements);
            responseData.put("totalRecords", measurements.size());

            ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>();
            apiResponse.setData(responseData);
            apiResponse.setMessage("Medidas obtenidas exitosamente");

            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al obtener medidas: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para descargar PDF de rutinas
     */
    @GetMapping("/download-routines-pdf")
    public ResponseEntity<?> downloadRoutinesPdf(@RequestHeader("Authorization") String authHeader) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            Client client = clientRepository.findById(clientId)
                    .orElseThrow(() -> new Exception("Cliente no encontrado"));
            
            List<RoutineAssignment> routines = clientAuthService.getClientRoutines(clientId);
            
            byte[] pdfBytes = pdfGeneratorService.generateRoutinesPdf(client, routines);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", "mis_rutinas.pdf");

            return new ResponseEntity<>(pdfBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al generar PDF: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para descargar PDF de una rutina específica
     */
    @GetMapping("/download-routine-pdf/{idRoutineAssignment}")
    public ResponseEntity<?> downloadSingleRoutinePdf(
            @RequestHeader("Authorization") String authHeader,
            @PathVariable Long idRoutineAssignment) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            Client client = clientRepository.findById(clientId)
                    .orElseThrow(() -> new Exception("Cliente no encontrado"));
            
            // Obtener todas las rutinas del cliente y filtrar la específica
            List<RoutineAssignment> allRoutines = clientAuthService.getClientRoutines(clientId);
            
            RoutineAssignment specificRoutine = allRoutines.stream()
                    .filter(r -> r.getIdRoutineAssignment().equals(idRoutineAssignment))
                    .findFirst()
                    .orElseThrow(() -> new Exception("Rutina no encontrada o no pertenece al cliente"));
            
            // Generar PDF solo con esta rutina
            List<RoutineAssignment> singleRoutineList = java.util.Collections.singletonList(specificRoutine);
            byte[] pdfBytes = pdfGeneratorService.generateRoutinesPdf(client, singleRoutineList);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            
            // Sanitizar el nombre del archivo para evitar caracteres problemáticos
            String routineName = specificRoutine.getRoutine().getName();
            if (routineName == null || routineName.trim().isEmpty()) {
                routineName = "rutina";
            }
            // Eliminar caracteres especiales y reemplazar espacios
            String safeFilename = routineName
                .replaceAll("[^a-zA-Z0-9\\s-_]", "")
                .replaceAll("\\s+", "_")
                .toLowerCase();
            String filename = "rutina_" + safeFilename + ".pdf";
            
            headers.setContentDispositionFormData("attachment", filename);

            return new ResponseEntity<>(pdfBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al generar PDF: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para descargar PDF de medidas
     */
    @GetMapping("/download-measurements-pdf")
    public ResponseEntity<?> downloadMeasurementsPdf(@RequestHeader("Authorization") String authHeader) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            Client client = clientRepository.findById(clientId)
                    .orElseThrow(() -> new Exception("Cliente no encontrado"));
            
            List<Measurement> measurements = clientAuthService.getClientMeasurements(clientId);
            
            byte[] pdfBytes = pdfGeneratorService.generateMeasurementsPdf(client, measurements);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            headers.setContentDispositionFormData("attachment", "mis_medidas.pdf");

            return new ResponseEntity<>(pdfBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al generar PDF: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para descargar Excel de medidas
     */
    @GetMapping("/download-measurements-excel")
    public ResponseEntity<?> downloadMeasurementsExcel(@RequestHeader("Authorization") String authHeader) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            Client client = clientRepository.findById(clientId)
                    .orElseThrow(() -> new Exception("Cliente no encontrado"));
            
            List<Measurement> measurements = clientAuthService.getClientMeasurements(clientId);
            
            byte[] excelBytes = excelGeneratorService.generateMeasurementsExcel(client, measurements);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDispositionFormData("attachment", "mis_medidas.xlsx");

            return new ResponseEntity<>(excelBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al generar Excel: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para verificar si el cliente usa contraseña provisional
     */
    @GetMapping("/has-provisional-password")
    public ResponseEntity<?> hasProvisionalPassword(@RequestHeader("Authorization") String authHeader) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            boolean isProvisional = clientAuthService.hasProvisionalPassword(clientId);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("hasProvisionalPassword", isProvisional);

            ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>();
            apiResponse.setData(responseData);
            apiResponse.setMessage("Estado de contraseña obtenido");

            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al verificar contraseña: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para cambiar la contraseña del cliente
     */
    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody @Valid ChangeClientPasswordDTO changePasswordDTO) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            // Validar que las nuevas contraseñas coincidan
            if (!changePasswordDTO.getNewPassword().equals(changePasswordDTO.getConfirmPassword())) {
                ApiResponse<String> errorResponse = new ApiResponse<>();
                errorResponse.setMessage("Las contraseñas no coinciden");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Validar longitud mínima
            if (changePasswordDTO.getNewPassword().length() < 6) {
                ApiResponse<String> errorResponse = new ApiResponse<>();
                errorResponse.setMessage("La contraseña debe tener al menos 6 caracteres");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Verificar contraseña actual antes de cambiar
            Client client = clientRepository.findById(clientId)
                    .orElseThrow(() -> new Exception("Cliente no encontrado"));
            
            ClientCredentialsDTO credentials = new ClientCredentialsDTO(
                client.getPerson().getIdentificationNumber(),
                changePasswordDTO.getCurrentPassword()
            );
            
            // Esto lanzará excepción si la contraseña actual es incorrecta
            clientAuthService.login(credentials);

            // Cambiar la contraseña
            clientAuthService.changePassword(clientId, changePasswordDTO.getNewPassword());

            ApiResponse<String> apiResponse = new ApiResponse<>();
            apiResponse.setMessage("Contraseña cambiada exitosamente");

            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al cambiar contraseña: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

    /**
     * Endpoint para obtener todas las notas personales del cliente para una rutina específica
     */
    @GetMapping("/exercise-notes/{idRoutine}")
    public ResponseEntity<?> getExerciseNotes(
            @RequestHeader("Authorization") String authHeader,
            @PathVariable Long idRoutine) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            List<ClientExerciseNote> notes = clientExerciseNoteRepository.findByClientIdAndRoutineId(clientId, idRoutine);

            // Convertir a DTOs para respuesta más limpia
            List<ClientExerciseNoteDTO> noteDTOs = notes.stream()
                    .map(note -> new ClientExerciseNoteDTO(
                            note.getIdClientExerciseNote(),
                            note.getClient().getIdClient(),
                            note.getRoutineExercise().getIdRoutineExercise(),
                            note.getPersonalNote()
                    ))
                    .collect(java.util.stream.Collectors.toList());

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("notes", noteDTOs);
            responseData.put("totalRecords", noteDTOs.size());

            ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>();
            apiResponse.setData(responseData);
            apiResponse.setMessage("Notas obtenidas exitosamente");

            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al obtener notas: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para obtener todas las notas personales del cliente
     */
    @GetMapping("/exercise-notes")
    public ResponseEntity<?> getAllExerciseNotes(@RequestHeader("Authorization") String authHeader) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            List<ClientExerciseNote> notes = clientExerciseNoteRepository.findByClient_IdClient(clientId);

            // Convertir a DTOs para respuesta más limpia
            List<ClientExerciseNoteDTO> noteDTOs = notes.stream()
                    .map(note -> new ClientExerciseNoteDTO(
                            note.getIdClientExerciseNote(),
                            note.getClient().getIdClient(),
                            note.getRoutineExercise().getIdRoutineExercise(),
                            note.getPersonalNote()
                    ))
                    .collect(java.util.stream.Collectors.toList());

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("notes", noteDTOs);
            responseData.put("totalRecords", noteDTOs.size());

            ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>();
            apiResponse.setData(responseData);
            apiResponse.setMessage("Notas obtenidas exitosamente");

            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al obtener notas: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para guardar o actualizar una nota personal de ejercicio
     */
    @PostMapping("/exercise-notes")
    public ResponseEntity<?> saveExerciseNote(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody ClientExerciseNoteDTO noteDTO) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            // Verificar que el ejercicio existe
            RoutineExercise routineExercise = routineExerciseRepository.findById(noteDTO.getIdRoutineExercise())
                    .orElseThrow(() -> new Exception("Ejercicio de rutina no encontrado"));
            
            // Verificar que el cliente tiene acceso a esta rutina (pertenece a una de sus asignaciones)
            List<RoutineAssignment> clientRoutines = clientAuthService.getClientRoutines(clientId);
            boolean hasAccess = clientRoutines.stream()
                    .anyMatch(ra -> ra.getRoutine().getIdRoutine().equals(routineExercise.getRoutine().getIdRoutine()));
            
            if (!hasAccess) {
                ApiResponse<String> errorResponse = new ApiResponse<>();
                errorResponse.setMessage("No tienes acceso a este ejercicio");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
            }
            
            // Obtener cliente
            Client client = clientRepository.findById(clientId)
                    .orElseThrow(() -> new Exception("Cliente no encontrado"));
            
            // Buscar si ya existe una nota para este cliente y ejercicio
            Optional<ClientExerciseNote> existingNote = clientExerciseNoteRepository
                    .findByClient_IdClientAndRoutineExercise_IdRoutineExercise(clientId, noteDTO.getIdRoutineExercise());
            
            ClientExerciseNote note;
            if (existingNote.isPresent()) {
                // Actualizar nota existente
                note = existingNote.get();
                note.setPersonalNote(noteDTO.getPersonalNote());
            } else {
                // Crear nueva nota
                note = new ClientExerciseNote(client, routineExercise, noteDTO.getPersonalNote());
            }
            
            note = clientExerciseNoteRepository.save(note);
            
            ClientExerciseNoteDTO responseDTO = new ClientExerciseNoteDTO(
                    note.getIdClientExerciseNote(),
                    note.getClient().getIdClient(),
                    note.getRoutineExercise().getIdRoutineExercise(),
                    note.getPersonalNote()
            );

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("note", responseDTO);

            ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>();
            apiResponse.setData(responseData);
            apiResponse.setMessage("Nota guardada exitosamente");

            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al guardar nota: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para eliminar una nota personal de ejercicio
     */
    @PostMapping("/exercise-notes/delete/{idRoutineExercise}")
    public ResponseEntity<?> deleteExerciseNote(
            @RequestHeader("Authorization") String authHeader,
            @PathVariable Long idRoutineExercise) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            // Buscar la nota
            Optional<ClientExerciseNote> existingNote = clientExerciseNoteRepository
                    .findByClient_IdClientAndRoutineExercise_IdRoutineExercise(clientId, idRoutineExercise);
            
            if (!existingNote.isPresent()) {
                ApiResponse<String> errorResponse = new ApiResponse<>();
                errorResponse.setMessage("Nota no encontrada");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
            }
            
            clientExerciseNoteRepository.delete(existingNote.get());

            ApiResponse<String> apiResponse = new ApiResponse<>();
            apiResponse.setMessage("Nota eliminada exitosamente");

            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al eliminar nota: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para obtener los datos actualizados del perfil del cliente
     * Esto incluye la fecha de expiración de membresía actualizada
     */
    @GetMapping("/my-profile")
    public ResponseEntity<?> getMyProfile(@RequestHeader("Authorization") String authHeader) {
        try {
            Long clientId = extractClientIdFromToken(authHeader);
            
            Client client = clientRepository.findById(clientId)
                    .orElseThrow(() -> new Exception("Cliente no encontrado"));
            
            ClientLoginDTO profileDTO = new ClientLoginDTO();
            profileDTO.setIdClient(client.getIdClient());
            profileDTO.setPerson(client.getPerson());
            profileDTO.setExpirationMembershipDate(client.getExpirationMembershipDate());
            profileDTO.setRegistrationDate(client.getRegistrationDate());

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("profile", profileDTO);

            ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>();
            apiResponse.setData(responseData);
            apiResponse.setMessage("Perfil obtenido exitosamente");

            return ResponseEntity.ok(apiResponse);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al obtener perfil: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Extrae el ID del cliente del token de autorización
     */
    private Long extractClientIdFromToken(String authHeader) throws Exception {
        // Extraer el número de cédula del token
        String token = authHeader.replace("Bearer ", "");
        String identificationNumber = userAuthenticationProvider.getUsernameFromToken(token);
        
        // Buscar el cliente por número de cédula
        List<Client> allClients = clientRepository.findAll();
        
        Client client = allClients.stream()
                .filter(c -> {
                    boolean hasPersonAndId = c.getPerson() != null && c.getPerson().getIdentificationNumber() != null;
                    boolean matchesId = hasPersonAndId && c.getPerson().getIdentificationNumber().equals(identificationNumber);
                    boolean notDeleted = Long.valueOf(0L).equals(c.getIsDeleted());
                    
                    return hasPersonAndId && matchesId && notDeleted;
                })
                .findFirst()
                .orElseThrow(() -> new Exception("Cliente no encontrado"));
        
        return client.getIdClient();
    }
}
