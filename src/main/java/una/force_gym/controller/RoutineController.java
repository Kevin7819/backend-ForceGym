package una.force_gym.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import una.force_gym.domain.Client;
import una.force_gym.domain.Routine;
import una.force_gym.domain.RoutineAssignment;
import una.force_gym.dto.RoutineWithExercisesDTO;
import una.force_gym.repository.RoutineAssignmentRepository;
import una.force_gym.repository.RoutineRepository;
import una.force_gym.service.PdfGeneratorService;
import una.force_gym.service.RoutineService;
import una.force_gym.util.ApiResponse;

import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/routine")
public class RoutineController {

    @Autowired
    private RoutineService routineService;

    @Autowired
    private PdfGeneratorService pdfGeneratorService;

    @Autowired
    private RoutineAssignmentRepository routineAssignmentRepository;

    @Autowired
    private RoutineRepository routineRepository;

    @PostMapping("/add")
    public ResponseEntity<ApiResponse<RoutineWithExercisesDTO>> createRoutineWithExercisesAndClients(
            @RequestBody RoutineWithExercisesDTO routineDTO) {
        try {
            RoutineWithExercisesDTO createdRoutine = routineService.saveWithExercisesAndClients(routineDTO);
            ApiResponse<RoutineWithExercisesDTO> response = new ApiResponse<>(
                    "Rutina creada correctamente con ejercicios y asignaciones de clientes.",
                    createdRoutine
            );
            return new ResponseEntity<>(response, HttpStatus.CREATED);
        } catch (RuntimeException e) {
            ApiResponse<RoutineWithExercisesDTO> response = new ApiResponse<>(
                    "Error al crear la rutina: " + e.getMessage(),
                    null
            );
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    @PutMapping("/update")
    public ResponseEntity<ApiResponse<RoutineWithExercisesDTO>> updateRoutineWithExercisesAndClients(
            @RequestBody RoutineWithExercisesDTO routineDTO) {
        try {
            RoutineWithExercisesDTO updatedRoutine = routineService.updateWithExercisesAndClients(routineDTO);
            ApiResponse<RoutineWithExercisesDTO> response = new ApiResponse<>(
                    "Rutina actualizada correctamente con ejercicios y asignaciones de clientes.",
                    updatedRoutine
            );
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e) {
            ApiResponse<RoutineWithExercisesDTO> response = new ApiResponse<>(
                    "Error al actualizar la rutina: " + e.getMessage(),
                    null
            );
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/list")
    public ResponseEntity<ApiResponse<List<RoutineWithExercisesDTO>>> getAllRoutinesWithDetails() {
        try {
            List<RoutineWithExercisesDTO> routines = routineService.getAllRoutinesWithDetails();
            ApiResponse<List<RoutineWithExercisesDTO>> response = new ApiResponse<>(
                    "Rutinas obtenidas correctamente con sus detalles.",
                    routines
            );
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e) {
            ApiResponse<List<RoutineWithExercisesDTO>> response = new ApiResponse<>(
                    "Error al obtener las rutinas: " + e.getMessage(),
                    null
            );
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<RoutineWithExercisesDTO>> getRoutineWithDetails(@PathVariable Long id) {
        try {
            RoutineWithExercisesDTO routine = routineService.getRoutineWithDetails(id);
            ApiResponse<RoutineWithExercisesDTO> response = new ApiResponse<>(
                    "Rutina obtenida correctamente con sus detalles.",
                    routine
            );
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e) {
            ApiResponse<RoutineWithExercisesDTO> response = new ApiResponse<>(
                    "Error al obtener la rutina: " + e.getMessage(),
                    null
            );
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<ApiResponse<List<RoutineWithExercisesDTO>>> deleteRoutineWithDependencies(@PathVariable Long id) {
        try {
            routineService.deleteRoutineWithDependencies(id); // Elimina la rutina
            List<RoutineWithExercisesDTO> updatedRoutines = routineService.getAllRoutinesWithDetails(); // Obtiene la lista actualizada
            ApiResponse<List<RoutineWithExercisesDTO>> response = new ApiResponse<>(
                    "Rutina eliminada correctamente con todas sus dependencias.",
                    updatedRoutines // Devuelve la lista actualizada
            );
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e) {
            ApiResponse<List<RoutineWithExercisesDTO>> response = new ApiResponse<>(
                    "Error al eliminar la rutina: " + e.getMessage(),
                    null
            );
            return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/client/{clientId}")
    public ResponseEntity<ApiResponse<List<RoutineWithExercisesDTO>>> getRoutinesByClient(
            @PathVariable Long clientId) {
        try {
            List<RoutineWithExercisesDTO> routines = routineService.getRoutinesByClient(clientId);
            ApiResponse<List<RoutineWithExercisesDTO>> response = new ApiResponse<>(
                    "Rutinas del cliente obtenidas correctamente.",
                    routines
            );
            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (RuntimeException e) {
            ApiResponse<List<RoutineWithExercisesDTO>> response = new ApiResponse<>(
                    "Error al obtener las rutinas del cliente: " + e.getMessage(),
                    null
            );
            return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Endpoint para descargar PDF de una rutina específica asignada a un cliente
     * Usado por el sistema administrativo
     */
    @GetMapping("/download-routine-pdf/{idRoutineAssignment}")
    public ResponseEntity<?> downloadRoutinePdf(@PathVariable Long idRoutineAssignment) {
        try {
            // Obtener la asignación de rutina
            RoutineAssignment routineAssignment = routineAssignmentRepository.findById(idRoutineAssignment)
                    .orElseThrow(() -> new Exception("Asignación de rutina no encontrada"));

            // Obtener el cliente desde la asignación
            Client client = routineAssignment.getClient();
            if (client == null) {
                throw new Exception("Cliente no encontrado en la asignación");
            }

            // Generar PDF con la rutina específica (usando el mismo formato del portal del cliente)
            List<RoutineAssignment> singleRoutineList = Collections.singletonList(routineAssignment);
            byte[] pdfBytes = pdfGeneratorService.generateRoutinesPdf(client, singleRoutineList);

            // Configurar headers para descarga
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            String filename = "rutina_" + routineAssignment.getRoutine().getName().replaceAll("\\s+", "_") + ".pdf";
            headers.setContentDispositionFormData("attachment", filename);

            return new ResponseEntity<>(pdfBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al generar PDF: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Endpoint para descargar PDF de una rutina sin cliente asignado
     * Usado desde la página de gestión de rutinas
     */
    @GetMapping("/export-pdf/{idRoutine}")
    public ResponseEntity<?> exportRoutinePdf(@PathVariable Long idRoutine) {
        try {
            // Obtener la rutina
            Routine routine = routineRepository.findById(idRoutine)
                    .orElseThrow(() -> new Exception("Rutina no encontrada"));

            // Generar PDF sin cliente (formato igual al portal del cliente pero sin datos de cliente)
            byte[] pdfBytes = pdfGeneratorService.generateRoutinePdfWithoutClient(routine);

            // Configurar headers para descarga
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_PDF);
            String filename = "rutina_" + routine.getName().replaceAll("\\s+", "_") + ".pdf";
            headers.setContentDispositionFormData("attachment", filename);

            return new ResponseEntity<>(pdfBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            ApiResponse<String> errorResponse = new ApiResponse<>();
            errorResponse.setMessage("Error al generar PDF: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }
}
