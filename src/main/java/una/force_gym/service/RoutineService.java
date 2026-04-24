package una.force_gym.service;

import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import una.force_gym.domain.DifficultyRoutine;
import una.force_gym.domain.Exercise;
import una.force_gym.domain.Routine;
import una.force_gym.domain.RoutineAssignment;
import una.force_gym.domain.RoutineExercise;
import una.force_gym.domain.User;
import una.force_gym.dto.RoutineAssignmentDTO;
import una.force_gym.dto.RoutineExerciseDTO;
import una.force_gym.dto.RoutineWithExercisesDTO;
import una.force_gym.repository.ClientRepository;
import una.force_gym.repository.DifficultyRoutineRepository;
import una.force_gym.repository.ExerciseRepository;
import una.force_gym.repository.RoutineAssignmentRepository;
import una.force_gym.repository.RoutineExerciseRepository;
import una.force_gym.repository.RoutineRepository;
import una.force_gym.repository.UserRepository;

@Service
public class RoutineService {

    @Autowired
    private RoutineRepository routineRepository;

    @Autowired
    private RoutineExerciseRepository routineExerciseRepository;

    @Autowired
    private RoutineAssignmentRepository routineAssignmentRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private DifficultyRoutineRepository difficultyRoutineRepository;

    @Autowired
    private ExerciseRepository exerciseRepository;

    @Transactional
    public RoutineWithExercisesDTO saveWithExercisesAndClients(RoutineWithExercisesDTO dto) {
        validateRoutineDTO(dto);

        if (routineRepository.existsByNameAndUser_IdUserAndIsDeleted(dto.getName(), dto.getIdUser(), 0L)) {
            throw new RuntimeException("Ya existe una rutina con el nombre '" + dto.getName() + "' para este usuario");
        }

        Routine routine = createRoutineFromDTO(dto);
        Routine savedRoutine = routineRepository.save(routine);

        saveRoutineExercises(savedRoutine, dto.getExercises());

        if (dto.getAssignments() != null && !dto.getAssignments().isEmpty()) {
            saveRoutineAssignments(savedRoutine, dto.getAssignments());
        }

        return mapRoutineToDTO(savedRoutine);
    }

    @Transactional
    public RoutineWithExercisesDTO updateWithExercisesAndClients(RoutineWithExercisesDTO dto) {
        if (dto.getIdRoutine() == null) {
            throw new RuntimeException("Se requiere ID de rutina para actualización");
        }

        validateRoutineDTO(dto);

        Routine routine = routineRepository.findById(dto.getIdRoutine())
                .orElseThrow(() -> new RuntimeException("Rutina no encontrada con ID: " + dto.getIdRoutine()));

        if (!routine.getName().equals(dto.getName())) {
            if (routineRepository.existsByNameAndUser_IdUserAndIsDeleted(dto.getName(), dto.getIdUser(), 0L)) {
                throw new RuntimeException("Ya existe una rutina con el nombre '" + dto.getName() + "' para este usuario");
            }
        }

        updateRoutineFromDTO(routine, dto);
        Routine updatedRoutine = routineRepository.save(routine);

        updateRoutineRelations(updatedRoutine, dto);

        return mapRoutineToDTO(updatedRoutine);
    }

    private void updateRoutineFromDTO(Routine routine, RoutineWithExercisesDTO dto) {
        routine.setName(dto.getName());
        routine.setDate(dto.getDate());

        User user = userRepository.findById(dto.getIdUser())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado con ID: " + dto.getIdUser()));
        routine.setUser(user);

        DifficultyRoutine difficulty = difficultyRoutineRepository.findById(dto.getDifficultyRoutine().getIdDifficultyRoutine())
                .orElseThrow(() -> new RuntimeException("Dificultad no encontrada con ID: " + dto.getDifficultyRoutine().getIdDifficultyRoutine()));
        routine.setDifficultyRoutine(difficulty);

        routine.setUpdatedAt(new Timestamp(System.currentTimeMillis()));
        routine.setUpdatedByUser(dto.getIdUser());
    }

    private void updateRoutineRelations(Routine routine, RoutineWithExercisesDTO dto) {
        // ACTUALIZACIÓN INTELIGENTE DE EJERCICIOS
        // En lugar de eliminar todos y recrear, actualizamos los existentes para preservar los IDs
        // Esto mantiene las notas personales de los clientes vinculadas a idRoutineExercise
        
        // Obtener ejercicios actuales de la rutina
        List<RoutineExercise> existingExercises = routineExerciseRepository.findByRoutine_IdRoutine(routine.getIdRoutine());
        
        // Crear un mapa para búsqueda rápida de ejercicios existentes
        // Clave: idExercise_dayNumber_categoryOrder (identifica un ejercicio único)
        Map<String, RoutineExercise> existingExercisesMap = existingExercises.stream()
                .collect(Collectors.toMap(
                    ex -> ex.getExercise().getIdExercise() + "_" + 
                          (ex.getDayNumber() != null ? ex.getDayNumber() : 1) + "_" + 
                          ex.getCategoryOrder(),
                    ex -> ex
                ));

        // Lista de ejercicios que se deben mantener (actualizar o crear)
        Set<String> exercisesToKeep = new HashSet<>();

        // Procesar ejercicios del DTO
        for (RoutineExerciseDTO exDto : dto.getExercises()) {
            validateExerciseDTO(exDto);
            
            String key = exDto.getIdExercise() + "_" + 
                        (exDto.getDayNumber() != null ? exDto.getDayNumber() : 1) + "_" + 
                        exDto.getCategoryOrder();
            
            exercisesToKeep.add(key);

            RoutineExercise existingExercise = existingExercisesMap.get(key);

            if (existingExercise != null) {
                // ACTUALIZAR ejercicio existente (preserva el idRoutineExercise y las notas)
                existingExercise.setSeries(exDto.getSeries());
                existingExercise.setRepetitions(exDto.getRepetitions());
                existingExercise.setNote(exDto.getNote());
                existingExercise.setCategoryOrder(exDto.getCategoryOrder());
                existingExercise.setDayNumber(exDto.getDayNumber() != null ? exDto.getDayNumber() : 1);
                routineExerciseRepository.save(existingExercise);
            } else {
                // CREAR nuevo ejercicio
                RoutineExercise newExercise = new RoutineExercise();
                newExercise.setRoutine(routine);
                
                Exercise exercise = exerciseRepository.findById(exDto.getIdExercise())
                        .orElseThrow(() -> new RuntimeException("Ejercicio no encontrado con ID: " + exDto.getIdExercise()));
                newExercise.setExercise(exercise);
                
                newExercise.setSeries(exDto.getSeries());
                newExercise.setRepetitions(exDto.getRepetitions());
                newExercise.setNote(exDto.getNote());
                newExercise.setCategoryOrder(exDto.getCategoryOrder());
                newExercise.setDayNumber(exDto.getDayNumber() != null ? exDto.getDayNumber() : 1);
                
                routineExerciseRepository.save(newExercise);
            }
        }

        // ELIMINAR solo los ejercicios que ya no están en el DTO
        for (Map.Entry<String, RoutineExercise> entry : existingExercisesMap.entrySet()) {
            if (!exercisesToKeep.contains(entry.getKey())) {
                routineExerciseRepository.delete(entry.getValue());
            }
        }

        // Solo actualizar asignaciones si se proporcionaron en el DTO
        // Si assignments es null o está vacío desde el frontend, no tocar las asignaciones existentes
        // Esto permite que el frontend use el endpoint específico /assign-clients
        if (dto.getAssignments() != null && !dto.getAssignments().isEmpty()) {
            routineAssignmentRepository.deleteByRoutineId(routine.getIdRoutine());
            saveRoutineAssignments(routine, dto.getAssignments());
        }
        // Si assignments es vacío, las asignaciones existentes se mantienen intactas
    }

    @Transactional(readOnly = true)
    public List<RoutineWithExercisesDTO> getAllRoutinesWithDetails() {
        List<Routine> routines = routineRepository.findAll();

        return routines.stream()
                .filter(routine -> routine.getIsDeleted() == 0)
                .map(this::mapRoutineToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public RoutineWithExercisesDTO getRoutineWithDetails(Long id) {
        Routine routine = routineRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Rutina no encontrada con ID: " + id));

        return mapRoutineToDTO(routine);
    }

    @Transactional
    public void deleteRoutineWithDependencies(Long id) {
        if (!routineRepository.existsById(id)) {
            throw new RuntimeException("Rutina no encontrada con ID: " + id);
        }

        routineExerciseRepository.deleteByRoutineId(id);
        routineAssignmentRepository.deleteByRoutineId(id);
        routineRepository.deleteById(id);
    }

    @Transactional(readOnly = true)
    public List<RoutineWithExercisesDTO> getRoutinesByClient(Long clientId) {
        if (!clientRepository.existsById(clientId)) {
            throw new RuntimeException("Cliente no encontrado con ID: " + clientId);
        }

        return routineAssignmentRepository.findByClient_IdClient(clientId).stream()
                .map(RoutineAssignment::getRoutine)
                .filter(routine -> routine.getIsDeleted() == 0)
                .map(this::mapRoutineToDTO)
                .collect(Collectors.toList());
    }

    private void validateRoutineDTO(RoutineWithExercisesDTO dto) {
        if (dto == null) {
            throw new RuntimeException("Los datos de la rutina no pueden ser nulos");
        }

        if (dto.getName() == null || dto.getName().trim().isEmpty()) {
            throw new RuntimeException("El nombre de la rutina no puede estar vacío");
        }

        if (dto.getExercises() == null || dto.getExercises().isEmpty()) {
            throw new RuntimeException("Debe incluir al menos un ejercicio");
        }

        if (dto.getIdUser() == null || !userRepository.existsById(dto.getIdUser())) {
            throw new RuntimeException("Usuario no válido");
        }
    }

    private Routine createRoutineFromDTO(RoutineWithExercisesDTO dto) {
        Routine routine = new Routine();
        routine.setName(dto.getName());
        routine.setDate(dto.getDate());
        routine.setIsDeleted(0L);
        routine.setCreatedByUser(dto.getIdUser());
        routine.setCreatedAt(new Timestamp(System.currentTimeMillis()));

        User user = userRepository.findById(dto.getIdUser())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado con ID: " + dto.getIdUser()));
        routine.setUser(user);

        DifficultyRoutine difficulty = difficultyRoutineRepository.findById(dto.getDifficultyRoutine().getIdDifficultyRoutine())
                .orElseThrow(() -> new RuntimeException("Dificultad no encontrada con ID: " + dto.getDifficultyRoutine().getIdDifficultyRoutine()));
        routine.setDifficultyRoutine(difficulty);

        return routine;
    }

    private void saveRoutineExercises(Routine routine, List<RoutineExerciseDTO> exerciseDTOs) {
        List<RoutineExercise> exercises = exerciseDTOs.stream()
                .map(exDto -> {
                    validateExerciseDTO(exDto);

                    RoutineExercise routineExercise = new RoutineExercise();
                    routineExercise.setRoutine(routine);

                    Exercise exercise = exerciseRepository.findById(exDto.getIdExercise())
                            .orElseThrow(() -> new RuntimeException("Ejercicio no encontrado con ID: " + exDto.getIdExercise()));
                    routineExercise.setExercise(exercise);

                    routineExercise.setSeries(exDto.getSeries());
                    routineExercise.setRepetitions(exDto.getRepetitions());
                    routineExercise.setNote(exDto.getNote());
                    routineExercise.setCategoryOrder(exDto.getCategoryOrder());
                    routineExercise.setDayNumber(exDto.getDayNumber() != null ? exDto.getDayNumber() : 1);
                    return routineExercise;
                })
                .collect(Collectors.toList());

        routineExerciseRepository.saveAll(exercises);
    }

    private void saveRoutineAssignments(Routine routine, List<RoutineAssignmentDTO> assignmentDTOs) {
        List<RoutineAssignment> assignments = assignmentDTOs.stream()
                .map(assignmentDto -> {
                    validateAssignmentDTO(assignmentDto);

                    RoutineAssignment assignment = new RoutineAssignment();
                    assignment.setRoutine(routine);
                    assignment.setClient(clientRepository.findById(assignmentDto.getIdClient())
                            .orElseThrow(() -> new RuntimeException("Cliente no encontrado con ID: " + assignmentDto.getIdClient())));
                    assignment.setAssignmentDate(assignmentDto.getAssignmentDate() != null
                            ? assignmentDto.getAssignmentDate() : getTodayLocalDate()); // Usar fecha local

                    return assignment;
                })
                .collect(Collectors.toList());

        routineAssignmentRepository.saveAll(assignments);
    }

    private void validateExerciseDTO(RoutineExerciseDTO exDto) {
        if (exDto.getSeries() == null || exDto.getSeries() < 1) {
            throw new RuntimeException("Las series deben ser al menos 1");
        }
        if (exDto.getRepetitions() == null || exDto.getRepetitions().trim().isEmpty()) {
            throw new RuntimeException("Las repeticiones son requeridas");
        }
        // Validar que repetitions sea un número positivo o "*" (al fallo)
        String reps = exDto.getRepetitions().trim();
        if (!reps.equals("*")) {
            try {
                int repsValue = Integer.parseInt(reps);
                if (repsValue < 1) {
                    throw new RuntimeException("Las repeticiones deben ser al menos 1 o '*' para indicar al fallo");
                }
            } catch (NumberFormatException e) {
                throw new RuntimeException("Las repeticiones deben ser un número positivo o '*' para indicar al fallo");
            }
        }
        if (exDto.getIdExercise() == null) {
            throw new RuntimeException("Debe especificar un ejercicio válido");
        }
    }

    private void validateAssignmentDTO(RoutineAssignmentDTO assignmentDto) {
        if (assignmentDto.getIdClient() == null) {
            throw new RuntimeException("Debe especificar un cliente");
        }
    }

    private RoutineWithExercisesDTO mapRoutineToDTO(Routine routine) {
        RoutineWithExercisesDTO dto = new RoutineWithExercisesDTO();
        dto.setIdRoutine(routine.getIdRoutine());
        dto.setName(routine.getName());
        dto.setDate(routine.getDate());
        dto.setIdUser(routine.getUser().getIdUser());
        dto.setDifficultyRoutine(routine.getDifficultyRoutine());
        dto.setIsDeleted(routine.getIsDeleted());

        // Mapear ejercicios
        List<RoutineExerciseDTO> exerciseDTOs = routineExerciseRepository.findByRoutine_IdRoutine(routine.getIdRoutine())
                .stream()
                .map(ex -> {
                    RoutineExerciseDTO exDto = new RoutineExerciseDTO();
                    exDto.setIdExercise(ex.getExercise().getIdExercise());
                    exDto.setSeries(ex.getSeries());
                    exDto.setRepetitions(ex.getRepetitions());
                    exDto.setNote(ex.getNote());
                    exDto.setCategoryOrder(ex.getCategoryOrder());
                    exDto.setDayNumber(ex.getDayNumber() != null ? ex.getDayNumber() : 1);
                    return exDto;
                })
                .collect(Collectors.toList());
        dto.setExercises(exerciseDTOs);

        // Mapear asignaciones a clientes
        List<RoutineAssignmentDTO> assignmentDTOs = routineAssignmentRepository.findByRoutine_IdRoutine(routine.getIdRoutine())
                .stream()
                .map(assignment -> {
                    RoutineAssignmentDTO assignmentDto = new RoutineAssignmentDTO();
                    assignmentDto.setIdRoutineAssignment(assignment.getIdRoutineAssignment());
                    assignmentDto.setIdClient(assignment.getClient().getIdClient());
                    assignmentDto.setAssignmentDate(assignment.getAssignmentDate());
                    return assignmentDto;
                })
                .collect(Collectors.toList());
        dto.setAssignments(assignmentDTOs);

        return dto;
    }

    /**
     * Asignar clientes a una rutina existente sin modificar los ejercicios
     * Preserva las notas personales de los clientes ya asignados
     */
    @Transactional
    public RoutineWithExercisesDTO assignClientsToRoutine(Long routineId, List<Long> clientIds) {
        // Validar que la rutina existe
        Routine routine = routineRepository.findById(routineId)
                .orElseThrow(() -> new RuntimeException("Rutina no encontrada con ID: " + routineId));

        if (routine.getIsDeleted() == 1) {
            throw new RuntimeException("No se puede asignar clientes a una rutina eliminada");
        }

        // Validar que hay clientes para asignar
        if (clientIds == null || clientIds.isEmpty()) {
            throw new RuntimeException("Debe proporcionar al menos un cliente para asignar");
        }

        // Obtener asignaciones actuales
        List<RoutineAssignment> currentAssignments = routineAssignmentRepository.findByRoutine_IdRoutine(routineId);
        List<Long> currentClientIds = currentAssignments.stream()
                .map(assignment -> assignment.getClient().getIdClient())
                .collect(Collectors.toList());

        // Determinar qué clientes agregar y cuáles remover
        List<Long> clientsToAdd = clientIds.stream()
                .filter(clientId -> !currentClientIds.contains(clientId))
                .collect(Collectors.toList());

        List<Long> clientsToRemove = currentClientIds.stream()
                .filter(clientId -> !clientIds.contains(clientId))
                .collect(Collectors.toList());

        // Agregar nuevos clientes
        for (Long clientId : clientsToAdd) {
            if (!clientRepository.existsById(clientId)) {
                throw new RuntimeException("Cliente no encontrado con ID: " + clientId);
            }

            RoutineAssignment newAssignment = new RoutineAssignment();
            newAssignment.setRoutine(routine);
            newAssignment.setClient(clientRepository.findById(clientId).orElseThrow());
            newAssignment.setAssignmentDate(getTodayLocalDate()); // Fecha local sin hora
            routineAssignmentRepository.save(newAssignment);
        }

        // Remover clientes que ya no están en la lista
        for (Long clientId : clientsToRemove) {
            currentAssignments.stream()
                    .filter(assignment -> assignment.getClient().getIdClient().equals(clientId))
                    .findFirst()
                    .ifPresent(routineAssignmentRepository::delete);
        }

        // Retornar la rutina actualizada con todas sus asignaciones
        return mapRoutineToDTO(routine);
    }

    /**
     * Obtener lista de clientes asignados a una rutina
     */
    @Transactional(readOnly = true)
    public List<Long> getAssignedClientIds(Long routineId) {
        if (!routineRepository.existsById(routineId)) {
            throw new RuntimeException("Rutina no encontrada con ID: " + routineId);
        }

        return routineAssignmentRepository.findByRoutine_IdRoutine(routineId)
                .stream()
                .map(assignment -> assignment.getClient().getIdClient())
                .collect(Collectors.toList());
    }

    /**
     * Obtiene la fecha actual como Date con hora 00:00:00 en la zona horaria local
     * Esto evita problemas de conversión UTC que causan cambios de día
     */
    private Date getTodayLocalDate() {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        calendar.set(Calendar.MILLISECOND, 0);
        return calendar.getTime();
    }
}
