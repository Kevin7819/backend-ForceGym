package una.force_gym.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import una.force_gym.domain.ClientExerciseNote;

public interface ClientExerciseNoteRepository extends JpaRepository<ClientExerciseNote, Long> {

    // Buscar nota por cliente y ejercicio de rutina
    Optional<ClientExerciseNote> findByClient_IdClientAndRoutineExercise_IdRoutineExercise(
            Long clientId, Long routineExerciseId);

    // Obtener todas las notas de un cliente
    List<ClientExerciseNote> findByClient_IdClient(Long clientId);

    // Obtener todas las notas de un cliente para una rutina específica
    @Query("SELECT cen FROM ClientExerciseNote cen " +
           "WHERE cen.client.idClient = :clientId " +
           "AND cen.routineExercise.routine.idRoutine = :routineId")
    List<ClientExerciseNote> findByClientIdAndRoutineId(
            @Param("clientId") Long clientId, 
            @Param("routineId") Long routineId);

    // Verificar si existe una nota para cliente y ejercicio
    boolean existsByClient_IdClientAndRoutineExercise_IdRoutineExercise(
            Long clientId, Long routineExerciseId);
}
