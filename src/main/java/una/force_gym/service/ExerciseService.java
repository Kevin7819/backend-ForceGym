package una.force_gym.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.ParameterMode;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.StoredProcedureQuery;
import una.force_gym.domain.Exercise;
import una.force_gym.repository.ExerciseRepository;

@Service
public class ExerciseService {

    @Autowired
    private ExerciseRepository exerciseRepo;

    @PersistenceContext
    private EntityManager entityManager;

    public Map<String, Object> getExercises(
            int page,
            int size,
            int searchType,
            String searchTerm,
            String orderBy,
            String directionOrderBy,
            String filterByStatus,
            String filterByDifficulty,
            Integer filterByCategory
    ) {
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("prGetExercise", Exercise.class);

        // Parámetros de entrada
        query.registerStoredProcedureParameter("p_page", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_limit", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_searchType", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_searchTerm", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_orderBy", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_directionOrderBy", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByStatus", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByDifficulty", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByCategory", Integer.class, ParameterMode.IN);

        // Parámetro de salida
        query.registerStoredProcedureParameter("p_totalRecords", Integer.class, ParameterMode.OUT);

        // Setear parámetros
        query.setParameter("p_page", page);
        query.setParameter("p_limit", size);
        query.setParameter("p_searchType", searchType);
        query.setParameter("p_searchTerm", searchTerm);
        query.setParameter("p_orderBy", orderBy);
        query.setParameter("p_directionOrderBy", directionOrderBy);
        query.setParameter("p_filterByStatus", filterByStatus);
        query.setParameter("p_filterByDifficulty", filterByDifficulty);
        query.setParameter("p_filterByCategory", filterByCategory);

        // Ejecutar
        query.execute();

        List<?> rawResults = query.getResultList();
        List<Exercise> exercises = rawResults.stream()
                .filter(Exercise.class::isInstance)
                .map(Exercise.class::cast)
                .collect(Collectors.toList());

        Integer totalRecords = (Integer) query.getOutputParameterValue("p_totalRecords");

        Map<String, Object> response = new HashMap<>();
        response.put("exercises", exercises);
        response.put("totalRecords", totalRecords);

        return response;
    }

    @Transactional
    public List<Exercise> getAllExercises() {
        return exerciseRepo.getAllExercises();
    }

    @Transactional
    public int addExercise(String name, String description, String videoUrl, Long idExerciseDifficulty, Long idExerciseCategory, Long createdByUser) {
        return exerciseRepo.addExercise(name, description, videoUrl, idExerciseDifficulty, idExerciseCategory, createdByUser);
    }

    @Transactional
    public int updateExercise(
            int idExercise,
            String name,
            String description,
            String videoUrl,
            Long idExerciseDifficulty,
            Long idExerciseCategory,
            Long isDeleted,
            Long loggedIdUser
    ) {
        return exerciseRepo.updateExercise(idExercise, name, description, videoUrl, idExerciseDifficulty, idExerciseCategory, isDeleted, loggedIdUser);
    }

    @Transactional
    public int deleteExercise(int idExercise, int deletedByUser) {
        return exerciseRepo.deleteExercise(idExercise, deletedByUser);
    }
}
