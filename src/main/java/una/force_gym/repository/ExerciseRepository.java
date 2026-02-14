package una.force_gym.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.query.Procedure;
import org.springframework.data.repository.query.Param;

import una.force_gym.domain.Exercise;

public interface ExerciseRepository extends JpaRepository<Exercise, Long> {

    @Procedure(procedureName = "prGetAllExercise")
    List<Exercise> getAllExercises();

    @Procedure(procedureName = "prInsertExercise", outputParameterName = "result")
    int addExercise(
            @Param("pName") String name,
            @Param("pDescription") String description,
            @Param("pVideoUrl") String videoUrl,
            @Param("pIdExerciseDifficulty") Long idExerciseDifficulty,
            @Param("pIdExerciseCategory") Long idExerciseCategory,
            @Param("pLoggedIdUser") Long loggedIdUser
    );

    @Procedure(procedureName = "prUpdateExercise", outputParameterName = "result")
    int updateExercise(
            @Param("pIdExercise") int idExercise,
            @Param("pName") String name,
            @Param("pDescription") String description,
            @Param("pVideoUrl") String videoUrl,
            @Param("pIdExerciseDifficulty") Long idExerciseDifficulty,
            @Param("pIdExerciseCategory") Long idExerciseCategory,
            @Param("pIsDeleted") Long isDeleted,
            @Param("pLoggedIdUser") Long loggedIdUser
    );

    @Procedure(procedureName = "prDeleteExercise", outputParameterName = "result")
    int deleteExercise(
            @Param("pIdExercise") int idExercise,
            @Param("pDeletedByUser") int deletedByUser
    );
}
