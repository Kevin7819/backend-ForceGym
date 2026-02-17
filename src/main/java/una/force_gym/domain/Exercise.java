package una.force_gym.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "tbExercise")
public class Exercise {

    @Id
    @Column(name = "idExercise")
    private Long idExercise;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idUser", referencedColumnName = "idUser")
    private User user;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idExerciseCategory", referencedColumnName = "idExerciseCategory")
    private ExerciseCategory exerciseCategory;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "videoUrl")
    private String videoUrl;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idExerciseDifficulty", referencedColumnName = "idExerciseDifficulty")
    private ExerciseDifficulty exerciseDifficulty;

    @Column(name = "isDeleted")
    private Long isDeleted;

    public Exercise() {
    }

    public Exercise(String description, ExerciseCategory exerciseCategory, ExerciseDifficulty exerciseDifficulty, Long idExercise, Long isDeleted, String name, String videoUrl, User user) {
        this.description = description;
        this.exerciseCategory = exerciseCategory;
        this.exerciseDifficulty = exerciseDifficulty;
        this.idExercise = idExercise;
        this.isDeleted = isDeleted;
        this.name = name;
        this.videoUrl = videoUrl;
        this.user = user;
    }

    public Long getIdExercise() {
        return idExercise;
    }

    public void setIdExercise(Long idExercise) {
        this.idExercise = idExercise;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public ExerciseCategory getExerciseCategory() {
        return exerciseCategory;
    }

    public void setExerciseCategory(ExerciseCategory exerciseCategory) {
        this.exerciseCategory = exerciseCategory;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public ExerciseDifficulty getExerciseDifficulty() {
        return exerciseDifficulty;
    }

    public void setExerciseDifficulty(ExerciseDifficulty exerciseDifficulty) {
        this.exerciseDifficulty = exerciseDifficulty;
    }

    public Long getIsDeleted() {
        return isDeleted;
    }

    public void setIsDeleted(Long isDeleted) {
        this.isDeleted = isDeleted;
    }

    public String getVideoUrl() {
        return videoUrl;
    }

    public void setVideoUrl(String videoUrl) {
        this.videoUrl = videoUrl;
    }

}
