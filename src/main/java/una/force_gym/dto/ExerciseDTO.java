package una.force_gym.dto;

public class ExerciseDTO {

    private Long idExercise;
    private String name;
    private String description;
    private String videoUrl;
    private Long idExerciseDifficulty;
    private Long idExerciseCategory;
    private Long idUser;
    private Long isDeleted;
    private Long paramLoggedIdUser;

    public ExerciseDTO() {
    }

    public ExerciseDTO(String description, Long idExercise, Long idExerciseCategory, Long idExerciseDifficulty, Long idUser, Long isDeleted, String name, String videoUrl, Long paramLoggedIdUser) {
        this.description = description;
        this.idExercise = idExercise;
        this.idExerciseCategory = idExerciseCategory;
        this.idExerciseDifficulty = idExerciseDifficulty;
        this.idUser = idUser;
        this.isDeleted = isDeleted;
        this.name = name;
        this.videoUrl = videoUrl;
        this.paramLoggedIdUser = paramLoggedIdUser;
    }

    public Long getIdExercise() {
        return idExercise;
    }

    public void setIdExercise(Long idExercise) {
        this.idExercise = idExercise;
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

    public Long getIdExerciseDifficulty() {
        return idExerciseDifficulty;
    }

    public void setIdExerciseDifficulty(Long idExerciseDifficulty) {
        this.idExerciseDifficulty = idExerciseDifficulty;
    }

    public Long getIdExerciseCategory() {
        return idExerciseCategory;
    }

    public void setIdExerciseCategory(Long idExerciseCategory) {
        this.idExerciseCategory = idExerciseCategory;
    }

    public Long getIdUser() {
        return idUser;
    }

    public void setIdUser(Long idUser) {
        this.idUser = idUser;
    }

    public Long getIsDeleted() {
        return isDeleted;
    }

    public void setIsDeleted(Long isDeleted) {
        this.isDeleted = isDeleted;
    }

    public Long getParamLoggedIdUser() {
        return paramLoggedIdUser;
    }

    public void setParamLoggedIdUser(Long paramLoggedIdUser) {
        this.paramLoggedIdUser = paramLoggedIdUser;
    }

    public String getVideoUrl() {
        return videoUrl;
    }

    public void setVideoUrl(String videoUrl) {
        this.videoUrl = videoUrl;
    }

}
