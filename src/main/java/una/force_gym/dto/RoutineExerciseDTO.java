package una.force_gym.dto;

public class RoutineExerciseDTO {

    private Long idExercise;
    private Integer series;
    private Integer repetitions;
    private Integer categoryOrder;
    private Integer dayNumber;
    private String note;

    public RoutineExerciseDTO() {
    }

    public RoutineExerciseDTO(Long idExercise, Integer repetitions, Integer series, String note) {
        this.idExercise = idExercise;
        this.repetitions = repetitions;
        this.series = series;
        this.note = note;
    }

    public RoutineExerciseDTO(Integer categoryOrder, Long idExercise, String note, Integer repetitions, Integer series) {
        this.categoryOrder = categoryOrder;
        this.idExercise = idExercise;
        this.note = note;
        this.repetitions = repetitions;
        this.series = series;
    }

    public Long getIdExercise() {
        return idExercise;
    }

    public void setIdExercise(Long idExercise) {
        this.idExercise = idExercise;
    }

    public Integer getSeries() {
        return series;
    }

    public void setSeries(Integer series) {
        this.series = series;
    }

    public Integer getRepetitions() {
        return repetitions;
    }

    public void setRepetitions(Integer repetitions) {
        this.repetitions = repetitions;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }

    public Integer getCategoryOrder() {
        return categoryOrder;
    }

    public void setCategoryOrder(Integer categoryOrder) {
        this.categoryOrder = categoryOrder;
    }

    public Integer getDayNumber() {
        return dayNumber;
    }

    public void setDayNumber(Integer dayNumber) {
        this.dayNumber = dayNumber;
    }

}
