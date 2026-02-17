package una.force_gym.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "tbRoutineExercise")
public class RoutineExercise {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "idRoutineExercise")
    private Long idRoutineExercise;

    @ManyToOne
    @JoinColumn(name = "idRoutine", referencedColumnName = "idRoutine")
    private Routine routine;

    @ManyToOne
    @JoinColumn(name = "idExercise", referencedColumnName = "idExercise")
    private Exercise exercise;

    @Column(name = "series")
    private Integer series;

    @Column(name = "repetitions")
    private Integer repetitions;

    @Column(name = "note")
    private String note;

    @Column(name = "categoryOrder")
    private Integer categoryOrder;

    @Column(name = "dayNumber")
    private Integer dayNumber;

    public RoutineExercise() {
    }

    public RoutineExercise(Exercise exercise, Long idRoutineExercise, Integer repetitions, Routine routine, Integer series, String note) {
        this.exercise = exercise;
        this.idRoutineExercise = idRoutineExercise;
        this.repetitions = repetitions;
        this.routine = routine;
        this.series = series;
        this.note = note;
    }

    public RoutineExercise(Integer categoryOrder, Exercise exercise, Long idRoutineExercise, String note, Integer repetitions, Routine routine, Integer series) {
        this.categoryOrder = categoryOrder;
        this.exercise = exercise;
        this.idRoutineExercise = idRoutineExercise;
        this.note = note;
        this.repetitions = repetitions;
        this.routine = routine;
        this.series = series;
    }

    public Long getIdRoutineExercise() {
        return idRoutineExercise;
    }

    public void setIdRoutineExercise(Long idRoutineExercise) {
        this.idRoutineExercise = idRoutineExercise;
    }

    public Routine getRoutine() {
        return routine;
    }

    public void setRoutine(Routine routine) {
        this.routine = routine;
    }

    public Exercise getExercise() {
        return exercise;
    }

    public void setExercise(Exercise exercise) {
        this.exercise = exercise;
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
