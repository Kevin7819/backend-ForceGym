package una.force_gym.domain;

import java.sql.Timestamp;
import java.util.Date;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

@Entity
@Table(name = "tbRoutine")
public class Routine {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "idRoutine")
    private Long idRoutine;

    @Column(name = "name")
    private String name;

    @Column(name = "date")
    private Date date;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idUser", referencedColumnName = "idUser")
    @JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
    private User user;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idDifficultyRoutine", referencedColumnName = "idDifficultyRoutine")
    private DifficultyRoutine difficultyRoutine;
    
    @Column(name = "createdByUser", nullable = false)
    private Long createdByUser;

    @Column(name = "createdAt", nullable = false)
    private Timestamp createdAt = new Timestamp(System.currentTimeMillis());

    @OneToMany(mappedBy = "routine", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @JsonIgnoreProperties({"routine", "client"})
    private List<RoutineAssignment> assignments;

    @OneToMany(mappedBy = "routine", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @JsonIgnoreProperties({"routine"})
    @JsonProperty("routineExercises")
    private List<RoutineExercise> exercises;

    @Column(name = "updatedByUser")
    private Long updatedByUser;

    @Column(name = "updatedAt")
    private Timestamp updatedAt;

    @Column(name = "isDeleted")
    private Long isDeleted;

    public Routine() {
    }

    public Routine(Date date, DifficultyRoutine difficultyRoutine, Long idRoutine, Long isDeleted, String name, User user) {
        this.date = date;
        this.difficultyRoutine = difficultyRoutine;
        this.idRoutine = idRoutine;
        this.isDeleted = isDeleted;
        this.name = name;
        this.user = user;
    }

    public Routine(Long createdByUser, Date date, DifficultyRoutine difficultyRoutine, Long idRoutine, Long isDeleted, String name, Timestamp updatedAt, Long updatedByUser, User user) {
        this.createdByUser = createdByUser;
        this.date = date;
        this.difficultyRoutine = difficultyRoutine;
        this.idRoutine = idRoutine;
        this.isDeleted = isDeleted;
        this.name = name;
        this.updatedAt = updatedAt;
        this.updatedByUser = updatedByUser;
        this.user = user;
    }

    public Routine(List<RoutineAssignment> assignments, Long createdByUser, Date date, DifficultyRoutine difficultyRoutine, List<RoutineExercise> exercises, Long idRoutine, Long isDeleted, String name, Timestamp updatedAt, Long updatedByUser, User user) {
        this.assignments = assignments;
        this.createdByUser = createdByUser;
        this.date = date;
        this.difficultyRoutine = difficultyRoutine;
        this.exercises = exercises;
        this.idRoutine = idRoutine;
        this.isDeleted = isDeleted;
        this.name = name;
        this.updatedAt = updatedAt;
        this.updatedByUser = updatedByUser;
        this.user = user;
    }

    public Long getIdRoutine() {
        return idRoutine;
    }

    public void setIdRoutine(Long idRoutine) {
        this.idRoutine = idRoutine;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public DifficultyRoutine getDifficultyRoutine() {
        return difficultyRoutine;
    }

    public void setDifficultyRoutine(DifficultyRoutine difficultyRoutine) {
        this.difficultyRoutine = difficultyRoutine;
    }

    public Long getCreatedByUser() {
        return createdByUser;
    }

    public void setCreatedByUser(Long createdByUser) {
        this.createdByUser = createdByUser;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }

    public Long getUpdatedByUser() {
        return updatedByUser;
    }

    public void setUpdatedByUser(Long updatedByUser) {
        this.updatedByUser = updatedByUser;
    }

    public Timestamp getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Timestamp updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Long getIsDeleted() {
        return isDeleted;
    }

    public void setIsDeleted(Long isDeleted) {
        this.isDeleted = isDeleted;
    }

    public List<RoutineAssignment> getAssignments() {
        return assignments;
    }

    public void setAssignments(List<RoutineAssignment> assignments) {
        this.assignments = assignments;
    }

    public List<RoutineExercise> getExercises() {
        return exercises;
    }

    public void setExercises(List<RoutineExercise> exercises) {
        this.exercises = exercises;
    }

}
