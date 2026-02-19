package una.force_gym.domain;

import java.sql.Timestamp;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "tbClientExerciseNote")
public class ClientExerciseNote {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "idClientExerciseNote")
    private Long idClientExerciseNote;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idClient", referencedColumnName = "idClient")
    @JsonIgnoreProperties({"routineAssignments", "measurements", "hibernateLazyInitializer", "handler"})
    private Client client;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idRoutineExercise", referencedColumnName = "idRoutineExercise")
    @JsonIgnoreProperties({"routine", "hibernateLazyInitializer", "handler"})
    private RoutineExercise routineExercise;

    @Column(name = "personalNote", columnDefinition = "TEXT")
    private String personalNote;

    @Column(name = "createdAt")
    private Timestamp createdAt;

    @Column(name = "updatedAt")
    private Timestamp updatedAt;

    public ClientExerciseNote() {
        this.createdAt = new Timestamp(System.currentTimeMillis());
        this.updatedAt = new Timestamp(System.currentTimeMillis());
    }

    public ClientExerciseNote(Client client, RoutineExercise routineExercise, String personalNote) {
        this.client = client;
        this.routineExercise = routineExercise;
        this.personalNote = personalNote;
        this.createdAt = new Timestamp(System.currentTimeMillis());
        this.updatedAt = new Timestamp(System.currentTimeMillis());
    }

    public Long getIdClientExerciseNote() {
        return idClientExerciseNote;
    }

    public void setIdClientExerciseNote(Long idClientExerciseNote) {
        this.idClientExerciseNote = idClientExerciseNote;
    }

    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public RoutineExercise getRoutineExercise() {
        return routineExercise;
    }

    public void setRoutineExercise(RoutineExercise routineExercise) {
        this.routineExercise = routineExercise;
    }

    public String getPersonalNote() {
        return personalNote;
    }

    public void setPersonalNote(String personalNote) {
        this.personalNote = personalNote;
        this.updatedAt = new Timestamp(System.currentTimeMillis());
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }

    public Timestamp getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Timestamp updatedAt) {
        this.updatedAt = updatedAt;
    }
}
