package una.force_gym.domain;

import java.util.Date;

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
@Table(name = "tbRoutineAssignment")
public class RoutineAssignment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "idRoutineAssignment")
    private Long idRoutineAssignment;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idRoutine", referencedColumnName = "idRoutine")
    @JsonIgnoreProperties({"routineAssignments", "hibernateLazyInitializer", "handler"})
    private Routine routine;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idClient", referencedColumnName = "idClient")
    @JsonIgnoreProperties({"routineAssignments", "measurements", "hibernateLazyInitializer", "handler"})
    private Client client;

    @Column(name = "assignmentDate")
    private Date assignmentDate;

    public RoutineAssignment() {
    }

    public RoutineAssignment(Date assignmentDate, Client client, Long idRoutineAssignment, Routine routine) {
        this.assignmentDate = assignmentDate;
        this.client = client;
        this.idRoutineAssignment = idRoutineAssignment;
        this.routine = routine;
    }

    public Long getIdRoutineAssignment() {
        return idRoutineAssignment;
    }

    public void setIdRoutineAssignment(Long idRoutineAssignment) {
        this.idRoutineAssignment = idRoutineAssignment;
    }

    public Routine getRoutine() {
        return routine;
    }

    public void setRoutine(Routine routine) {
        this.routine = routine;
    }

    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public Date getAssignmentDate() {
        return assignmentDate;
    }

    public void setAssignmentDate(Date assignmentDate) {
        this.assignmentDate = assignmentDate;
    }

}
