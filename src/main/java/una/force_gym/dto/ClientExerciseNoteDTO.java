package una.force_gym.dto;

public class ClientExerciseNoteDTO {

    private Long idClientExerciseNote;
    private Long idClient;
    private Long idRoutineExercise;
    private String personalNote;

    public ClientExerciseNoteDTO() {
    }

    public ClientExerciseNoteDTO(Long idClientExerciseNote, Long idClient, Long idRoutineExercise, String personalNote) {
        this.idClientExerciseNote = idClientExerciseNote;
        this.idClient = idClient;
        this.idRoutineExercise = idRoutineExercise;
        this.personalNote = personalNote;
    }

    public Long getIdClientExerciseNote() {
        return idClientExerciseNote;
    }

    public void setIdClientExerciseNote(Long idClientExerciseNote) {
        this.idClientExerciseNote = idClientExerciseNote;
    }

    public Long getIdClient() {
        return idClient;
    }

    public void setIdClient(Long idClient) {
        this.idClient = idClient;
    }

    public Long getIdRoutineExercise() {
        return idRoutineExercise;
    }

    public void setIdRoutineExercise(Long idRoutineExercise) {
        this.idRoutineExercise = idRoutineExercise;
    }

    public String getPersonalNote() {
        return personalNote;
    }

    public void setPersonalNote(String personalNote) {
        this.personalNote = personalNote;
    }
}
