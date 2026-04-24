package una.force_gym.dto;

import java.util.List;

public class ClientAssignmentRequest {
    private Long idRoutine;
    private List<Long> clientIds;
    private Long paramLoggedIdUser;

    public ClientAssignmentRequest() {
    }

    public ClientAssignmentRequest(Long idRoutine, List<Long> clientIds, Long paramLoggedIdUser) {
        this.idRoutine = idRoutine;
        this.clientIds = clientIds;
        this.paramLoggedIdUser = paramLoggedIdUser;
    }

    public Long getIdRoutine() {
        return idRoutine;
    }

    public void setIdRoutine(Long idRoutine) {
        this.idRoutine = idRoutine;
    }

    public List<Long> getClientIds() {
        return clientIds;
    }

    public void setClientIds(List<Long> clientIds) {
        this.clientIds = clientIds;
    }

    public Long getParamLoggedIdUser() {
        return paramLoggedIdUser;
    }

    public void setParamLoggedIdUser(Long paramLoggedIdUser) {
        this.paramLoggedIdUser = paramLoggedIdUser;
    }
}
