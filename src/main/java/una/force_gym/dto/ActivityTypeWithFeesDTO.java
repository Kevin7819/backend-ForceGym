package una.force_gym.dto;

import java.util.List;

public class ActivityTypeWithFeesDTO {
    private Long idActivityType;
    private String name;
    private Integer durationDays;
    private List<FeeDTO> fees;
    private Long isDeleted;
    
    public ActivityTypeWithFeesDTO() {}

    public ActivityTypeWithFeesDTO(Long idActivityType, String name, Integer durationDays, List<FeeDTO> fees, Long isDeleted) {
        this.idActivityType = idActivityType;
        this.name = name;
        this.durationDays = durationDays;
        this.fees = fees;
        this.isDeleted = isDeleted;
    }

    public Long getIdActivityType() {
        return idActivityType;
    }

    public void setIdActivityType(Long idActivityType) {
        this.idActivityType = idActivityType;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getDurationDays() {
        return durationDays;
    }

    public void setDurationDays(Integer durationDays) {
        this.durationDays = durationDays;
    }
    
    public List<FeeDTO> getFees() {
        return fees;
    }

    public void setFees(List<FeeDTO> fees) {
        this.fees = fees;
    }

    public Long getIsDeleted() {
        return isDeleted;
    }

    public void setIsDeleted(Long isDeleted) {
        this.isDeleted = isDeleted;
    }
    
}