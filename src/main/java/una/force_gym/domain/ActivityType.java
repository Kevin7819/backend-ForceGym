package una.force_gym.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "tbActivityType")
public class ActivityType {

    @Id
     @GeneratedValue(strategy = GenerationType.IDENTITY) 
    @Column(name = "idActivityType")
    private Long idActivityType;

    @Column(name = "name")
    private String name;

    @Column(name = "durationDays")
    private Integer durationDays;

    @Column(name = "isDeleted")
    private Long isDeleted;

    public ActivityType() {}

    public ActivityType(Long idActivityType, String name, Integer durationDays, Long isDeleted) {
        this.idActivityType = idActivityType;
        this.name = name;
        this.durationDays = durationDays;
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

    public Long getIsDeleted() {
        return isDeleted;
    }

    public void setIsDeleted(Long isDeleted) {
        this.isDeleted = isDeleted;
    }
    
}
