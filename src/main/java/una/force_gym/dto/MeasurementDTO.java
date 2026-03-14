package una.force_gym.dto;

import java.util.Date;

public class MeasurementDTO {
    
    private Long idMeasurement;
    private Long idClient;
    private Date measurementDate;
    private Float weight;
    private Float height;
    private Float bmi;
    private Float muscleMass;
    private Float bodyFatPercentage;
    private Float visceralFatPercentage;
    private Float chestSize;
    private Float backSize;
    private Float hipSize;
    private Float waistSize;
    private Float leftLegSize;
    private Float rightLegSize;
    private Float leftCalfSize;
    private Float rightCalfSize;
    private Float leftForeArmSize;
    private Float rightForeArmSize;
    private Float leftArmSize;
    private Float rightArmSize;
    private Long isDeleted;
    private Long paramLoggedIdUser;

    public MeasurementDTO() {}

    public MeasurementDTO(Long idMeasurement, Long idClient, Date measurementDate, Float weight, Float height, Float bmi,
            Float muscleMass, Float bodyFatPercentage, Float visceralFatPercentage, Float chestSize, Float backSize, Float hipSize, Float waistSize,
            Float leftLegSize, Float rightLegSize, Float leftCalfSize, Float rightCalfSize,
            Float leftForeArmSize, Float rightForeArmSize, Float leftArmSize, Float rightArmSize,
            Long isDeleted, Long paramLoggedIdUser) {
        this.idMeasurement = idMeasurement;
        this.idClient = idClient;
        this.measurementDate = measurementDate;
        this.weight = weight;
        this.height = height;
        this.bmi = bmi;
        this.muscleMass = muscleMass;
        this.bodyFatPercentage = bodyFatPercentage;
        this.visceralFatPercentage = visceralFatPercentage;
        this.chestSize = chestSize;
        this.backSize = backSize;
        this.hipSize = hipSize;
        this.waistSize = waistSize;
        this.leftLegSize = leftLegSize;
        this.rightLegSize = rightLegSize;
        this.leftCalfSize = leftCalfSize;
        this.rightCalfSize = rightCalfSize;
        this.leftForeArmSize = leftForeArmSize;
        this.rightForeArmSize = rightForeArmSize;
        this.leftArmSize = leftArmSize;
        this.rightArmSize = rightArmSize;
        this.isDeleted = isDeleted;
        this.paramLoggedIdUser = paramLoggedIdUser;
    }

    public Long getIdMeasurement() {
        return idMeasurement;
    }

    public void setIdMeasurement(Long idMeasurement) {
        this.idMeasurement = idMeasurement;
    }

    public Long getIdClient() {
        return idClient;
    }

    public void setIdClient(Long idClient) {
        this.idClient = idClient;
    }

    public Date getMeasurementDate() {
        return measurementDate;
    }

    public void setMeasurementDate(Date measurementDate) {
        this.measurementDate = measurementDate;
    }

    public Float getWeight() {
        return weight;
    }

    public void setWeight(Float weight) {
        this.weight = weight;
    }

    public Float getHeight() {
        return height;
    }

    public void setHeight(Float height) {
        this.height = height;
    }

    public Float getBmi() {
        return bmi;
    }

    public void setBmi(Float bmi) {
        this.bmi = bmi;
    }

    public Float getMuscleMass() {
        return muscleMass;
    }

    public void setMuscleMass(Float muscleMass) {
        this.muscleMass = muscleMass;
    }

    public Float getBodyFatPercentage() {
        return bodyFatPercentage;
    }

    public void setBodyFatPercentage(Float bodyFatPercentage) {
        this.bodyFatPercentage = bodyFatPercentage;
    }

    public Float getVisceralFatPercentage() {
        return visceralFatPercentage;
    }

    public void setVisceralFatPercentage(Float visceralFatPercentage) {
        this.visceralFatPercentage = visceralFatPercentage;
    }

    public Float getChestSize() {
        return chestSize;
    }

    public void setChestSize(Float chestSize) {
        this.chestSize = chestSize;
    }

    public Float getBackSize() {
        return backSize;
    }

    public void setBackSize(Float backSize) {
        this.backSize = backSize;
    }

    public Float getHipSize() {
        return hipSize;
    }

    public void setHipSize(Float hipSize) {
        this.hipSize = hipSize;
    }

    public Float getWaistSize() {
        return waistSize;
    }

    public void setWaistSize(Float waistSize) {
        this.waistSize = waistSize;
    }

    public Float getLeftLegSize() {
        return leftLegSize;
    }

    public void setLeftLegSize(Float leftLegSize) {
        this.leftLegSize = leftLegSize;
    }

    public Float getRightLegSize() {
        return rightLegSize;
    }

    public void setRightLegSize(Float rightLegSize) {
        this.rightLegSize = rightLegSize;
    }

    public Float getLeftCalfSize() {
        return leftCalfSize;
    }

    public void setLeftCalfSize(Float leftCalfSize) {
        this.leftCalfSize = leftCalfSize;
    }

    public Float getRightCalfSize() {
        return rightCalfSize;
    }

    public void setRightCalfSize(Float rightCalfSize) {
        this.rightCalfSize = rightCalfSize;
    }

    public Float getLeftForeArmSize() {
        return leftForeArmSize;
    }

    public void setLeftForeArmSize(Float leftForeArmSize) {
        this.leftForeArmSize = leftForeArmSize;
    }

    public Float getRightForeArmSize() {
        return rightForeArmSize;
    }

    public void setRightForeArmSize(Float rightForeArmSize) {
        this.rightForeArmSize = rightForeArmSize;
    }

    public Float getLeftArmSize() {
        return leftArmSize;
    }

    public void setLeftArmSize(Float leftArmSize) {
        this.leftArmSize = leftArmSize;
    }

    public Float getRightArmSize() {
        return rightArmSize;
    }

    public void setRightArmSize(Float rightArmSize) {
        this.rightArmSize = rightArmSize;
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
}
