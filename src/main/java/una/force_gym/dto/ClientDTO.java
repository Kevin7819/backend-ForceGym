package una.force_gym.dto;

import java.time.LocalDate;
import java.util.Date;

public class ClientDTO {
    
    private Long idClient;
    
    //Person
    private Long idPerson;
    private String name;
    private String firstLastName;
    private String secondLastName;
    private LocalDate birthday;
    private String identificationNumber;
    private String phoneNumber;
    private String email;
    private Long idGender;
    
    //ClientType
    private Long idClientType;

    //HealtQuestionnaire
    private Long idHealthQuestionnaire;
    private Boolean diabetes;
    private Boolean hypertension;
    private Boolean muscleInjuries;
    private Boolean boneJointIssues;
    private Boolean balanceLoss;
    private Boolean cardiovascularDisease;
    private Boolean breathingIssues;

    private Long idUser;
    private Date registrationDate;
    private Date expirationMembershipDate;
    private String phoneNumberContactEmergency;
    private String nameEmergencyContact;

    private String signatureImage;
    private Long isDeleted;
    private Long paramLoggedIdUser;

    public ClientDTO() {}

    public ClientDTO(Long idClient, Long idPerson, String name, String firstLastName, String secondLastName,
            LocalDate birthday, String identificationNumber, String phoneNumber, String email, Long idGender,
            Long idClientType, Long idHealthQuestionnaire, Boolean diabetes, Boolean hypertension,
            Boolean muscleInjuries, Boolean boneJointIssues, Boolean balanceLoss, Boolean cardiovascularDisease,
            Boolean breathingIssues, Long idUser, Date registrationDate, Date expirationMembershipDate,
            String phoneNumberContactEmergency, String nameEmergencyContact, String signatureImage, Long isDeleted,
            Long paramLoggedIdUser) {
        this.idClient = idClient;
        this.idPerson = idPerson;
        this.name = name;
        this.firstLastName = firstLastName;
        this.secondLastName = secondLastName;
        this.birthday = birthday;
        this.identificationNumber = identificationNumber;
        this.phoneNumber = phoneNumber;
        this.email = email;
        this.idGender = idGender;
        this.idClientType = idClientType;
        this.idHealthQuestionnaire = idHealthQuestionnaire;
        this.diabetes = diabetes;
        this.hypertension = hypertension;
        this.muscleInjuries = muscleInjuries;
        this.boneJointIssues = boneJointIssues;
        this.balanceLoss = balanceLoss;
        this.cardiovascularDisease = cardiovascularDisease;
        this.breathingIssues = breathingIssues;
        this.idUser = idUser;
        this.registrationDate = registrationDate;
        this.expirationMembershipDate = expirationMembershipDate;
        this.phoneNumberContactEmergency = phoneNumberContactEmergency;
        this.nameEmergencyContact = nameEmergencyContact;
        this.signatureImage = signatureImage;
        this.isDeleted = isDeleted;
        this.paramLoggedIdUser = paramLoggedIdUser;
    }

    public Long getIdClient() {
        return idClient;
    }

    public void setIdClient(Long idClient) {
        this.idClient = idClient;
    }

    public Long getIdPerson() {
        return idPerson;
    }

    public void setIdPerson(Long idPerson) {
        this.idPerson = idPerson;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getFirstLastName() {
        return firstLastName;
    }

    public void setFirstLastName(String firstLastName) {
        this.firstLastName = firstLastName;
    }

    public String getSecondLastName() {
        return secondLastName;
    }

    public void setSecondLastName(String secondLastName) {
        this.secondLastName = secondLastName;
    }

    public LocalDate getBirthday() {
        return birthday;
    }

    public void setBirthday(LocalDate birthday) {
        this.birthday = birthday;
    }

    public String getIdentificationNumber() {
        return identificationNumber;
    }

    public void setIdentificationNumber(String identificationNumber) {
        this.identificationNumber = identificationNumber;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Long getIdGender() {
        return idGender;
    }

    public void setIdGender(Long idGender) {
        this.idGender = idGender;
    }

    public Long getIdClientType() {
        return idClientType;
    }

    public void setIdClientType(Long idClientType) {
        this.idClientType = idClientType;
    }

    public Long getIdHealthQuestionnaire() {
        return idHealthQuestionnaire;
    }

    public void setIdHealthQuestionnaire(Long idHealthQuestionnaire) {
        this.idHealthQuestionnaire = idHealthQuestionnaire;
    }

    public Boolean getDiabetes() {
        return diabetes;
    }

    public void setDiabetes(Boolean diabetes) {
        this.diabetes = diabetes;
    }

    public Boolean getHypertension() {
        return hypertension;
    }

    public void setHypertension(Boolean hypertension) {
        this.hypertension = hypertension;
    }

    public Boolean getMuscleInjuries() {
        return muscleInjuries;
    }

    public void setMuscleInjuries(Boolean muscleInjuries) {
        this.muscleInjuries = muscleInjuries;
    }

    public Boolean getBoneJointIssues() {
        return boneJointIssues;
    }

    public void setBoneJointIssues(Boolean boneJointIssues) {
        this.boneJointIssues = boneJointIssues;
    }

    public Boolean getBalanceLoss() {
        return balanceLoss;
    }

    public void setBalanceLoss(Boolean balanceLoss) {
        this.balanceLoss = balanceLoss;
    }

    public Boolean getCardiovascularDisease() {
        return cardiovascularDisease;
    }

    public void setCardiovascularDisease(Boolean cardiovascularDisease) {
        this.cardiovascularDisease = cardiovascularDisease;
    }

    public Boolean getBreathingIssues() {
        return breathingIssues;
    }

    public void setBreathingIssues(Boolean breathingIssues) {
        this.breathingIssues = breathingIssues;
    }

    public Long getIdUser() {
        return idUser;
    }

    public void setIdUser(Long idUser) {
        this.idUser = idUser;
    }

    public Date getRegistrationDate() {
        return registrationDate;
    }

    public void setRegistrationDate(Date registrationDate) {
        this.registrationDate = registrationDate;
    }

    public Date getExpirationMembershipDate() {
        return expirationMembershipDate;
    }

    public void setExpirationMembershipDate(Date expirationMembershipDate) {
        this.expirationMembershipDate = expirationMembershipDate;
    }

    public String getPhoneNumberContactEmergency() {
        return phoneNumberContactEmergency;
    }

    public void setPhoneNumberContactEmergency(String phoneNumberContactEmergency) {
        this.phoneNumberContactEmergency = phoneNumberContactEmergency;
    }

    public String getNameEmergencyContact() {
        return nameEmergencyContact;
    }

    public void setNameEmergencyContact(String nameEmergencyContact) {
        this.nameEmergencyContact = nameEmergencyContact;
    }

    public String getSignatureImage() {
        return signatureImage;
    }

    public void setSignatureImage(String signatureImage) {
        this.signatureImage = signatureImage;
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
