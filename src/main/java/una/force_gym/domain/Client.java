package una.force_gym.domain;

import java.util.Date;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "tbClient")
public class Client {

    @Id
    @Column(name = "idClient")
    private Long idClient;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idPerson", referencedColumnName = "idPerson")
    private Person person;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idClientType", referencedColumnName = "idClientType")
    private ClientType  typeClient;

    @OneToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idHealthQuestionnaire", referencedColumnName = "idHealthQuestionnaire")
    private HealthQuestionnaire healthQuestionnaire;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "idUser", referencedColumnName = "idUser")
    private User user;

    @Column(name = "registrationDate")
    private Date registrationDate;

    @Column(name = "expirationMembershipDate")
    private Date expirationMembershipDate;

    @Column(name = "phoneNumberContactEmergency")
    private String phoneNumberContactEmergency;
    
    @Column(name = "nameEmergencyContact")
    private String nameEmergencyContact;

    @Column(name = "signatureImage")
    private String signatureImage;

    @Column(name = "isDeleted")
    private Long isDeleted;

    public Client() {}

    public Client(Long idClient, Person person, TypeClient typeClient, HealthQuestionnaire healthQuestionnaire,
            User user, Date registrationDate, Date expirationMembershipDate, String phoneNumberContactEmergency,
            String nameEmergencyContact, String signatureImage, Long isDeleted) {
        this.idClient = idClient;
        this.person = person;
        this.typeClient = typeClient;
        this.healthQuestionnaire = healthQuestionnaire;
        this.user = user;
        this.registrationDate = registrationDate;
        this.expirationMembershipDate = expirationMembershipDate;
        this.phoneNumberContactEmergency = phoneNumberContactEmergency;
        this.nameEmergencyContact = nameEmergencyContact;
        this.signatureImage = signatureImage;
        this.isDeleted = isDeleted;
    }

    public Long getIdClient() {
        return idClient;
    }

    public void setIdClient(Long idClient) {
        this.idClient = idClient;
    }

    public Person getPerson() {
        return person;
    }

    public void setPerson(Person person) {
        this.person = person;
    }

    public TypeClient getTypeClient() {
        return typeClient;
    }

    public void setTypeClient(TypeClient typeClient) {
        this.typeClient = typeClient;
    }

    public HealthQuestionnaire getHealthQuestionnaire() {
        return healthQuestionnaire;
    }

    public void setHealthQuestionnaire(HealthQuestionnaire healthQuestionnaire) {
        this.healthQuestionnaire = healthQuestionnaire;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
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
    
}
