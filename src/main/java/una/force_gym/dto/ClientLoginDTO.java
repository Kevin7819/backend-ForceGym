package una.force_gym.dto;

import java.util.Date;

import una.force_gym.domain.Person;

public class ClientLoginDTO {

    private Long idClient;
    private Person person;
    private String token;
    private Date expirationMembershipDate;
    private Date registrationDate;

    public ClientLoginDTO() {}

    public ClientLoginDTO(Long idClient, Person person, String token) {
        this.idClient = idClient;
        this.person = person;
        this.token = token;
    }

    public ClientLoginDTO(Long idClient, Person person, String token, Date expirationMembershipDate, Date registrationDate) {
        this.idClient = idClient;
        this.person = person;
        this.token = token;
        this.expirationMembershipDate = expirationMembershipDate;
        this.registrationDate = registrationDate;
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

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Date getExpirationMembershipDate() {
        return expirationMembershipDate;
    }

    public void setExpirationMembershipDate(Date expirationMembershipDate) {
        this.expirationMembershipDate = expirationMembershipDate;
    }

    public Date getRegistrationDate() {
        return registrationDate;
    }

    public void setRegistrationDate(Date registrationDate) {
        this.registrationDate = registrationDate;
    }
}
