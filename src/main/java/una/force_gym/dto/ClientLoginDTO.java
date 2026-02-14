package una.force_gym.dto;

import una.force_gym.domain.Person;

public class ClientLoginDTO {

    private Long idClient;
    private Person person;
    private String token;

    public ClientLoginDTO() {}

    public ClientLoginDTO(Long idClient, Person person, String token) {
        this.idClient = idClient;
        this.person = person;
        this.token = token;
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
}
