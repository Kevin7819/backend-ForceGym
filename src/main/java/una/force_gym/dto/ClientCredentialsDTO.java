package una.force_gym.dto;

public class ClientCredentialsDTO {
    
    private String identificationNumber;
    private String password;
    private String recaptchaToken;

    public ClientCredentialsDTO() {}

    public ClientCredentialsDTO(String identificationNumber, String password) {
        this.identificationNumber = identificationNumber;
        this.password = password;
    }

    public ClientCredentialsDTO(String identificationNumber, String password, String recaptchaToken) {
        this.identificationNumber = identificationNumber;
        this.password = password;
        this.recaptchaToken = recaptchaToken;
    }

    public String getIdentificationNumber() {
        return identificationNumber;
    }

    public void setIdentificationNumber(String identificationNumber) {
        this.identificationNumber = identificationNumber;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRecaptchaToken() {
        return recaptchaToken;
    }

    public void setRecaptchaToken(String recaptchaToken) {
        this.recaptchaToken = recaptchaToken;
    }
}
