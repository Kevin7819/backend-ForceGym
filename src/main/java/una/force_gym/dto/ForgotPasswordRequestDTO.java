package una.force_gym.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class ForgotPasswordRequestDTO {
    
    @NotBlank(message = "El email es requerido")
    @Email(message = "Formato de email inválido")
    private String email;
    
    private String recaptchaToken;

    public ForgotPasswordRequestDTO() {
    }

    public ForgotPasswordRequestDTO(String email) {
        this.email = email;
    }

    public ForgotPasswordRequestDTO(String email, String recaptchaToken) {
        this.email = email;
        this.recaptchaToken = recaptchaToken;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getRecaptchaToken() {
        return recaptchaToken;
    }

    public void setRecaptchaToken(String recaptchaToken) {
        this.recaptchaToken = recaptchaToken;
    }
}
