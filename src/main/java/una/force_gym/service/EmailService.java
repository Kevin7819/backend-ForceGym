package una.force_gym.service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class EmailService implements IEmailService {

    @Value("${RESEND_API_KEY}")
    private String resendApiKey;

    @Value("${MAIL_FROM_EMAIL}")
    private String emailSender;

    private static final String RESEND_URL = "https://api.resend.com/emails";

    @Override
    public void sendEmail(String[] toUsers, String subject, String message) {

        try {
            // 1. Cargar plantilla HTML
            String htmlTemplate;
            try (InputStream is = getClass().getResourceAsStream("/templates/email.html")) {
                if (is == null) {
                    throw new RuntimeException("No se encontró email.html");
                }
                htmlTemplate = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            String htmlContent = htmlTemplate
                    .replace("${subject}", subject)
                    .replace("${message}", message);

            // 2. Crear body para Resend
            Map<String, Object> body = new HashMap<>();
            body.put("from", "Force Gym <" + emailSender + ">");
            body.put("to", toUsers);
            body.put("subject", subject);
            body.put("html", htmlContent);

            // 3. Headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(resendApiKey);

            HttpEntity<Map<String, Object>> request =
                    new HttpEntity<>(body, headers);

            // 4. Enviar
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> response =
                    restTemplate.postForEntity(RESEND_URL, request, String.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("Error Resend: " + response.getBody());
            }

        } catch (Exception e) {
            System.err.println("Error enviando correo con Resend");
            e.printStackTrace();
        }
    }
}
