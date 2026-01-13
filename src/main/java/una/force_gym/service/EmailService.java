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

    @Value("${resend.api.key}")
    private String resendApiKey;

    @Value("${email.account.sender}")
    private String emailSender;

    private static final String RESEND_URL = "https://api.resend.com/emails";

    @Override
    public void sendEmail(String[] toUsers, String subject, String message) {

        try {
            // Load HTML template
            String htmlTemplate;
            try (InputStream is = getClass().getResourceAsStream("/templates/email.html")) {
                if (is == null) {
                    throw new RuntimeException("email.html not found");
                }
                htmlTemplate = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            String htmlContent = htmlTemplate
                    .replace("${subject}", subject)
                    .replace("${message}", message);

            // Build request body
            Map<String, Object> body = new HashMap<>();
            body.put("from", emailSender);
            body.put("to", toUsers);
            body.put("subject", subject);
            body.put("html", htmlContent);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(resendApiKey);

            HttpEntity<Map<String, Object>> request =
                    new HttpEntity<>(body, headers);

            RestTemplate restTemplate = new RestTemplate();
            restTemplate.postForEntity(RESEND_URL, request, String.class);

        } catch (Exception e) {
            System.err.println("Error sending email with Resend: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
