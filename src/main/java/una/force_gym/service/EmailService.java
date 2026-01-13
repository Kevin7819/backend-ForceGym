package una.force_gym.service;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class EmailService implements IEmailService {

    private static final String MAILERSEND_URL =
            "https://api.mailersend.com/v1/email";

    @Value("${MAILERSEND_API_KEY}")
    private String apiKey;

    @Value("${MAIL_FROM_EMAIL}")
    private String emailSender;

    @Value("${MAIL_FROM_NAME}")
    private String senderName;

    private final RestTemplate restTemplate;

    public EmailService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public void sendEmail(String[] toUsers, String subject, String message) {
        try {
            // 1. Load HTML template
            String htmlTemplate;
            try (InputStream templateStream =
                     getClass().getResourceAsStream("/templates/email.html")) {

                if (templateStream == null) {
                    throw new FileNotFoundException("email.html template not found");
                }

                htmlTemplate = new String(
                        templateStream.readAllBytes(),
                        StandardCharsets.UTF_8
                );
            }

            // 2. Replace placeholders
            String htmlContent = htmlTemplate
                    .replace("${subject}", subject)
                    .replace("${message}", message);

            // 3. Send email to each user
            for (String to : toUsers) {

                Map<String, Object> body = Map.of(
                    "from", Map.of(
                        "email", emailSender,
                        "name", senderName
                    ),
                    "to", List.of(
                        Map.of("email", to)
                    ),
                    "subject", subject,
                    "html", htmlContent
                );

                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_JSON);
                headers.setBearerAuth(apiKey);

                HttpEntity<Map<String, Object>> request =
                        new HttpEntity<>(body, headers);

                restTemplate.postForEntity(
                        MAILERSEND_URL,
                        request,
                        Void.class
                );
            }

        } catch (Exception e) {
            System.err.println("Error sending email with MailerSend: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
