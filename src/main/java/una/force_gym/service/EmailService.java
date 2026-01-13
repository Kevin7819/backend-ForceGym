package una.force_gym.service;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.internet.MimeMessage;

@Service
public class EmailService implements IEmailService {

    @Value("${EMAIL_SENDER}")
    private String emailSender;

    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public void sendEmail(String[] toUsers, String subject, String message) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper =
                    new MimeMessageHelper(mimeMessage, true, "utf-8");

            // Load HTML template
            String htmlTemplate;
            try (InputStream is =
                    getClass().getResourceAsStream("/templates/email.html")) {

                if (is == null) {
                    throw new FileNotFoundException("email.html not found");
                }

                htmlTemplate = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            // Replace placeholders
            String htmlContent = htmlTemplate
                    .replace("${subject}", subject)
                    .replace("${message}", message);

            helper.setFrom(emailSender);
            helper.setTo(toUsers);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(mimeMessage);

        } catch (Exception e) {
            System.err.println("Error sending email with Gmail SMTP: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
