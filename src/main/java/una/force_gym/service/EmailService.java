package una.force_gym.service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import jakarta.mail.internet.MimeMessage;

@Service
public class EmailService implements IEmailService {

    @Autowired(required = false)
    private JavaMailSender mailSender;

    @Autowired
    private Environment environment;

    @Value("${RESEND_API_KEY:}")
    private String resendApiKey;

    @Value("${MAIL_FROM_EMAIL:no-reply@forcegym.website}")
    private String emailSender;

    @Value("${spring.mail.username:}")
    private String smtpUsername;

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

            // Decidir método de envío basado en configuración de Resend
            // Usa SMTP solo si no hay API key válida de Resend
            boolean hasValidResendKey = resendApiKey != null 
                                     && !resendApiKey.isEmpty() 
                                     && !resendApiKey.startsWith("re_dummy")
                                     && !resendApiKey.equals("re_TU_API_KEY_REAL_AQUI");

            if (hasValidResendKey) {
                sendEmailViaResend(toUsers, subject, htmlContent);
            } else if (mailSender != null) {
                System.out.println("⚠️  API key de Resend no configurada, usando SMTP como fallback");
                sendEmailViaSmtp(toUsers, subject, htmlContent);
            } else {
                throw new RuntimeException("No hay servicio de email configurado (ni Resend ni SMTP)");
            }

        } catch (Exception e) {
            System.err.println("❌ ERROR CRÍTICO enviando correo electrónico");
            System.err.println("   Destinatarios: " + String.join(", ", toUsers));
            System.err.println("   Asunto: " + subject);
            e.printStackTrace();
            throw new RuntimeException("Error al enviar correo: " + e.getMessage(), e);
        }
    }

    private boolean isLocalProfile() {
        String[] activeProfiles = environment.getActiveProfiles();
        for (String profile : activeProfiles) {
            if ("local".equals(profile)) {
                return true;
            }
        }
        return activeProfiles.length == 0; // Sin perfil = local por defecto
    }

    private void sendEmailViaSmtp(String[] toUsers, String subject, String htmlContent) throws Exception {
        System.out.println("📧 Enviando email via SMTP (Gmail)...");
        System.out.println("   Desde: " + smtpUsername);
        System.out.println("   Para: " + String.join(", ", toUsers));
        System.out.println("   Asunto: " + subject);

        if (mailSender == null) {
            throw new RuntimeException("JavaMailSender no está configurado. Verifica las propiedades de spring.mail.*");
        }

        MimeMessage mimeMessage = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
        
        helper.setFrom(smtpUsername);
        helper.setTo(toUsers);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);
        
        mailSender.send(mimeMessage);
        System.out.println("✅ Email enviado exitosamente via SMTP");
    }

    private void sendEmailViaResend(String[] toUsers, String subject, String htmlContent) throws Exception {
        System.out.println("📧 Enviando email via Resend API...");
        System.out.println("   Desde: " + emailSender);
        System.out.println("   Para: " + String.join(", ", toUsers));
        System.out.println("   Asunto: " + subject);

        if (resendApiKey == null || resendApiKey.isEmpty()) {
            throw new RuntimeException("RESEND_API_KEY no está configurada");
        }

        // Crear body para Resend
        Map<String, Object> body = new HashMap<>();
        body.put("from", "Force Gym <" + emailSender + ">");
        body.put("to", toUsers);
        body.put("subject", subject);
        body.put("html", htmlContent);

        // Headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(resendApiKey);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);

        // Enviar
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.postForEntity(RESEND_URL, request, String.class);

        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Error Resend API: " + response.getBody());
        }

        System.out.println("✅ Email enviado exitosamente via Resend");
    }
}
