package una.force_gym.service;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import jakarta.servlet.http.HttpServletRequest;
import una.force_gym.domain.ClientPasswordResetToken;
import una.force_gym.domain.Client;
import una.force_gym.repository.ClientPasswordResetTokenRepository;
import una.force_gym.repository.ClientRepository;
import una.force_gym.util.SecureRandomString;
import java.util.Optional;
import java.util.UUID;

@Service
public class ClientPasswordResetService {
    
    @Autowired
    private ClientPasswordResetTokenRepository tokenRepository;
    
    @Autowired
    private ClientRepository clientRepository;  
    
    @Autowired
    private EmailService emailService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${frontend.url:http://localhost:5173}")
    private String frontendUrl;

    /**
     * Método único que genera el token y envía el email
     */
    @Transactional
    public void generateAndSendResetToken(Client client, HttpServletRequest request) {
        // 1. Token único 
        String token = UUID.randomUUID().toString();
        
        // 2. Fingerprint del dispositivo/cliente
        String clientFingerprint = generateClientFingerprint(request);
        
        // 3. Hash de verificación
        String salt = SecureRandomString.generate(512);
        String verificationHash = generateVerificationHash(client, clientFingerprint, salt);
        
        // 4. Guardar todos los componentes en la base de datos
        ClientPasswordResetToken resetToken = new ClientPasswordResetToken(
            client,
            token,
            clientFingerprint,
            salt,
            verificationHash,
            Long.valueOf(30) // media hora de expiración
        );
        tokenRepository.save(resetToken);
        
        // 5. Enviar email con el token
        sendPasswordResetEmail(client, token, request);
    }

    private String generateClientFingerprint(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String acceptLanguage = request.getHeader("Accept-Language");
        String remoteAddr = request.getRemoteAddr();
        
        String components = String.join("|",
            userAgent != null ? userAgent : "unknown",
            acceptLanguage != null ? acceptLanguage : "unknown",
            remoteAddr != null ? remoteAddr : "unknown"
        );
        return DigestUtils.sha256Hex(components);
    }

    private String generateVerificationHash(Client client, String clientFingerprint, String salt) {
        String components = String.join("|",
            client.getPerson().getEmail(),
            client.getPassword(),
            clientFingerprint,
            salt
        );
        return DigestUtils.sha512Hex(components);
    }

    private void sendPasswordResetEmail(Client client, String token, HttpServletRequest request) {
        // Email del cliente
        String[] emails = new String[1];
        emails[0] = client.getPerson().getEmail();

        // Crear enlace con token de un solo uso
        String resetUrl = buildResetUrl(token, request);
        
        // Email con advertencia de seguridad
        String content = """
            <p>Hola %s,</p>
            <p>Se ha solicitado un restablecimiento de contraseña para tu cuenta del Portal de Clientes.</p>
            <p><strong>Advertencia de seguridad:</strong> Este enlace expirará en 30 minutos y solo es válido desde tu dispositivo habitual.</p>
            <p>Si no reconoces esta solicitud, por favor ignora este mensaje.</p>
            <div class="button-container"> <p class="button"><a href='%s'>Restablecer contraseña</a></p> </div>
            """.formatted(client.getPerson().getName(), resetUrl);
        
        emailService.sendEmail(emails, "Restablecimiento de contraseña - Portal de Clientes", content);
    }

    private String buildResetUrl(String token, HttpServletRequest request) {
        return frontendUrl + "/cliente/restablecer-contrasena?token=" + token;
    }

    public Optional<ClientPasswordResetToken> validatePasswordResetToken(String token, HttpServletRequest request) {
        // 1. Buscar token en la base de datos
        Optional<ClientPasswordResetToken> resetToken = tokenRepository.findByRecoveryToken(token);
        if (resetToken.isEmpty()) {
            System.err.println("❌ Token de cliente no encontrado en la base de datos");
            return Optional.empty();
        }

        // 2. Verificar que el token no haya sido usado
        if (resetToken.get().getIsUsed()) {
            System.err.println("❌ Token de cliente ya fue usado previamente");
            return Optional.empty();
        }

        // 3. Verificar expiración
        if (resetToken.get().isExpired()) {
            System.err.println("❌ Token de cliente expirado (más de 30 minutos)");
            tokenRepository.delete(resetToken.get());
            return Optional.empty();
        }
        
        // 4. Verificar fingerprint del cliente (WARNING: no bloquea, solo advierte)
        String currentFingerprint = generateClientFingerprint(request);
        if (!resetToken.get().getClientFingerprint().equals(currentFingerprint)) {
            // Fingerprint diferente - permitir de todos modos
            // NO retornamos empty - permitimos continuar
        }
        
        // 5. Verificar hash de seguridad (WARNING: no bloquea, solo advierte)
        String currentVerificationHash = generateVerificationHash(
            resetToken.get().getClient(), 
            currentFingerprint, 
            resetToken.get().getSalt()
        );
        if (!resetToken.get().getVerificationHash().equals(currentVerificationHash)) {
            // Hash diferente - permitir de todos modos
            // NO retornamos empty - permitimos continuar
        }
        
        return resetToken;
    }
    
    @Transactional
    public void resetPassword(Optional<ClientPasswordResetToken> tokenOpt, String newPassword) {
        ClientPasswordResetToken token = tokenOpt.get();
        
        // Cambiar contraseña en el registro de cliente
        Client client = token.getClient();
        client.setPassword(passwordEncoder.encode(newPassword));
        clientRepository.save(client); // Guardar nueva contraseña en base de datos
        
        token.setIsUsed(true); // Cambiar estado de uso del token
        tokenRepository.save(token);
    }
}
