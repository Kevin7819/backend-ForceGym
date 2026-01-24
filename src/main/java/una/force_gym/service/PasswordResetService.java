package una.force_gym.service;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import jakarta.servlet.http.HttpServletRequest;
import una.force_gym.domain.PasswordResetToken;
import una.force_gym.domain.User;
import una.force_gym.repository.PasswordResetTokenRepository;
import una.force_gym.repository.UserRepository;
import una.force_gym.util.SecureRandomString;
import java.util.Optional;
import java.util.UUID;

@Service
public class PasswordResetService {
    
    @Autowired
    private PasswordResetTokenRepository tokenRepository;
    
    @Autowired
    private UserRepository userRepository;  
    
    @Autowired
    private EmailService emailService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;

    public String generateSecurePasswordResetToken(User user, HttpServletRequest request) {
        // 1. Token único 
        String token = UUID.randomUUID().toString();
        
        // 2. Fingerprint del dispositivo/cliente
        String clientFingerprint = generateClientFingerprint(request);
        
        // 3. Hash de verificación
        String salt = SecureRandomString.generate(512);
        String verificationHash = generateVerificationHash(user, clientFingerprint, salt);
        
        // 4. Guardar todos los componentes en la base de datos
        PasswordResetToken resetToken = new PasswordResetToken(
            user,
            token,
            clientFingerprint,
            salt,
            verificationHash,
            Long.valueOf(30) // media hora de expiración
        );
        tokenRepository.save(resetToken);
        
        return token;
    }

    private String generateClientFingerprint(HttpServletRequest request) {
        String components = String.join("|",
            request.getHeader("User-Agent"),
            request.getHeader("Accept-Language"),
            request.getRemoteAddr() 
        );
        return DigestUtils.sha256Hex(components);
    }

    private String generateVerificationHash(User user, String clientFingerprint, String salt) {
        String components = String.join("|",
            user.getPerson().getEmail(),
            user.getPassword(),
            clientFingerprint,
            salt
        );
        return DigestUtils.sha512Hex(components);
    }

    public void sendPasswordResetEmail(User user, String token, HttpServletRequest request) {
        // Email 
        String[] emails = new String[1];
        emails[0] = user.getPerson().getEmail();

        // Crear enlace con token de un solo uso
        String resetUrl = buildResetUrl(token, request);
        
        // Email con advertencia de seguridad
        String content = """
            <p>Se ha solicitado un restablecimiento de contraseña para tu cuenta.</p>
            <p><strong>Advertencia de seguridad:</strong> Este enlace expirará en 30 minutos y solo es válido desde tu dispositivo habitual.</p>
            <p>Si no reconoces esta solicitud, por favor ignora este mensaje.</p>
            <div class="button-container"> <p class="button"><a href='%s'>Restablecer contraseña</a></p> </div>
            """.formatted(resetUrl);
        
        emailService.sendEmail(emails, "Restablecimiento de contraseña", content);
    }

    private String buildResetUrl(String token, HttpServletRequest request) {
        return "https://frontend-forcegym-production.up.railway.app/reset-password?token=" + token;
    }

    public Optional<PasswordResetToken> validatePasswordResetToken(String token, HttpServletRequest request) {
        // 1. Buscar token en la base de datos
        Optional<PasswordResetToken> resetToken = tokenRepository.findByRecoveryToken(token);
        if (resetToken.isEmpty()) {
            return Optional.empty();
        }

        // 2. Verificar que el token no haya sido usado
        if (resetToken.get().getIsUsed()) {
            return Optional.empty();
        }

        // 3. Verificar expiración
        if (resetToken.get().isExpired()) {
            tokenRepository.delete(resetToken.get());
            return Optional.empty();
        }
        
        // 4. Verificar fingerprint del cliente
        String currentFingerprint = generateClientFingerprint(request);
        if (!resetToken.get().getClientFingerprint().equals(currentFingerprint)) {
            return Optional.empty();
        }
        
        // 5. Verificar hash de seguridad
        String currentVerificationHash = generateVerificationHash(resetToken.get().getUser(), currentFingerprint, resetToken.get().getSalt());
        if (!resetToken.get().getVerificationHash().equals(currentVerificationHash)) {
            return Optional.empty();
        }
        
        return resetToken;
    }
    
    @Transactional
    public void resetPassword(Optional<PasswordResetToken> tokenOpt, String newPassword) {
        PasswordResetToken token = tokenOpt.get();
        
        // Cambiar contraseña en el registro de usuario
        User user = token.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user); // Guardar nueva contraseña en base de datos
        
        token.setIsUsed(true); // Cambiar estado de uso del token
        tokenRepository.save(token);
        
    }
}