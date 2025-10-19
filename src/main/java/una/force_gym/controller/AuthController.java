package una.force_gym.controller;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import una.force_gym.config.UserAuthenticationProvider;
import una.force_gym.domain.PasswordResetToken;
import una.force_gym.domain.User;
import una.force_gym.dto.CredentialsDTO;
import una.force_gym.dto.LoginDTO;
import una.force_gym.dto.ResetPasswordDTO;
import una.force_gym.service.PasswordResetService;
import una.force_gym.service.ReCaptchaService;
import una.force_gym.service.UserService;
import una.force_gym.util.ApiResponse;

@RestController
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserAuthenticationProvider userAuthenticationProvider;

    @Autowired
    private ReCaptchaService reCaptchaService;

    @Autowired
    private PasswordResetService passwordResetService;
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid CredentialsDTO credentialsDTO) {
        /*if (!reCaptchaService.verifyRecaptcha(credentialsDTO.getRecaptchaToken())) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "message", "Recaptcha no válido"
            ));
        }*/

        LoginDTO loginDTO = userService.login(credentialsDTO);
        loginDTO.setToken(userAuthenticationProvider.createToken(loginDTO.getUsername()));

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("loggedUser", loginDTO);
        responseData.put("message", "Login exitoso");

        ApiResponse<Map<String, Object>> apiResponse = new ApiResponse<>();
        apiResponse.setData(responseData);
        apiResponse.setMessage("Login exitoso"); 

        return ResponseEntity.ok(apiResponse);
    }

    @PostMapping("/recoveryPassword")
    public ResponseEntity<ApiResponse<String>> forgotPassword(@RequestParam String email, HttpServletRequest httpRequest) {
        User user = userService.findByEmail(email);

        if(user.getIdUser()==null){
            ApiResponse<String> responseNotFound = new ApiResponse<>("Usuario no encontrado", null);
            return new ResponseEntity<>(responseNotFound, HttpStatus.BAD_REQUEST); 
        }
        
        String generatedToken = passwordResetService.generateSecurePasswordResetToken(user, httpRequest);
        passwordResetService.sendPasswordResetEmail(user, generatedToken, httpRequest);
        
        ApiResponse<String> response = new ApiResponse<>("Se ha enviado un link a su correo electrónico", null);
        return new ResponseEntity<>(response, HttpStatus.OK); 
    }

    @PostMapping("/resetPassword")
    public ResponseEntity<?> resetPassword(
        @RequestBody ResetPasswordDTO request,
        HttpServletRequest httpRequest
    ) {
        // 1. Validar token con todas las comprobaciones
        Optional<PasswordResetToken> resetToken = passwordResetService.validatePasswordResetToken(request.getToken(), httpRequest);
        if (!resetToken.isPresent()) {
            ApiResponse<String> response = new ApiResponse<>("Token no válido o expirado", null);
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
        
        // 2. Cambiar contraseña
        passwordResetService.resetPassword(resetToken, request.getNewPassword());
        
        return ResponseEntity.ok().build();
    }

}
