package una.force_gym.config;


import java.util.Base64;
import java.util.Collections;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import jakarta.annotation.PostConstruct;
import una.force_gym.domain.Client;
import una.force_gym.dto.UserDTO;
import una.force_gym.repository.ClientRepository;
import una.force_gym.service.UserService;

import java.util.List;

@Component
public class UserAuthenticationProvider {

    @Value("${security.jwt.token.secret-key:secret-key}")
    private String secretKey;

    @Autowired
    private UserService userService;

    @Autowired
    private ClientRepository clientRepository;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String createToken(String username) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + 12 * 60 * 60 * 1000); // 12 horas

        Algorithm algorithm = Algorithm.HMAC256(secretKey);
        return JWT.create()
                .withSubject(username)
                .withIssuedAt(now)
                .withExpiresAt(validity)
                .sign(algorithm);
    }

    public Authentication validateToken(String token) {
        Algorithm algorithm = Algorithm.HMAC256(secretKey);

        JWTVerifier verifier = JWT.require(algorithm)
                .build();

        DecodedJWT decoded = verifier.verify(token);
        String subject = decoded.getSubject();

        // Primero intentar buscar como usuario
        try {
            UserDTO user = userService.findByUsername(subject);
            if (user != null) {
                return new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList());
            }
        } catch (Exception e) {
            // No es un usuario, intentar buscar como cliente
        }

        // Si no es un usuario, buscar como cliente por número de identificación
        List<Client> allClients = clientRepository.findAll();
        Client client = allClients.stream()
            .filter(c -> c.getPerson() != null && 
                        c.getPerson().getIdentificationNumber() != null &&
                        c.getPerson().getIdentificationNumber().equals(subject) &&
                        Long.valueOf(0L).equals(c.getIsDeleted()))
            .findFirst()
            .orElse(null);

        if (client != null) {
            // Crear un UserDTO "virtual" para el cliente
            UserDTO clientAsUser = new UserDTO();
            clientAsUser.setIdUser(client.getIdClient()); // Usar el ID del cliente
            clientAsUser.setPerson(client.getPerson());
            clientAsUser.setUsername(client.getPerson().getIdentificationNumber());
            clientAsUser.setIsDeleted(client.getIsDeleted());
            // role será null para clientes, lo cual está bien
            
            return new UsernamePasswordAuthenticationToken(clientAsUser, null, Collections.emptyList());
        }

        return null;
    }

    public String getUsernameFromToken(String token) {
        Algorithm algorithm = Algorithm.HMAC256(secretKey);

        JWTVerifier verifier = JWT.require(algorithm)
                .build();

        DecodedJWT decoded = verifier.verify(token);
        return decoded.getSubject();
    }

}
