package una.force_gym.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.TokenExpiredException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthFilter extends OncePerRequestFilter {
    
    @Autowired
    private final UserAuthenticationProvider userAuthenticationProvider;

    public JwtAuthFilter(UserAuthenticationProvider userAuthenticationProvider) {
        this.userAuthenticationProvider = userAuthenticationProvider;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse,
            FilterChain filterChain) throws ServletException, IOException {
        String header = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7); 
    
            logger.info("Header recibido: " + header);
            logger.info("Token recibido: " + token);

            try {
                Authentication auth = userAuthenticationProvider.validateToken(token);
                logger.info("Token válido para usuario: " + auth.getName());
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (TokenExpiredException e) {
                logger.warn("Token expirado");
            } catch (Exception e) {
                logger.error("Error validando token: ", e);
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
