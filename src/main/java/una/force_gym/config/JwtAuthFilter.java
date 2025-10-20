package una.force_gym.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
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
    
            try {
                SecurityContextHolder.getContext().setAuthentication(
                        userAuthenticationProvider.validateToken(token));
            } catch (TokenExpiredException e) {
                SecurityContextHolder.clearContext();
                logger.warn("El token ha expirado: {}", e.getMessage());
                httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                httpServletResponse.setContentType("application/json");
                httpServletResponse.getWriter().write("{\"error\": \"Token expirado\"}");
                return;
            } catch (RuntimeException e) {
                SecurityContextHolder.clearContext();
                logger.error("Token no válido: {}", e.getMessage());
                httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                httpServletResponse.setContentType("application/json");
                httpServletResponse.getWriter().write("{\"error\": \"Token inválido\"}");
                return;
            }
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

}
