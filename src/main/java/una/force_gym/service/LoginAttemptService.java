package una.force_gym.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Servicio para controlar intentos de login y prevenir ataques de fuerza bruta
 * - Máximo 5 intentos por IP en 1 minuto
 * - Bloqueo de 5 minutos si se excede el límite
 */
@Service
public class LoginAttemptService {

    private static final int MAX_ATTEMPTS = 5;
    private static final int ATTEMPT_WINDOW_MINUTES = 1;
    private static final int BLOCK_DURATION_MINUTES = 5;

    // Cache para rastrear intentos de login (IP -> contador de intentos)
    private final Cache<String, Integer> attemptsCache;
    
    // Cache para IPs bloqueadas (IP -> timestamp del bloqueo)
    private final Cache<String, Long> blockedCache;

    public LoginAttemptService() {
        // Caché de intentos: expira después de 1 minuto
        this.attemptsCache = Caffeine.newBuilder()
                .expireAfterWrite(ATTEMPT_WINDOW_MINUTES, TimeUnit.MINUTES)
                .maximumSize(1000)
                .build();

        // Caché de bloqueos: expira después de 5 minutos
        this.blockedCache = Caffeine.newBuilder()
                .expireAfterWrite(BLOCK_DURATION_MINUTES, TimeUnit.MINUTES)
                .maximumSize(1000)
                .build();
    }

    /**
     * Registra un intento de login fallido
     * @param ip Dirección IP del cliente
     */
    public void loginFailed(String ip) {
        int attempts = attemptsCache.get(ip, k -> 0) + 1;
        attemptsCache.put(ip, attempts);

        if (attempts >= MAX_ATTEMPTS) {
            blockedCache.put(ip, System.currentTimeMillis());
            System.out.println("🚫 IP bloqueada por exceder intentos: " + ip);
        }
    }

    /**
     * Limpia los intentos de login para una IP (cuando el login es exitoso)
     * @param ip Dirección IP del cliente
     */
    public void loginSucceeded(String ip) {
        attemptsCache.invalidate(ip);
        blockedCache.invalidate(ip);
    }

    /**
     * Verifica si una IP está bloqueada
     * @param ip Dirección IP del cliente
     * @return true si la IP está bloqueada, false en caso contrario
     */
    public boolean isBlocked(String ip) {
        return blockedCache.getIfPresent(ip) != null;
    }

    /**
     * Obtiene el número de intentos restantes para una IP
     * @param ip Dirección IP del cliente
     * @return Número de intentos restantes antes del bloqueo
     */
    public int getRemainingAttempts(String ip) {
        int attempts = attemptsCache.get(ip, k -> 0);
        return Math.max(0, MAX_ATTEMPTS - attempts);
    }

    /**
     * Obtiene el tiempo restante de bloqueo en minutos
     * @param ip Dirección IP del cliente
     * @return Minutos restantes de bloqueo, o 0 si no está bloqueada
     */
    public long getRemainingBlockTime(String ip) {
        Long blockTime = blockedCache.getIfPresent(ip);
        if (blockTime == null) {
            return 0;
        }
        
        long elapsedMinutes = TimeUnit.MILLISECONDS.toMinutes(System.currentTimeMillis() - blockTime);
        return Math.max(0, BLOCK_DURATION_MINUTES - elapsedMinutes);
    }

    /**
     * Obtiene el número actual de intentos para una IP
     * @param ip Dirección IP del cliente
     * @return Número de intentos realizados
     */
    public int getAttempts(String ip) {
        return attemptsCache.get(ip, k -> 0);
    }
}
