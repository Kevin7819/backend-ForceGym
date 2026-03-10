package una.force_gym.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitarios para LoginAttemptService
 * Verifica el funcionamiento del rate limiting basado en IP
 */
class LoginAttemptServiceTest {

    private LoginAttemptService loginAttemptService;
    private static final String TEST_IP = "192.168.1.100";

    @BeforeEach
    void setUp() {
        loginAttemptService = new LoginAttemptService();
    }

    @Test
    void testLoginFailed_incrementsAttempts() {
        // Arrange
        assertEquals(5, loginAttemptService.getRemainingAttempts(TEST_IP));

        // Act
        loginAttemptService.loginFailed(TEST_IP);

        // Assert
        assertEquals(4, loginAttemptService.getRemainingAttempts(TEST_IP));
        assertEquals(1, loginAttemptService.getAttempts(TEST_IP));
    }

    @Test
    void testLoginFailed_blocksAfterMaxAttempts() {
        // Arrange
        assertFalse(loginAttemptService.isBlocked(TEST_IP));

        // Act - 5 intentos fallidos
        for (int i = 0; i < 5; i++) {
            loginAttemptService.loginFailed(TEST_IP);
        }

        // Assert
        assertTrue(loginAttemptService.isBlocked(TEST_IP));
        assertEquals(0, loginAttemptService.getRemainingAttempts(TEST_IP));
    }

    @Test
    void testLoginSucceeded_clearsAttempts() {
        // Arrange - registrar 3 intentos fallidos
        loginAttemptService.loginFailed(TEST_IP);
        loginAttemptService.loginFailed(TEST_IP);
        loginAttemptService.loginFailed(TEST_IP);
        assertEquals(3, loginAttemptService.getAttempts(TEST_IP));

        // Act - login exitoso
        loginAttemptService.loginSucceeded(TEST_IP);

        // Assert - intentos deben resetearse
        assertEquals(0, loginAttemptService.getAttempts(TEST_IP));
        assertEquals(5, loginAttemptService.getRemainingAttempts(TEST_IP));
        assertFalse(loginAttemptService.isBlocked(TEST_IP));
    }

    @Test
    void testLoginSucceeded_removesBlock() {
        // Arrange - bloquear IP
        for (int i = 0; i < 5; i++) {
            loginAttemptService.loginFailed(TEST_IP);
        }
        assertTrue(loginAttemptService.isBlocked(TEST_IP));

        // Act - login exitoso
        loginAttemptService.loginSucceeded(TEST_IP);

        // Assert - debe desbloquear
        assertFalse(loginAttemptService.isBlocked(TEST_IP));
        assertEquals(5, loginAttemptService.getRemainingAttempts(TEST_IP));
    }

    @Test
    void testMultipleIPs_areIndependent() {
        // Arrange
        String ip1 = "192.168.1.100";
        String ip2 = "192.168.1.101";

        // Act
        loginAttemptService.loginFailed(ip1);
        loginAttemptService.loginFailed(ip1);
        loginAttemptService.loginFailed(ip2);

        // Assert - cada IP tiene su propio contador
        assertEquals(2, loginAttemptService.getAttempts(ip1));
        assertEquals(1, loginAttemptService.getAttempts(ip2));
        assertEquals(3, loginAttemptService.getRemainingAttempts(ip1));
        assertEquals(4, loginAttemptService.getRemainingAttempts(ip2));
    }

    @Test
    void testRemainingAttempts_neverGoesNegative() {
        // Act - más de 5 intentos
        for (int i = 0; i < 10; i++) {
            loginAttemptService.loginFailed(TEST_IP);
        }

        // Assert - no debe ser negativo
        assertTrue(loginAttemptService.getRemainingAttempts(TEST_IP) >= 0);
        assertEquals(0, loginAttemptService.getRemainingAttempts(TEST_IP));
    }

    @Test
    void testGetRemainingBlockTime_returnsValidTime() throws InterruptedException {
        // Arrange - bloquear IP
        for (int i = 0; i < 5; i++) {
            loginAttemptService.loginFailed(TEST_IP);
        }

        // Act
        long remainingTime = loginAttemptService.getRemainingBlockTime(TEST_IP);

        // Assert - debe estar entre 4 y 5 minutos
        assertTrue(remainingTime >= 4 && remainingTime <= 5,
                "Remaining time should be between 4 and 5 minutes, but was: " + remainingTime);
    }

    @Test
    void testGetRemainingBlockTime_returnsZeroForNonBlockedIP() {
        // Act
        long remainingTime = loginAttemptService.getRemainingBlockTime(TEST_IP);

        // Assert
        assertEquals(0, remainingTime);
    }

    @Test
    void testNewIP_hasMaxAttempts() {
        // Act & Assert
        String newIp = "10.0.0.1";
        assertEquals(5, loginAttemptService.getRemainingAttempts(newIp));
        assertEquals(0, loginAttemptService.getAttempts(newIp));
        assertFalse(loginAttemptService.isBlocked(newIp));
    }

    @Test
    void testBoundaryCondition_fourthAttempt() {
        // Act - 4 intentos fallidos (justo antes del bloqueo)
        for (int i = 0; i < 4; i++) {
            loginAttemptService.loginFailed(TEST_IP);
        }

        // Assert - no debe estar bloqueada aún
        assertFalse(loginAttemptService.isBlocked(TEST_IP));
        assertEquals(1, loginAttemptService.getRemainingAttempts(TEST_IP));

        // Act - quinto intento
        loginAttemptService.loginFailed(TEST_IP);

        // Assert - ahora sí debe estar bloqueada
        assertTrue(loginAttemptService.isBlocked(TEST_IP));
        assertEquals(0, loginAttemptService.getRemainingAttempts(TEST_IP));
    }
}
