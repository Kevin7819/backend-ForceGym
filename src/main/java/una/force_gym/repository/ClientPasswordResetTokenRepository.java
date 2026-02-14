package una.force_gym.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import una.force_gym.domain.ClientPasswordResetToken;
import una.force_gym.domain.Client;

import java.util.Optional;

public interface ClientPasswordResetTokenRepository extends JpaRepository<ClientPasswordResetToken, Long> {
    Optional<ClientPasswordResetToken> findByRecoveryToken(String recoveryToken);
    Optional<ClientPasswordResetToken> findByClient(Client client);
}
