package una.force_gym.domain;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "tbClientPasswordRecovery")
public class ClientPasswordResetToken {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "idPasswordRecovery")
    private Long idPasswordRecovery;
    
    @ManyToOne(targetEntity = Client.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "idClient")
    private Client client;
    
    @Column(name = "recoveryToken")
    private String recoveryToken;
    
    @Column(name = "timeCreated")
    private LocalDateTime timeCreated;

    @Column(name = "expiryDate")
    private LocalDateTime expiryDate;

    @Column(name = "clientFingerprint")
    private String clientFingerprint;

    @Column(name = "salt")
    private String salt;

    @Column(name = "verificationHash")
    private String verificationHash;

    @Column(name = "isUsed")
    private Boolean isUsed;

    public ClientPasswordResetToken() {}
    
    public ClientPasswordResetToken(Client client, String recoveryToken, String clientFingerprint, String salt, String verificationHash, Long tokenExpiry) {
        this.client = client;
        this.recoveryToken = recoveryToken;
        this.clientFingerprint = clientFingerprint;
        this.salt = salt;
        this.verificationHash = verificationHash;
        this.timeCreated = LocalDateTime.now();
        this.expiryDate = calculateExpiryDate();
        this.isUsed = false;
    }

    private LocalDateTime calculateExpiryDate() {
        return this.timeCreated.plusMinutes(30);
    }
    
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }

    public Long getIdPasswordRecovery() {
        return idPasswordRecovery;
    }

    public void setIdPasswordRecovery(Long idPasswordRecovery) {
        this.idPasswordRecovery = idPasswordRecovery;
    }

    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public String getRecoveryToken() {
        return recoveryToken;
    }

    public void setRecoveryToken(String recoveryToken) {
        this.recoveryToken = recoveryToken;
    }

    public LocalDateTime getTimeCreated() {
        return timeCreated;
    }

    public void setTimeCreated(LocalDateTime timeCreated) {
        this.timeCreated = timeCreated;
    }

    public LocalDateTime getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(LocalDateTime expiryDate) {
        this.expiryDate = expiryDate;
    }

    public String getClientFingerprint() {
        return clientFingerprint;
    }

    public void setClientFingerprint(String clientFingerprint) {
        this.clientFingerprint = clientFingerprint;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getVerificationHash() {
        return verificationHash;
    }

    public void setVerificationHash(String verificationHash) {
        this.verificationHash = verificationHash;
    }

    public Boolean getIsUsed() {
        return isUsed;
    }

    public void setIsUsed(Boolean isUsed) {
        this.isUsed = isUsed;
    }
}
