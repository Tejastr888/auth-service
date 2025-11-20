package com.sportschaos.auth_service.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "verification_otps")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerificationOTP {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long userId;

    @Column(nullable = false, length = 6)
    private String otpCode;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private Boolean isUsed = false;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OTPType type = OTPType.EMAIL_VERIFICATION;

    @Column(name = "attempts")
    private Integer attempts = 0;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        if (expiresAt == null) {
            expiresAt = LocalDateTime.now().plusMinutes(10); // 10-minute expiry
        }
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return !isUsed && !isExpired() && attempts < 5;
    }
}
