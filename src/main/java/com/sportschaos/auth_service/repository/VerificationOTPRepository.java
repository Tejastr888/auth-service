package com.sportschaos.auth_service.repository;

import com.sportschaos.auth_service.entity.VerificationOTP;
import com.sportschaos.auth_service.entity.OTPType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface VerificationOTPRepository extends JpaRepository<VerificationOTP, Long> {

    Optional<VerificationOTP> findByUserIdAndOtpCodeAndTypeAndIsUsedFalse(
            Long userId,
            String otpCode,
            OTPType type
    );

    Optional<VerificationOTP> findTopByUserIdAndTypeOrderByCreatedAtDesc(
            Long userId,
            OTPType type
    );

    void deleteByUserIdAndType(Long userId, OTPType type);

    void deleteByExpiresAtBefore(LocalDateTime dateTime);
}
