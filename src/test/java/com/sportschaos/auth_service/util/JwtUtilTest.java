package com.sportschaos.auth_service.util;

import com.sportschaos.auth_service.entity.Role;
import com.sportschaos.auth_service.entity.User;
import com.sportschaos.auth_service.entity.UserStatus;
import io.jsonwebtoken.MalformedJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtUtilTest {

    private JwtUtil jwtUtil;
    private User testUser;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    @BeforeEach
    void setUp() throws Exception {
        // ✅ Generate test RSA keys programmatically
        KeyPair keyPair = generateTestRSAKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        // ✅ Create JwtUtil and inject keys
        jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "privateKey", privateKey);
        ReflectionTestUtils.setField(jwtUtil, "publicKey", publicKey);
        ReflectionTestUtils.setField(jwtUtil, "jwtExpiration", 3600000L);

        // Create test user
        testUser = new User();
        testUser.setId(1L);
        testUser.setEmail("test@example.com");
        testUser.setPassword("password");
        testUser.setName("Test User");
        testUser.setRole(Role.USER);
        testUser.setStatus(UserStatus.ACTIVE);
    }

    /**
     * Helper method to generate test RSA key pair
     */
    private KeyPair generateTestRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    @Test
    void generateToken_ShouldReturnValidToken() {
        // When
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", testUser.getRole().name());
        claims.put("userId", testUser.getId());

        String token = jwtUtil.generateToken(testUser, claims);

        // Then
        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();
        assertThat(token.split("\\.")).hasSize(3); // JWT has 3 parts: header.payload.signature
    }

    @Test
    void generateTokenWithExtraClaims_ShouldIncludeClaims() {
        // Given
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("role", "USER");
        extraClaims.put("userId", 1L);

        // When
        String token = jwtUtil.generateToken(testUser, extraClaims);

        // Then
        assertThat(token).isNotNull();
        String extractedRole = jwtUtil.extractClaim(token, claims -> claims.get("role", String.class));
        Long extractedUserId = jwtUtil.extractClaim(token, claims -> claims.get("userId", Long.class));

        assertThat(extractedRole).isEqualTo("USER");
        assertThat(extractedUserId).isEqualTo(1L);
    }

    @Test
    void extractUsername_ShouldReturnCorrectUsername() {
        // Given
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", testUser.getRole().name());
        String token = jwtUtil.generateToken(testUser, claims);

        // When
        String username = jwtUtil.extractUsername(token);

        // Then
        assertThat(username).isEqualTo("test@example.com");
    }

    @Test
    void extractExpiration_ShouldReturnFutureDate() {
        // Given
        Map<String, Object> claims = new HashMap<>();
        String token = jwtUtil.generateToken(testUser, claims);

        // When
        Date expiration = jwtUtil.extractClaim(token, io.jsonwebtoken.Claims::getExpiration);

        // Then
        assertThat(expiration).isAfter(new Date());
        assertThat(expiration).isBefore(new Date(System.currentTimeMillis() + 3700000L));
    }

    @Test
    void isTokenValid_WithValidToken_ShouldReturnTrue() {
        // Given
        Map<String, Object> claims = new HashMap<>();
        String token = jwtUtil.generateToken(testUser, claims);

        // When
        Boolean isValid = jwtUtil.isTokenValid(token, testUser);

        // Then
        assertThat(isValid).isTrue();
    }

    @Test
    void isTokenValid_WithoutUserDetails_ShouldReturnTrue() {
        // Given
        Map<String, Object> claims = new HashMap<>();
        String token = jwtUtil.generateToken(testUser, claims);

        // When
        Boolean isValid = jwtUtil.isTokenValid(token);

        // Then
        assertThat(isValid).isTrue();
    }

    @Test
    void isTokenValid_WithInvalidUser_ShouldReturnFalse() {
        // Given
        Map<String, Object> claims = new HashMap<>();
        String token = jwtUtil.generateToken(testUser, claims);

        User differentUser = new User();
        differentUser.setEmail("different@example.com");

        // When
        Boolean isValid = jwtUtil.isTokenValid(token, differentUser);

        // Then
        assertThat(isValid).isFalse();
    }

    @Test
    void isTokenValid_WithMalformedToken_ShouldReturnFalse() {
        // Given
        String malformedToken = "invalid.token.here";

        // When
        Boolean isValid = jwtUtil.isTokenValid(malformedToken);

        // Then
        assertThat(isValid).isFalse();
    }

    @Test
    void extractUsername_WithMalformedToken_ShouldThrowException() {
        // Given
        String malformedToken = "invalid.token.here";

        // When/Then
        assertThatThrownBy(() -> jwtUtil.extractUsername(malformedToken))
                .isInstanceOf(io.jsonwebtoken.JwtException.class);
    }

    @Test
    void extractAllClaims_WithValidToken_ShouldReturnClaims() {
        // Given
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("role", "USER");
        extraClaims.put("userId", 1L);
        extraClaims.put("customField", "customValue");

        String token = jwtUtil.generateToken(testUser, extraClaims);

        // When
        String role = jwtUtil.extractClaim(token, claims -> claims.get("role", String.class));
        Long userId = jwtUtil.extractClaim(token, claims -> claims.get("userId", Long.class));
        String customField = jwtUtil.extractClaim(token, claims -> claims.get("customField", String.class));

        // Then
        assertThat(role).isEqualTo("USER");
        assertThat(userId).isEqualTo(1L);
        assertThat(customField).isEqualTo("customValue");
    }

    @Test
    void tokenSignedWithDifferentKey_ShouldFailValidation() throws Exception {
        // Given - Generate a different key pair
        KeyPair differentKeyPair = generateTestRSAKeyPair();

        // Create a different JwtUtil with different keys
        JwtUtil differentJwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(differentJwtUtil, "privateKey", differentKeyPair.getPrivate());
        ReflectionTestUtils.setField(differentJwtUtil, "publicKey", differentKeyPair.getPublic());
        ReflectionTestUtils.setField(differentJwtUtil, "jwtExpiration", 3600000L);

        Map<String, Object> claims = new HashMap<>();
        String tokenFromDifferentKey = differentJwtUtil.generateToken(testUser, claims);

        // When - Try to validate with original jwtUtil (different public key)
        Boolean isValid = jwtUtil.isTokenValid(tokenFromDifferentKey);

        // Then - Should fail because signature doesn't match
        assertThat(isValid).isFalse();
    }

    @Test
    void expiredToken_ShouldFailValidation() throws InterruptedException {
        // Given - Create JwtUtil with very short expiration (1 second)
        JwtUtil shortExpiryJwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(shortExpiryJwtUtil, "privateKey", privateKey);
        ReflectionTestUtils.setField(shortExpiryJwtUtil, "publicKey", publicKey);
        ReflectionTestUtils.setField(shortExpiryJwtUtil, "jwtExpiration", 1000L); // 1 second

        Map<String, Object> claims = new HashMap<>();
        String token = shortExpiryJwtUtil.generateToken(testUser, claims);

        // Wait for token to expire
        Thread.sleep(1500);

        // When
        Boolean isValid = jwtUtil.isTokenValid(token);

        // Then
        assertThat(isValid).isFalse();
    }
}
