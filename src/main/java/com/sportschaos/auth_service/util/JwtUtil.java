package com.sportschaos.auth_service.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Component
public class JwtUtil {

    @Value("${jwt.private-key:#{null}}")
    private Resource privateKeyResource;

    @Value("${jwt.public-key:#{null}}")
    private Resource publicKeyResource;

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // ============== INITIALIZATION ==============

    @PostConstruct
    public void init() throws Exception {
        log.info("🔑 Initializing JWT keys...");
        
        // Priority 1: Try environment variables (for Railway/Cloud)
        String privateKeyEnv = System.getenv("JWT_PRIVATE_KEY");
        String publicKeyEnv = System.getenv("JWT_PUBLIC_KEY");
        
        // Priority 2: Try Base64 encoded environment variables
        String privateKeyBase64 = System.getenv("JWT_PRIVATE_KEY_BASE64");
        String publicKeyBase64 = System.getenv("JWT_PUBLIC_KEY_BASE64");
        
        if (privateKeyEnv != null && !privateKeyEnv.trim().isEmpty()) {
            log.info("📦 Loading keys from JWT_PRIVATE_KEY/JWT_PUBLIC_KEY environment variables");
            this.privateKey = loadPrivateKeyFromString(privateKeyEnv);
            this.publicKey = loadPublicKeyFromString(publicKeyEnv);
            log.info("✅ JWT keys loaded from environment variables");
        } else if (privateKeyBase64 != null && !privateKeyBase64.trim().isEmpty()) {
            log.info("📦 Loading keys from Base64 environment variables");
            this.privateKey = loadPrivateKeyFromBase64(privateKeyBase64);
            this.publicKey = loadPublicKeyFromBase64(publicKeyBase64);
            log.info("✅ JWT keys loaded from Base64 environment variables");
        } else if (privateKeyResource != null && privateKeyResource.exists()) {
            log.info("📁 Loading keys from classpath resources (Local Development)");
            this.privateKey = loadPrivateKeyFromResource();
            this.publicKey = loadPublicKeyFromResource();
            log.info("✅ JWT keys loaded from classpath");
        } else {
            String error = "❌ No JWT keys found! Check configuration.";
            log.error(error);
            throw new RuntimeException(error);
        }
        
        log.info("🔐 JWT Util initialized successfully with RSA-256 keys");
    }

    // ============== TOKEN GENERATION (Auth-Service Only) ==============

    public String generateToken(UserDetails userDetails, Map<String, Object> extraClaims) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    // ============== TOKEN VALIDATION (All Services) ==============

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    public boolean isTokenValid(String token) {
        try {
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // ============== EXTRACT CLAIMS ==============

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // ============== LOAD FROM ENVIRONMENT VARIABLES (RAILWAY/CLOUD) ==============

    /**
     * Load private key from PEM-formatted environment variable
     */
    private PrivateKey loadPrivateKeyFromString(String pemKey) throws Exception {
        try {
            String keyContent = pemKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
            
            byte[] keyBytes = Base64.getDecoder().decode(keyContent);
            
            // Try PKCS8 format first
            try {
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePrivate(spec);
            } catch (Exception e) {
                // If PKCS8 fails, try PKCS1 format
                log.warn("⚠️ PKCS8 failed, attempting PKCS1 conversion");
                return convertPKCS1ToPKCS8(keyBytes);
            }
        } catch (Exception e) {
            log.error("❌ Failed to load private key from environment: {}", e.getMessage());
            throw new RuntimeException("Failed to load private key from environment", e);
        }
    }

    /**
     * Load public key from PEM-formatted environment variable
     */
    private PublicKey loadPublicKeyFromString(String pemKey) throws Exception {
        try {
            String keyContent = pemKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
            
            byte[] keyBytes = Base64.getDecoder().decode(keyContent);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            log.error("❌ Failed to load public key from environment: {}", e.getMessage());
            throw new RuntimeException("Failed to load public key from environment", e);
        }
    }

    // ============== LOAD FROM BASE64 (ALTERNATIVE CLOUD FORMAT) ==============

    /**
     * Load private key from Base64-encoded PEM environment variable
     */
    private PrivateKey loadPrivateKeyFromBase64(String base64Key) throws Exception {
        try {
            // Decode base64 to get PEM content
            byte[] decodedKey = Base64.getDecoder().decode(base64Key);
            String pemContent = new String(decodedKey);
            
            // Use the standard PEM loader
            return loadPrivateKeyFromString(pemContent);
        } catch (Exception e) {
            log.error("❌ Failed to load private key from base64: {}", e.getMessage());
            throw new RuntimeException("Failed to load private key from base64", e);
        }
    }

    /**
     * Load public key from Base64-encoded PEM environment variable
     */
    private PublicKey loadPublicKeyFromBase64(String base64Key) throws Exception {
        try {
            // Decode base64 to get PEM content
            byte[] decodedKey = Base64.getDecoder().decode(base64Key);
            String pemContent = new String(decodedKey);
            
            // Use the standard PEM loader
            return loadPublicKeyFromString(pemContent);
        } catch (Exception e) {
            log.error("❌ Failed to load public key from base64: {}", e.getMessage());
            throw new RuntimeException("Failed to load public key from base64", e);
        }
    }

    // ============== LOAD FROM CLASSPATH (LOCAL DEVELOPMENT) ==============

    /**
     * Load private key from classpath resource file
     */
    private PrivateKey loadPrivateKeyFromResource() throws Exception {
        try (InputStream inputStream = privateKeyResource.getInputStream()) {
            String key = new String(inputStream.readAllBytes());
            return loadPrivateKeyFromString(key);
        } catch (Exception e) {
            log.error("❌ Failed to load private key from classpath: {}", e.getMessage());
            throw new RuntimeException("Failed to load private key from classpath", e);
        }
    }

    /**
     * Load public key from classpath resource file
     */
    private PublicKey loadPublicKeyFromResource() throws Exception {
        try (InputStream inputStream = publicKeyResource.getInputStream()) {
            String key = new String(inputStream.readAllBytes());
            return loadPublicKeyFromString(key);
        } catch (Exception e) {
            log.error("❌ Failed to load public key from classpath: {}", e.getMessage());
            throw new RuntimeException("Failed to load public key from classpath", e);
        }
    }

    // ============== PKCS1 TO PKCS8 CONVERSION ==============

    /**
     * Convert PKCS#1 format (RSA PRIVATE KEY) to PKCS#8 format (PRIVATE KEY)
     * This handles keys generated with: openssl genrsa
     */
    private PrivateKey convertPKCS1ToPKCS8(byte[] pkcs1Bytes) throws Exception {
        try {
            int pkcs1Length = pkcs1Bytes.length;
            int totalLength = pkcs1Length + 22;
            byte[] pkcs8Header = new byte[] {
                0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff), (byte) (totalLength & 0xff),
                0x2, 0x1, 0x0, // version
                0x30, 0xd, 0x6, 0x9, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, 
                (byte) 0xf7, 0xd, 0x1, 0x1, 0x1, 0x5, 0x0,
                0x4, (byte) 0x82, (byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff)
            };
            
            byte[] pkcs8bytes = new byte[pkcs8Header.length + pkcs1Bytes.length];
            System.arraycopy(pkcs8Header, 0, pkcs8bytes, 0, pkcs8Header.length);
            System.arraycopy(pkcs1Bytes, 0, pkcs8bytes, pkcs8Header.length, pkcs1Bytes.length);
            
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            log.error("❌ PKCS1 to PKCS8 conversion failed: {}", e.getMessage());
            throw new RuntimeException("Failed to convert PKCS1 to PKCS8", e);
        }
    }

    // ============== GETTERS ==============

    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
