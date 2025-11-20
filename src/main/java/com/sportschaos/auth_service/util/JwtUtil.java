//package com.sportschaos.auth_service.util;
//
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.core.io.Resource;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Component;
//
//
//import java.nio.file.Files;
//import java.security.KeyFactory;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.X509EncodedKeySpec;
//import java.util.Base64;
//import java.util.Date;
//
//import java.util.Map;
//import java.util.function.Function;
//
//@Slf4j
//@Component
//public class JwtUtil {
//
//    @Value("${jwt.private-key}")
//    private Resource privateKeyResource;
//
//    @Value("${jwt.public-key}")
//    private Resource publicKeyResource;
//
//    @Value("${jwt.expiration}")
//    private Long jwtExpiration;
//
//    private PrivateKey privateKey;
//    private PublicKey publicKey;
//
//    // Load keys when component is created
//    @jakarta.annotation.PostConstruct
//    public void init() throws Exception {
//        this.privateKey = loadPrivateKey();
//        this.publicKey = loadPublicKey();
//        log.info("RSA keys loaded successfully");
//    }
//
//    // ============== TOKEN GENERATION (Auth-Service Only) ==============
//
//    public String generateToken(UserDetails userDetails, Map<String, Object> extraClaims) {
//        return buildToken(extraClaims, userDetails, jwtExpiration);
//    }
//
//    private String buildToken(
//            Map<String, Object> extraClaims,
//            UserDetails userDetails,
//            long expiration
//    ) {
//        return Jwts.builder()
//                .setClaims(extraClaims)
//                .setSubject(userDetails.getUsername())
//                .setIssuedAt(new Date(System.currentTimeMillis()))
//                .setExpiration(new Date(System.currentTimeMillis() + expiration))
//                .signWith(privateKey, SignatureAlgorithm.RS256)  // Sign with PRIVATE key
//                .compact();
//    }
//
//    // ============== TOKEN VALIDATION (All Services) ==============
//
//    public boolean isTokenValid(String token, UserDetails userDetails) {
//        final String username = extractUsername(token);
//        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
//    }
//
//    public boolean isTokenValid(String token) {
//        try {
//            extractAllClaims(token);
//            return !isTokenExpired(token);
//        } catch (Exception e) {
//            log.error("Token validation failed: {}", e.getMessage());
//            return false;
//        }
//    }
//
//    private boolean isTokenExpired(String token) {
//        return extractExpiration(token).before(new Date());
//    }
//
//    // ============== EXTRACT CLAIMS ==============
//
//    public String extractUsername(String token) {
//        return extractClaim(token, Claims::getSubject);
//    }
//
//    private Date extractExpiration(String token) {
//        return extractClaim(token, Claims::getExpiration);
//    }
//
//    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        final Claims claims = extractAllClaims(token);
//        return claimsResolver.apply(claims);
//    }
//
//    private Claims extractAllClaims(String token) {
//        return Jwts.parser()
//                .setSigningKey(publicKey)  // Verify with PUBLIC key
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }
//
//    // ============== KEY LOADING ==============
//
//    private PrivateKey loadPrivateKey() throws Exception {
//        String key = new String(Files.readAllBytes(privateKeyResource.getFile().toPath()));
//
//        // Remove headers and whitespace
//        key = key.replace("-----BEGIN PRIVATE KEY-----", "")
//                .replace("-----END PRIVATE KEY-----", "")
//                .replaceAll("\\s", "");
//
//        byte[] keyBytes = Base64.getDecoder().decode(key);
//        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        return kf.generatePrivate(spec);
//    }
//
//    private PublicKey loadPublicKey() throws Exception {
//        String key = new String(Files.readAllBytes(publicKeyResource.getFile().toPath()));
//
//        // Remove headers and whitespace
//        key = key.replace("-----BEGIN PUBLIC KEY-----", "")
//                .replace("-----END PUBLIC KEY-----", "")
//                .replaceAll("\\s", "");
//
//        byte[] keyBytes = Base64.getDecoder().decode(key);
//        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        return kf.generatePublic(spec);
//    }
//
//    // ============== GETTERS ==============
//
//    public PublicKey getPublicKey() {
//        return publicKey;
//    }
//}
//

package com.sportschaos.auth_service.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.IOException;
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

    @Value("${jwt.private-key}")
    private Resource privateKeyResource;

    @Value("${jwt.public-key}")
    private Resource publicKeyResource;

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    // Load keys when component is created
    @jakarta.annotation.PostConstruct
    public void init() throws Exception {
        this.privateKey = loadPrivateKey();
        this.publicKey = loadPublicKey();
        log.info("RSA keys loaded successfully");
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

    // ============== KEY LOADING (FIXED) ==============

    private PrivateKey loadPrivateKey() throws Exception {
        // FIX: Use getInputStream() instead of getFile()
        try (InputStream inputStream = privateKeyResource.getInputStream()) {
            String key = new String(inputStream.readAllBytes());

            key = key.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(key);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }
    }

    private PublicKey loadPublicKey() throws Exception {
        // FIX: Use getInputStream() instead of getFile()
        try (InputStream inputStream = publicKeyResource.getInputStream()) {
            String key = new String(inputStream.readAllBytes());

            key = key.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }
    }

    // ============== GETTERS ==============

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
