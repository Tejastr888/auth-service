package com.sportschaos.auth_service.controller;

import com.sportschaos.auth_service.dto.AuthResponse;
import com.sportschaos.auth_service.dto.LoginRequest;
import com.sportschaos.auth_service.dto.RegisterRequest;
import com.sportschaos.auth_service.dto.UserDto;
import com.sportschaos.auth_service.entity.User;
import com.sportschaos.auth_service.service.AuthService;
import com.sportschaos.auth_service.service.UserService;
import com.sportschaos.auth_service.util.JwtUtil;
import org.springframework.security.core.userdetails.UserDetails;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;


import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration request received for email: {}", request.getEmail());
        AuthResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Validates a JWT token sent in the Authorization header.
     * Returns true if valid, false otherwise.
     */
    @GetMapping("/validate")
    public ResponseEntity<Boolean> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.ok(false);
            }
            String token = authHeader.substring(7);
            String username = jwtUtil.extractUsername(token);
            UserDetails userDetails = userService.loadUserByUsername(username);
            boolean valid = jwtUtil.isTokenValid(token, userDetails);
            return ResponseEntity.ok(valid);
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return ResponseEntity.ok(false);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login request received for email: {}", request.getEmail());
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser(Authentication authentication) {
        log.info("Get current user request for: {}", authentication.getName());

        User user = (User) authentication.getPrincipal();
        UserDto userDto = new UserDto(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getPhoneNumber(),
                user.getRole().name(),
                user.getStatus().name()
        );
        return ResponseEntity.ok(userDto);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout() {
        // In JWT, logout is typically handled on the client side
        // by removing the token from local storage
        return ResponseEntity.ok("Logged out successfully");
    }

    // Admin only endpoints
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        return userService.getUserById(id)
                .map(user -> ResponseEntity.ok(user))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/oauth2/providers")
    public ResponseEntity<List<String>> getOAuth2Providers() {
        List<String> providers = List.of("google", "github", "facebook");
        return ResponseEntity.ok(providers);
    }
}

