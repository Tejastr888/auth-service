package com.sportschaos.auth_service.service;

import com.sportschaos.auth_service.annotation.Loggable;
import com.sportschaos.auth_service.dto.AuthResponse;
import com.sportschaos.auth_service.dto.LoginRequest;
import com.sportschaos.auth_service.dto.RegisterRequest;
import com.sportschaos.auth_service.entity.Role;
import com.sportschaos.auth_service.entity.User;
import com.sportschaos.auth_service.exception.UserAlreadyExistsException;
import com.sportschaos.auth_service.exception.InvalidCredentialsException;
import com.sportschaos.auth_service.repository.UserRepository;
import com.sportschaos.auth_service.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @Transactional
    @Loggable(logResult = false) // Don't log the full token in result
    public AuthResponse register(RegisterRequest request) {
        // Check if user already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("User with email " + request.getEmail() + " already exists");
        }

        // Create new user
        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setPhoneNumber(request.getPhoneNumber());
        user.setRole(Role.valueOf(request.getRole().toUpperCase()));

        // Save user
        User savedUser = userRepository.save(user);

        // Generate JWT token
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("role", savedUser.getRole().name());
        extraClaims.put("userId", savedUser.getId());

        String token = jwtUtil.generateToken(savedUser, extraClaims);

        return new AuthResponse(
                token,
                savedUser.getId(),
                savedUser.getEmail(),
                savedUser.getName(),
                savedUser.getRole().name()
        );
    }

    @Loggable(logResult = false) // Don't log the full token in result
    public AuthResponse login(LoginRequest request) {
        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            // Get user details
            User user = (User) authentication.getPrincipal();

            // Generate JWT token
            Map<String, Object> extraClaims = new HashMap<>();
            extraClaims.put("role", user.getRole().name());
            extraClaims.put("userId", user.getId());

            String token = jwtUtil.generateToken(user, extraClaims);

            return new AuthResponse(
                    token,
                    user.getId(),
                    user.getEmail(),
                    user.getName(),
                    user.getRole().name()
            );

        } catch (Exception e) {
            throw new InvalidCredentialsException("Invalid email or password");
        }
    }
}