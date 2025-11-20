package com.sportschaos.auth_service.controller;



import com.fasterxml.jackson.databind.ObjectMapper;
import com.sportschaos.auth_service.dto.LoginRequest;
import com.sportschaos.auth_service.dto.RegisterRequest;
import com.sportschaos.auth_service.entity.Role;
import com.sportschaos.auth_service.entity.User;
import com.sportschaos.auth_service.entity.UserStatus;
import com.sportschaos.auth_service.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureWebMvc
@ActiveProfiles("test")
@Transactional
class AuthControllerIntegrationTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();

        userRepository.deleteAll();
    }

    @Test
    void register_WithValidData_ShouldReturnCreatedStatus() throws Exception {
        // Given
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("John Doe");
        registerRequest.setEmail("john@example.com");
        registerRequest.setPassword("password123");
        registerRequest.setPhoneNumber("+1234567890");
        registerRequest.setRole("USER");

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.email").value("john@example.com"))
                .andExpect(jsonPath("$.name").value("John Doe"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void register_WithInvalidEmail_ShouldReturnBadRequest() throws Exception {
        // Given
        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("John Doe");
        registerRequest.setEmail("invalid-email");
        registerRequest.setPassword("password123");

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.validationErrors.email").exists());
    }

    @Test
    void register_WithExistingEmail_ShouldReturnConflict() throws Exception {
        // Given - Create existing user
        User existingUser = new User();
        existingUser.setName("Existing User");
        existingUser.setEmail("john@example.com");
        existingUser.setPassword(passwordEncoder.encode("password"));
        existingUser.setRole(Role.USER);
        existingUser.setStatus(UserStatus.ACTIVE);
        userRepository.save(existingUser);

        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setName("John Doe");
        registerRequest.setEmail("john@example.com");
        registerRequest.setPassword("password123");

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("User with email john@example.com already exists"));
    }

    @Test
    void login_WithValidCredentials_ShouldReturnToken() throws Exception {
        // Given - Create user
        User user = new User();
        user.setName("John Doe");
        user.setEmail("john@example.com");
        user.setPassword(passwordEncoder.encode("password123"));
        user.setRole(Role.USER);
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("john@example.com");
        loginRequest.setPassword("password123");

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.email").value("john@example.com"))
                .andExpect(jsonPath("$.name").value("John Doe"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void login_WithInvalidCredentials_ShouldReturnUnauthorized() throws Exception {
        // Given
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("nonexistent@example.com");
        loginRequest.setPassword("wrongpassword");

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }
}

