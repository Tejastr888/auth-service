package com.sportschaos.auth_service.service;



import com.sportschaos.auth_service.dto.AuthResponse;
import com.sportschaos.auth_service.dto.LoginRequest;
import com.sportschaos.auth_service.dto.RegisterRequest;
import com.sportschaos.auth_service.entity.Role;
import com.sportschaos.auth_service.entity.User;
import com.sportschaos.auth_service.entity.UserStatus;
import com.sportschaos.auth_service.exception.InvalidCredentialsException;
import com.sportschaos.auth_service.exception.UserAlreadyExistsException;
import com.sportschaos.auth_service.repository.UserRepository;
import com.sportschaos.auth_service.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private Authentication authentication;

    @InjectMocks
    private AuthService authService;

    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;
    private User testUser;

    @BeforeEach
    void setUp() {
        registerRequest = new RegisterRequest();
        registerRequest.setName("John Doe");
        registerRequest.setEmail("john@example.com");
        registerRequest.setPassword("password123");
        registerRequest.setPhoneNumber("+1234567890");
        registerRequest.setRole("USER");

        loginRequest = new LoginRequest();
        loginRequest.setEmail("john@example.com");
        loginRequest.setPassword("password123");

        testUser = new User();
        testUser.setId(1L);
        testUser.setName("John Doe");
        testUser.setEmail("john@example.com");
        testUser.setPassword("encodedPassword");
        testUser.setRole(Role.USER);
        testUser.setStatus(UserStatus.ACTIVE);
    }

    @Test
    void register_WithValidRequest_ShouldReturnAuthResponse() {
        // Given
        when(userRepository.existsByEmail(registerRequest.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(registerRequest.getPassword())).thenReturn("encodedPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(jwtUtil.generateToken(eq(testUser), any(Map.class))).thenReturn("mock-jwt-token");

        // When
        AuthResponse response = authService.register(registerRequest);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo("mock-jwt-token");
        assertThat(response.getUserId()).isEqualTo(1L);
        assertThat(response.getEmail()).isEqualTo("john@example.com");
        assertThat(response.getName()).isEqualTo("John Doe");
        assertThat(response.getRole()).isEqualTo("USER");

        verify(userRepository).existsByEmail(registerRequest.getEmail());
        verify(passwordEncoder).encode(registerRequest.getPassword());
        verify(userRepository).save(any(User.class));
        verify(jwtUtil).generateToken(eq(testUser), any(Map.class));
    }

    @Test
    void register_WithExistingEmail_ShouldThrowException() {
        // Given
        when(userRepository.existsByEmail(registerRequest.getEmail())).thenReturn(true);

        // When/Then
        assertThatThrownBy(() -> authService.register(registerRequest))
                .isInstanceOf(UserAlreadyExistsException.class)
                .hasMessage("User with email john@example.com already exists");

        verify(userRepository).existsByEmail(registerRequest.getEmail());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void login_WithValidCredentials_ShouldReturnAuthResponse() {
        // Given
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.getPrincipal()).thenReturn(testUser);
        when(jwtUtil.generateToken(eq(testUser), any(Map.class))).thenReturn("mock-jwt-token");

        // When
        AuthResponse response = authService.login(loginRequest);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getToken()).isEqualTo("mock-jwt-token");
        assertThat(response.getUserId()).isEqualTo(1L);
        assertThat(response.getEmail()).isEqualTo("john@example.com");

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtUtil).generateToken(eq(testUser), any(Map.class));
    }

    @Test
    void login_WithInvalidCredentials_ShouldThrowException() {
        // Given
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // When/Then
        assertThatThrownBy(() -> authService.login(loginRequest))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid email or password");

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtUtil, never()).generateToken(any(User.class), any(Map.class));
    }
}
