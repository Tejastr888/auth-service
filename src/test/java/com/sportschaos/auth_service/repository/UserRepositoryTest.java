package com.sportschaos.auth_service.repository;

import com.sportschaos.auth_service.entity.Role;
import com.sportschaos.auth_service.entity.User;
import com.sportschaos.auth_service.entity.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepository userRepository;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setName("John Doe");
        testUser.setEmail("john@example.com");
        testUser.setPassword("password123");
        testUser.setRole(Role.USER);
        testUser.setStatus(UserStatus.ACTIVE);
    }

    @Test
    void findByEmail_WhenUserExists_ShouldReturnUser() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        Optional<User> foundUser = userRepository.findByEmail("john@example.com");

        // Then
        assertThat(foundUser).isPresent();
        assertThat(foundUser.get().getName()).isEqualTo("John Doe");
        assertThat(foundUser.get().getEmail()).isEqualTo("john@example.com");
    }

    @Test
    void findByEmail_WhenUserDoesNotExist_ShouldReturnEmpty() {
        // When
        Optional<User> foundUser = userRepository.findByEmail("nonexistent@example.com");

        // Then
        assertThat(foundUser).isNotPresent();
    }

    @Test
    void existsByEmail_WhenUserExists_ShouldReturnTrue() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        boolean exists = userRepository.existsByEmail("john@example.com");

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void existsByEmail_WhenUserDoesNotExist_ShouldReturnFalse() {
        // When
        boolean exists = userRepository.existsByEmail("nonexistent@example.com");

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    void findByRole_ShouldReturnUsersWithSpecificRole() {
        // Given
        User adminUser = new User();
        adminUser.setName("Admin User");
        adminUser.setEmail("admin@example.com");
        adminUser.setPassword("password123");
        adminUser.setRole(Role.ADMIN);
        adminUser.setStatus(UserStatus.ACTIVE);

        entityManager.persistAndFlush(testUser);
        entityManager.persistAndFlush(adminUser);

        // When
        List<User> users = userRepository.findByRole(Role.USER);
        List<User> admins = userRepository.findByRole(Role.ADMIN);

        // Then
        assertThat(users).hasSize(1);
        assertThat(users.get(0).getRole()).isEqualTo(Role.USER);
        assertThat(admins).hasSize(1);
        assertThat(admins.get(0).getRole()).isEqualTo(Role.ADMIN);
    }

    @Test
    void countByRole_ShouldReturnCorrectCount() {
        // Given
        User anotherUser = new User();
        anotherUser.setName("Jane Doe");
        anotherUser.setEmail("jane@example.com");
        anotherUser.setPassword("password123");
        anotherUser.setRole(Role.USER);
        anotherUser.setStatus(UserStatus.ACTIVE);

        entityManager.persistAndFlush(testUser);
        entityManager.persistAndFlush(anotherUser);

        // When
        long userCount = userRepository.countByRole(Role.USER);
        long adminCount = userRepository.countByRole(Role.ADMIN);

        // Then
        assertThat(userCount).isEqualTo(2);
        assertThat(adminCount).isEqualTo(0);
    }
}

