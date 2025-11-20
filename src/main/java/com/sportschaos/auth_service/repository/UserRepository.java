package com.sportschaos.auth_service.repository;

import com.sportschaos.auth_service.entity.User;
import com.sportschaos.auth_service.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    List<User> findByRole(Role role);

    @Query("SELECT u FROM User u WHERE u.role = :role AND u.status = 'ACTIVE'")
    List<User> findActiveUsersByRole(@Param("role") Role role);

    long countByRole(Role role);
}
