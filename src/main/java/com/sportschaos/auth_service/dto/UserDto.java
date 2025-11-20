package com.sportschaos.auth_service.dto;

public class UserDto {
    private Long id;
    private String name;
    private String email;
    private String phoneNumber;
    private String role;
    private String status;

    public UserDto(Long id, String name, String email, String phoneNumber, String role, String status) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.phoneNumber = phoneNumber;
        this.role = role;
        this.status = status;
    }

    // Getters
    public Long getId() { return id; }
    public String getName() { return name; }
    public String getEmail() { return email; }
    public String getPhoneNumber() { return phoneNumber; }
    public String getRole() { return role; }
    public String getStatus() { return status; }
}
