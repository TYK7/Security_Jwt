package com.example.jwtauthenticator.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "user_id")
    private UUID userId;

    @NotBlank
    @Column(unique = true)
    private String username;

    @NotBlank
    private String password;

    @Email
    @NotBlank
    @Column(unique = true)
    private String email;

    private String location;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "refresh_token")
    private String refreshToken;

    @Column(name = "tfa_secret")
    private String tfaSecret;

    @Column(name = "tfa_enabled")
    private boolean tfaEnabled;

    @Column(name = "tenant_id")
    private String tenantId;

    @Column(name = "email_verified")
    private boolean emailVerified;

    @Column(name = "verification_token")
    private String verificationToken;

    @PrePersist
    protected void onCreate() {
        if (userId == null) {
            userId = UUID.randomUUID();
        }
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        emailVerified = false; // Default to false on creation
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public enum Role {
        USER,
        ADMIN
    }
}
