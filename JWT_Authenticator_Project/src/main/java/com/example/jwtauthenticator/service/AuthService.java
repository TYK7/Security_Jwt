package com.example.jwtauthenticator.service;

import com.example.jwtauthenticator.entity.User;
import com.example.jwtauthenticator.entity.User.Role;
import com.example.jwtauthenticator.model.AuthRequest;
import com.example.jwtauthenticator.model.AuthResponse;

import com.example.jwtauthenticator.model.RegisterRequest;
import com.example.jwtauthenticator.repository.UserRepository;
import com.example.jwtauthenticator.security.JwtUserDetailsService;
import com.example.jwtauthenticator.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class AuthService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EmailService emailService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public String registerUser(RegisterRequest request) {
        if (userRepository.existsByUsernameAndTenantId(request.getUsername(), request.getTenantId())) {
            throw new RuntimeException("Username already exists for this tenant");
        }
        if (userRepository.existsByEmailAndTenantId(request.getEmail(), request.getTenantId())) {
            throw new RuntimeException("Email already exists for this tenant");
        }

        User newUser = User.builder()
                .username(request.getUsername())
                .password(request.getPassword())
                .email(request.getEmail())
                .location(request.getLocation())
                .role(Role.USER) // Default role
                .tenantId(request.getTenantId())
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .emailVerified(false)
                .build();

        String verificationToken = UUID.randomUUID().toString();
        newUser.setVerificationToken(verificationToken);

        userDetailsService.save(newUser);

        String verificationLink = "http://192.168.1.22:8080/auth/verify-email?token=" + verificationToken;
        emailService.sendEmail(newUser.getEmail(), "Email Verification", "Please click the link to verify your email: " + verificationLink);

        return "User registered successfully. Please verify your email.";
    }

    public AuthResponse createAuthenticationToken(AuthRequest authenticationRequest) throws Exception {
        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword(), authenticationRequest.getTenantId());
        final UserDetails userDetails = userDetailsService
                .loadUserByUsernameAndTenantId(authenticationRequest.getUsername(), authenticationRequest.getTenantId());
        User user = userRepository.findByUsernameAndTenantId(authenticationRequest.getUsername(), authenticationRequest.getTenantId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.isEmailVerified()) {
            throw new RuntimeException("Email not verified. Please verify your email to login.");
        }

        final String token = jwtUtil.generateToken(userDetails, user.getUserId().toString());
        final String refreshToken = jwtUtil.generateRefreshToken(userDetails, user.getUserId().toString());

        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        return new AuthResponse(token, refreshToken);
    }

    public AuthResponse loginUser(AuthRequest authenticationRequest) throws Exception {
        return createAuthenticationToken(authenticationRequest);
    }

    public AuthResponse refreshToken(String oldRefreshToken) throws Exception {
        String username = jwtUtil.extractUsername(oldRefreshToken);
        String userId = jwtUtil.extractUserId(oldRefreshToken);
        // For multi-tenancy, we need to extract tenantId from the refresh token or pass it separately.
        // For simplicity, assuming tenantId is part of the JWT claims or derived from userId.
        // In a real-world scenario, you might store tenantId in the refresh token claims.
        User user = userRepository.findByUserId(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!user.getRefreshToken().equals(oldRefreshToken) || jwtUtil.isTokenExpired(oldRefreshToken)) {
            throw new RuntimeException("Invalid or expired refresh token");
        }

        final UserDetails userDetails = userDetailsService.loadUserByUsernameAndTenantId(username, user.getTenantId());
        final String newToken = jwtUtil.generateToken(userDetails, user.getUserId().toString());
        final String newRefreshToken = jwtUtil.generateRefreshToken(userDetails, user.getUserId().toString());

        user.setRefreshToken(newRefreshToken);
        userRepository.save(user);

        return new AuthResponse(newToken, newRefreshToken);
    }

    public String verifyEmail(String token) {
        User user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));

        user.setEmailVerified(true);
        user.setVerificationToken(null); // Clear the token after verification
        userRepository.save(user);
        return "Email verified successfully!";
    }

    private void authenticate(String username, String password, String tenantId) throws Exception {
        try {
            // Manual authentication for multi-tenant setup
            User user = userRepository.findByUsernameAndTenantId(username, tenantId)
                    .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
            
            if (!passwordEncoder.matches(password, user.getPassword())) {
                throw new BadCredentialsException("Invalid credentials");
            }
            
            // Additional checks can be added here (e.g., account enabled, not locked, etc.)
            
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}


