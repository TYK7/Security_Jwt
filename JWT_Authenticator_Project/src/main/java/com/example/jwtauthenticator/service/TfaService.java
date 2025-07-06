package com.example.jwtauthenticator.service;

import com.example.jwtauthenticator.entity.User;
import com.example.jwtauthenticator.repository.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TfaService {

    @Autowired
    private UserRepository userRepository;

    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public String generateNewSecret(String username) {
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (!userOptional.isPresent()) {
            throw new RuntimeException("User not found");
        }
        User user = userOptional.get();

        final GoogleAuthenticatorKey key = gAuth.createCredentials();
        user.setTfaSecret(key.getKey());
        userRepository.save(user);
        return key.getKey();
    }

    public boolean verifyCode(String username, int code) {
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (!userOptional.isPresent()) {
            throw new RuntimeException("User not found");
        }
        User user = userOptional.get();

        if (user.getTfaSecret() == null) {
            throw new RuntimeException("2FA not set up for this user");
        }

        return gAuth.authorize(user.getTfaSecret(), code);
    }

    public void enableTfa(String username) {
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (!userOptional.isPresent()) {
            throw new RuntimeException("User not found");
        }
        User user = userOptional.get();
        user.setTfaEnabled(true);
        userRepository.save(user);
    }

    public void disableTfa(String username) {
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (!userOptional.isPresent()) {
            throw new RuntimeException("User not found");
        }
        User user = userOptional.get();
        user.setTfaEnabled(false);
        user.setTfaSecret(null);
        userRepository.save(user);
    }
}
