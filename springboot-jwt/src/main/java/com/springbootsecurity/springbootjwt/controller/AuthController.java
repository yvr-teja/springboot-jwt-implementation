package com.springbootsecurity.springbootjwt.controller;

import com.springbootsecurity.springbootjwt.dto.LoginResponse;
import com.springbootsecurity.springbootjwt.dto.TokenRefreshRequest;
import com.springbootsecurity.springbootjwt.dto.TokenRefreshResponse;
import com.springbootsecurity.springbootjwt.model.User;
import com.springbootsecurity.springbootjwt.repository.UserRepository;
import com.springbootsecurity.springbootjwt.security.JwtUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    // Manages user authentication (validates credentials via Spring Security)
    private final AuthenticationManager authenticationManager;
    // Persists and retrieves users from the database
    private final UserRepository userRepository;
    // Encodes passwords (BCrypt) before storing them
    private final PasswordEncoder passwordEncoder;
    // Handles JWT token generation and validation
    private final JwtUtils jwtUtils;

    public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository,
                          PasswordEncoder passwordEncoder, JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username already exists!"));
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        if (user.getRole() == null) user.setRole("ROLE_USER");
        userRepository.save(user);
        return ResponseEntity.ok(Map.of("message", "User registered successfully!"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            UserDetails userDetails = (org.springframework.security.core.userdetails.User) authentication.getPrincipal();
            String jwt = jwtUtils.generateToken(userDetails);
            String refreshToken = jwtUtils.generateRefreshToken(userDetails);
            return ResponseEntity.ok(new LoginResponse(jwt, refreshToken));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Login failed: " + e.getMessage()));
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
        String refreshToken = request.getRefreshToken();
        if (refreshToken == null || jwtUtils.isTokenExpired(refreshToken)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired refresh token!"));
        }
        String username = jwtUtils.extractUsername(refreshToken);
        com.springbootsecurity.springbootjwt.model.User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));
        String newAccessToken = jwtUtils.generateToken(user);
        String newRefreshToken = jwtUtils.generateRefreshToken(user);
        return ResponseEntity.ok(new TokenRefreshResponse(newAccessToken, newRefreshToken));
    }
}