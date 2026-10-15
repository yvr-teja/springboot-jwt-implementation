package com.springbootsecurity.springbootjwt.security;

import com.springbootsecurity.springbootjwt.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtils {

    // Secret key for signing JWT tokens (loaded from application.properties)
    @Value("${jwt.secret:404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970}")
    private String secretKey;

    // Access token expiration time in milliseconds (24 hours)
    @Value("${jwt.expiration:86400000}")
    private long jwtExpiration;

    // Refresh token expiration time in milliseconds (7 days)
    @Value("${jwt.refresh-expiration:604800000}")
    private long refreshTokenExpiration;

    // Generates a signing key from the secret using HMAC-SHA algorithm
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    // Generates an access token for the given user details
    public String generateToken(UserDetails userDetails) {
        return generateToken(userDetails, jwtExpiration);
    }

    // Generates a refresh token for the given user details
    public String generateRefreshToken(UserDetails userDetails) {
        return generateToken(userDetails, refreshTokenExpiration);
    }

    // Generates a token for a User entity (converts to UserDetails first)
    public String generateToken(User user) {
        org.springframework.security.core.userdetails.UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole().replace("ROLE_", ""))
                .build();
        return generateToken(userDetails);
    }

    // Generates a refresh token for a User entity
    public String generateRefreshToken(User user) {
        org.springframework.security.core.userdetails.UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole().replace("ROLE_", ""))
                .build();
        String jwt = generateToken(userDetails, refreshTokenExpiration);
        return jwt;
    }

    // Core token generation method with custom expiration
    private String generateToken(UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .subject(userDetails.getUsername())        // Set the JWT subject (username)
                .issuedAt(new Date(System.currentTimeMillis()))  // Set issued at timestamp
                .expiration(new Date(System.currentTimeMillis() + expiration))  // Set expiration
                .signWith(getSigningKey())                 // Sign with HMAC-SHA key
                .compact();                                // Build and compact the JWT
    }

    // Extracts the username (subject) from a JWT token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Generic method to extract any claim from a JWT token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Extracts all claims from a JWT token (requires validation)
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())               // Verify signature with our key
                .build()
                .parseSignedClaims(token)                  // Parse and validate the token
                .getPayload();                             // Return the claims payload
    }

    // Validates a token against user details (checks subject and expiration)
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // Checks if a token has expired
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Extracts the expiration date from a JWT token
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}