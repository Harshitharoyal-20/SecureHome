
package com.security.home.controller;

import java.util.Map;

import com.security.home.security.PasswordVerificationFilter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/password")
public class PasswordVerificationController {

    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;

    public PasswordVerificationController(
            JdbcTemplate jdbcTemplate,
            PasswordEncoder passwordEncoder) {

        this.jdbcTemplate = jdbcTemplate;
        this.passwordEncoder = passwordEncoder;
    }

    public record PasswordRequest(String password) {}

    @PostMapping("/verify")
    public ResponseEntity<?> verifyPassword(
            @RequestBody PasswordRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {

        if (authentication == null
                || !(authentication.getPrincipal()
                instanceof OAuth2User oauth2User)) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "error",
                            "Please sign in with GitHub"));
        }

        if (request == null
                || request.password() == null
                || request.password().isBlank()) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error",
                            "Password is required"));
        }

        Object id = oauth2User.getAttributes().get("id");

        if (id == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "error",
                            "GitHub identity not found"));
        }

        var hashes = jdbcTemplate.query(
                "SELECT u.password_hash " +
                "FROM oauth_account_links o " +
                "JOIN users u ON u.user_id = o.user_id " +
                "WHERE o.provider = ? " +
                "AND o.provider_user_id = ? " +
                "AND u.status = 'ACTIVE'",
                (rs, rowNum) ->
                        rs.getString("password_hash"),
                "github",
                id.toString()
        );

        if (hashes.isEmpty()
                || hashes.get(0) == null
                || !passwordEncoder.matches(
                        request.password(),
                        hashes.get(0))) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "error",
                            "Invalid password"));
        }

        HttpSession session = httpRequest.getSession(true);

        session.setAttribute(
                PasswordVerificationFilter.VERIFIED_ATTRIBUTE,
                true);

        return ResponseEntity.ok(
                Map.of("verified", true));
    }

    @PostMapping("/reset")
    public ResponseEntity<?> resetVerification(
            HttpServletRequest request) {

        HttpSession session = request.getSession(false);

        if (session != null) {
            session.removeAttribute(
                    PasswordVerificationFilter.VERIFIED_ATTRIBUTE);
        }

        return ResponseEntity.ok(
                Map.of("verified", false));
    }
}
