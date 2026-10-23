
package com.security.home.controller;

import com.security.home.entity.SecurityAlert;
import com.security.home.repository.SecurityAlertRepository;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/security-alerts")
@CrossOrigin(origins = {
    "http://localhost:5173",
    "https://secure-home-kappa.vercel.app"
})
public class SecurityAlertController {

    private final SecurityAlertRepository repository;
    private final JdbcTemplate jdbc;

    public SecurityAlertController(
            SecurityAlertRepository repository,
            JdbcTemplate jdbc) {
        this.repository = repository;
        this.jdbc = jdbc;
    }

    @GetMapping
    public List<SecurityAlert> getSecurityAlerts(
            Authentication authentication) {

        if (authentication == null
                || !authentication.isAuthenticated()
                || "anonymousUser".equals(
                    String.valueOf(authentication.getPrincipal()))) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Please log in"
            );
        }

        List<Map<String, Object>> users;

        if (authentication.getPrincipal() instanceof OAuth2User oauth) {
            Object providerId = oauth.getAttribute("id");

            if (providerId == null) {
                throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "GitHub account ID is missing"
                );
            }

            users = jdbc.queryForList(
                "SELECT u.user_id, r.role_name " +
                "FROM oauth_account_links o " +
                "JOIN users u ON u.user_id = o.user_id " +
                "JOIN roles r ON r.role_id = u.role_id " +
                "WHERE LOWER(o.provider) = 'github' " +
                "AND o.provider_user_id = ? " +
                "AND u.status = 'ACTIVE' " +
                "LIMIT 1",
                String.valueOf(providerId)
            );
        } else {
            users = jdbc.queryForList(
                "SELECT u.user_id, r.role_name " +
                "FROM users u " +
                "JOIN roles r ON r.role_id = u.role_id " +
                "WHERE LOWER(u.email) = LOWER(?) " +
                "AND u.status = 'ACTIVE' " +
                "LIMIT 1",
                authentication.getName()
            );
        }

        if (users.isEmpty()) {
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "No active application user is linked to this login"
            );
        }

        String role = String.valueOf(
            users.get(0).get("role_name")
        );

        if (!"ADMIN".equalsIgnoreCase(role)) {
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "You cannot view security alerts"
            );
        }

        return repository.findAllByOrderByCreatedAtDesc();
    }
}
