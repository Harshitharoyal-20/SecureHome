
package com.security.home.controller;

import com.security.home.entity.SecurityAlert;
import com.security.home.repository.SecurityAlertRepository;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/security-alerts")
public class SecurityAlertController {

    private final SecurityAlertRepository repository;
    private final JdbcTemplate jdbcTemplate;

    public SecurityAlertController(
            SecurityAlertRepository repository,
            JdbcTemplate jdbcTemplate) {
        this.repository = repository;
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping
    public List<SecurityAlert> getSecurityAlerts(
            Authentication authentication) {

        if (authentication == null
                || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED, "Please log in");
        }

        List<Map<String, Object>> users;

        if (authentication.getPrincipal() instanceof OAuth2User oauth) {
            Object id = oauth.getAttributes().get("id");

            if (id == null) {
                throw new ResponseStatusException(
                        HttpStatus.FORBIDDEN,
                        "GitHub account ID is missing");
            }

            users = jdbcTemplate.queryForList(
                    "SELECT u.user_id, r.role_name " +
                    "FROM oauth_account_links o " +
                    "JOIN users u ON u.user_id = o.user_id " +
                    "JOIN roles r ON r.role_id = u.role_id " +
                    "WHERE o.provider = ? " +
                    "AND o.provider_user_id = ? " +
                    "AND u.status = 'ACTIVE'",
                    "github", id.toString());
        } else {
            users = jdbcTemplate.queryForList(
                    "SELECT u.user_id, r.role_name " +
                    "FROM users u " +
                    "JOIN roles r ON r.role_id = u.role_id " +
                    "WHERE u.email = ? " +
                    "AND u.status = 'ACTIVE'",
                    authentication.getName());
        }

        if (users.isEmpty()) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "No active application user is linked to this login");
        }

        Integer userId = ((Number) users.get(0)
                .get("user_id")).intValue();

        String role = users.get(0)
                .get("role_name").toString();

        if ("ADMIN".equals(role)) {
            return repository.findAllByOrderByCreatedAtDesc();
        }

        if ("FAMILY_MEMBER".equals(role)
                || "SECURITY_STAFF".equals(role)
                || "GUEST".equals(role)) {

            List<Integer> alertIds = jdbcTemplate.query(
                    "SELECT alert_id FROM security_alerts " +
                    "WHERE recipient_user_id = ? " +
                    "ORDER BY created_at DESC",
                    (rs, rowNum) -> rs.getInt("alert_id"),
                    userId);

            return alertIds.stream()
                    .map(id -> repository.findById(id).orElse(null))
                    .filter(alert -> alert != null)
                    .toList();
        }

        throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "You cannot view security alerts");
    }
}
