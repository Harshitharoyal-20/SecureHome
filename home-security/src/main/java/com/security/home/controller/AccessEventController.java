
package com.security.home.controller;

import com.security.home.entity.AccessEvent;
import com.security.home.repository.AccessEventRepository;
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
@RequestMapping("/api/access-events")
public class AccessEventController {

    private final AccessEventRepository repository;
    private final JdbcTemplate jdbcTemplate;

    public AccessEventController(
            AccessEventRepository repository,
            JdbcTemplate jdbcTemplate) {
        this.repository = repository;
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping
    public List<AccessEvent> getAccessEvents(
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
            return repository.findAllByOrderByEventTimeDesc();
        }

        if ("FAMILY_MEMBER".equals(role)
                || "SECURITY_STAFF".equals(role)
                || "GUEST".equals(role)) {
            return repository.findByUserIdOrderByEventTimeDesc(userId);
        }

        throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "You cannot view access history");
    }
}
