
package com.security.home.controller;

import com.security.home.entity.AccessEvent;
import com.security.home.repository.AccessEventRepository;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/access-events")
@CrossOrigin(origins = {
    "http://localhost:5173",
    "https://secure-home-kappa.vercel.app"
})
public class AccessEventController {

    private static final Set<String> PRIVILEGED_EMAILS = Set.of(
        "sivakumar6413@gmail.com",
        "pranawii0713@gmail.com",
        "harshitha0064@gmail.com"
    );

    private final AccessEventRepository repository;
    private final JdbcTemplate jdbc;

    public AccessEventController(
            AccessEventRepository repository,
            JdbcTemplate jdbc) {
        this.repository = repository;
        this.jdbc = jdbc;
    }

    @GetMapping
    public List<AccessEvent> getAccessEvents(
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
                "SELECT u.user_id, u.email, r.role_name " +
                "FROM oauth_account_links o " +
                "JOIN users u ON u.user_id = o.user_id " +
                "JOIN roles r ON r.role_id = u.role_id " +
                "WHERE LOWER(o.provider) = 'github' " +
                "AND o.provider_user_id = ? " +
                "AND u.status = 'ACTIVE' LIMIT 1",
                String.valueOf(providerId)
            );
        } else {
            users = jdbc.queryForList(
                "SELECT u.user_id, u.email, r.role_name " +
                "FROM users u " +
                "JOIN roles r ON r.role_id = u.role_id " +
                "WHERE LOWER(u.email) = LOWER(?) " +
                "AND u.status = 'ACTIVE' LIMIT 1",
                authentication.getName()
            );
        }

        if (users.isEmpty()) {
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "No active application user is linked to this login"
            );
        }

        Map<String, Object> user = users.get(0);

        int userId = ((Number) user.get("user_id")).intValue();

        String email = user.get("email") == null
            ? ""
            : String.valueOf(user.get("email"))
                .trim().toLowerCase();

        String role = user.get("role_name") == null
            ? ""
            : String.valueOf(user.get("role_name"));

        boolean isAdmin =
            "ADMIN".equalsIgnoreCase(role)
            || PRIVILEGED_EMAILS.contains(email);

        boolean isSecurity =
            role.toUpperCase().contains("SECURITY")
            || "mahesh0562@gmail.com".equalsIgnoreCase(email);

        if (isAdmin || isSecurity) {
            return repository.findAllByOrderByEventTimeDesc();
        }

        return repository.findByUserIdOrderByEventTimeDesc(userId);
    }
}
