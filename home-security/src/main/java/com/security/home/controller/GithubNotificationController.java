package com.security.home.controller;

import com.security.home.service.GithubNotificationService;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/admin/github-notifications")
@CrossOrigin(origins = {
    "http://localhost:5173",
    "https://secure-home-kappa.vercel.app"
})
public class GithubNotificationController {

    private static final Set<String> PRIVILEGED_EMAILS = Set.of(
        "sivakumar6413@gmail.com",
        "pranawii0713@gmail.com",
        "harshitha0064@gmail.com"
    );

    private final GithubNotificationService notificationService;
    private final JdbcTemplate jdbc;

    public GithubNotificationController(GithubNotificationService notificationService, JdbcTemplate jdbc) {
        this.notificationService = notificationService;
        this.jdbc = jdbc;
    }

    private boolean isAdmin(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }

        boolean hasAdminRole = auth.getAuthorities().stream()
            .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));

        if (hasAdminRole) {
            return true;
        }

        String email = findUserEmail(auth);
        return email != null && PRIVILEGED_EMAILS.contains(email.trim().toLowerCase(Locale.ROOT));
    }

    private String findUserEmail(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }

        if (auth.getPrincipal() instanceof OAuth2User oauthUser) {
            Object providerId = oauthUser.getAttribute("id");
            if (providerId != null) {
                List<String> linkedEmails = jdbc.query(
                    "SELECT u.email FROM oauth_account_links o " +
                    "JOIN users u ON u.user_id = o.user_id " +
                    "WHERE LOWER(o.provider) = 'github' " +
                    "AND o.provider_user_id = ? " +
                    "AND u.status = 'ACTIVE' LIMIT 1",
                    (rs, rowNum) -> rs.getString("email"),
                    String.valueOf(providerId)
                );
                if (!linkedEmails.isEmpty()) {
                    return linkedEmails.get(0);
                }
            }

            Object email = oauthUser.getAttribute("email");
            if (email != null) {
                return String.valueOf(email).trim();
            }
        }

        List<String> emails = jdbc.query(
            "SELECT email FROM users " +
            "WHERE LOWER(email) = LOWER(?) " +
            "AND status = 'ACTIVE' LIMIT 1",
            (rs, rowNum) -> rs.getString("email"),
            auth.getName()
        );

        return emails.isEmpty() ? null : emails.get(0);
    }

    private void requireAdmin(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Please sign in first");
        }
        if (!isAdmin(auth)) {
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "Only administrators and family members can view access notifications"
            );
        }
    }

    @GetMapping
    public List<Map<String, Object>> getNotifications(Authentication auth) {
        requireAdmin(auth);
        return notificationService.getActiveNotifications();
    }

    @PostMapping("/{id}/dismiss")
    public Map<String, Object> dismissNotification(@PathVariable long id, Authentication auth) {
        requireAdmin(auth);
        boolean success = notificationService.dismissNotification(id);
        return Map.of("success", success, "message", "Notification dismissed");
    }

    @PostMapping("/dismiss-all")
    public Map<String, Object> dismissAll(Authentication auth) {
        requireAdmin(auth);
        notificationService.dismissAll();
        return Map.of("success", true, "message", "All notifications dismissed");
    }
}
