
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
    public List<Map<String, Object>> getAccessEvents(
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

        String baseSql =
            "SELECT " +
            "  e.event_id AS eventId, " +
            "  e.user_id AS userId, " +
            "  COALESCE(u.full_name, u.email, CONCAT('User #', e.user_id)) AS userName, " +
            "  COALESCE(u.email, '') AS userEmail, " +
            "  e.asset_id AS assetId, " +
            "  COALESCE(s.asset_name, CONCAT('Locker #', e.asset_id)) AS assetName, " +
            "  COALESCE(s.asset_type, 'LOCKER') AS assetType, " +
            "  COALESCE(s.location_description, 'Private Room') AS location, " +
            "  e.event_time AS eventTime, " +
            "  e.decision AS decision, " +
            "  e.reason AS reason, " +
            "  p.valid_from AS validFrom, " +
            "  p.valid_until AS validUntil, " +
            "  CASE " +
            "    WHEN p.is_active = 1 " +
            "      AND (p.valid_from IS NULL OR p.valid_from <= NOW()) " +
            "      AND (p.valid_until IS NULL OR p.valid_until >= NOW()) " +
            "    THEN 1 " +
            "    ELSE 0 " +
            "  END AS activeNow " +
            "FROM access_events e " +
            "LEFT JOIN users u ON u.user_id = e.user_id " +
            "LEFT JOIN secure_assets s ON s.asset_id = e.asset_id " +
            "LEFT JOIN asset_permissions p ON p.permission_id = ( " +
            "  SELECT p2.permission_id FROM asset_permissions p2 " +
            "  WHERE p2.user_id = e.user_id AND p2.asset_id = e.asset_id " +
            "  ORDER BY p2.permission_id DESC LIMIT 1 " +
            ") ";

        if (isAdmin) {
            return jdbc.queryForList(baseSql + "ORDER BY e.event_time DESC, e.event_id DESC");
        }

        return jdbc.queryForList(baseSql + "WHERE e.user_id = ? ORDER BY e.event_time DESC, e.event_id DESC", userId);
    }

    @GetMapping("/active-now")
    public List<Map<String, Object>> getCurrentlyActiveAccess(
            Authentication authentication) {

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Please sign in");
        }

        List<Map<String, Object>> users;
        if (authentication.getPrincipal() instanceof OAuth2User oauth) {
            Object providerId = oauth.getAttribute("id");
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
            return List.of();
        }

        Map<String, Object> user = users.get(0);
        int userId = ((Number) user.get("user_id")).intValue();
        String email = user.get("email") == null ? "" : String.valueOf(user.get("email")).trim().toLowerCase();
        String role = user.get("role_name") == null ? "" : String.valueOf(user.get("role_name"));

        boolean isAdmin = "ADMIN".equalsIgnoreCase(role) || PRIVILEGED_EMAILS.contains(email);

        if (isAdmin) {
            return jdbc.queryForList(
                "SELECT s.asset_id AS assetId, s.asset_name AS assetName, s.asset_type AS assetType, " +
                "s.location_description AS location, 'FULL_ADMIN' AS accessLevel, " +
                "1 AS activeNow " +
                "FROM secure_assets s WHERE s.status = 'ACTIVE' ORDER BY s.asset_name"
            );
        }

        return jdbc.queryForList(
            "SELECT s.asset_id AS assetId, s.asset_name AS assetName, s.asset_type AS assetType, " +
            "s.location_description AS location, p.valid_from AS validFrom, p.valid_until AS validUntil, " +
            "p.allowed_start AS allowedStart, p.allowed_end AS allowedEnd, 1 AS activeNow " +
            "FROM asset_permissions p " +
            "JOIN secure_assets s ON s.asset_id = p.asset_id " +
            "WHERE p.user_id = ? " +
            "AND p.is_active = 1 " +
            "AND s.status = 'ACTIVE' " +
            "AND (p.valid_from IS NULL OR p.valid_from <= NOW()) " +
            "AND (p.valid_until IS NULL OR p.valid_until >= NOW()) " +
            "ORDER BY s.asset_name",
            userId
        );
    }
}
