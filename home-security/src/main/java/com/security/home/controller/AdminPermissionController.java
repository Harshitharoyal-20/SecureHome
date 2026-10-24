
package com.security.home.controller;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/admin/permissions")
@CrossOrigin(origins = {
    "http://localhost:5173",
    "https://secure-home-kappa.vercel.app"
})
public class AdminPermissionController {

    private static final Set<String> PRIVILEGED_EMAILS = Set.of(
        "sivakumar6413@gmail.com",
        "pranawii0713@gmail.com",
        "harshitha0064@gmail.com"
    );

    private static final DateTimeFormatter UTC_FORMAT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final JdbcTemplate jdbc;

    public AdminPermissionController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
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
                String oauthEmail = String.valueOf(email).trim();

                List<String> registeredEmails = jdbc.query(
                    "SELECT email FROM users " +
                    "WHERE LOWER(email) = LOWER(?) " +
                    "AND status = 'ACTIVE' LIMIT 1",
                    (rs, rowNum) -> rs.getString("email"),
                    oauthEmail
                );

                if (!registeredEmails.isEmpty()) {
                    return registeredEmails.get(0);
                }
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

    private Integer findUserId(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }

        if (auth.getPrincipal() instanceof OAuth2User oauthUser) {
            Object providerId = oauthUser.getAttribute("id");

            if (providerId != null) {
                List<Integer> ids = jdbc.query(
                    "SELECT u.user_id FROM oauth_account_links o " +
                    "JOIN users u ON u.user_id = o.user_id " +
                    "WHERE LOWER(o.provider) = 'github' " +
                    "AND o.provider_user_id = ? " +
                    "AND u.status = 'ACTIVE' LIMIT 1",
                    (rs, rowNum) -> rs.getInt("user_id"),
                    String.valueOf(providerId)
                );

                if (!ids.isEmpty()) {
                    return ids.get(0);
                }
            }
        }

        List<Integer> ids = jdbc.query(
            "SELECT u.user_id FROM users u " +
            "WHERE LOWER(u.email) = LOWER(?) " +
            "AND u.status = 'ACTIVE' LIMIT 1",
            (rs, rowNum) -> rs.getInt("user_id"),
            auth.getName()
        );

        return ids.isEmpty() ? null : ids.get(0);
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

        return email != null &&
            PRIVILEGED_EMAILS.contains(
                email.trim().toLowerCase(Locale.ROOT)
            );
    }

    private void requireAdmin(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Please sign in first"
            );
        }

        if (!isAdmin(auth)) {
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "Only approved administrators can manage permissions"
            );
        }
    }

    @GetMapping("/users")
    public List<Map<String, Object>> users(Authentication auth) {
        requireAdmin(auth);

        return jdbc.queryForList(
            "SELECT u.user_id AS userId, " +
            "u.full_name AS fullName, " +
            "u.email AS email, " +
            "r.role_name AS roleName, " +
            "EXISTS (" +
            "  SELECT 1 FROM oauth_account_links o " +
            "  WHERE o.user_id = u.user_id AND LOWER(o.provider) = 'github'" +
            ") AS isGithub " +
            "FROM users u " +
            "JOIN roles r ON r.role_id = u.role_id " +
            "WHERE u.status = 'ACTIVE' " +
            "ORDER BY u.user_id"
        );
    }

    @GetMapping("/my")
    public List<Map<String, Object>> myPermissions(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Please sign in first"
            );
        }

        Integer userId = findUserId(auth);
        if (userId == null) {
            return List.of();
        }

        return jdbc.queryForList(
            "SELECT p.permission_id AS permissionId, " +
            "p.user_id AS userId, " +
            "p.asset_id AS assetId, " +
            "s.asset_name AS assetName, " +
            "s.asset_type AS assetType, " +
            "s.location_description AS location, " +
            "p.is_active AS active, " +
            "p.valid_from AS validFrom, " +
            "p.valid_until AS validUntil " +
            "FROM asset_permissions p " +
            "JOIN secure_assets s ON s.asset_id = p.asset_id " +
            "WHERE p.user_id = ? " +
            "ORDER BY p.permission_id DESC",
            userId
        );
    }

    @GetMapping("/assets")
    public List<Map<String, Object>> assets(Authentication auth) {
        requireAdmin(auth);

        return jdbc.queryForList(
            "SELECT asset_id AS assetId, " +
            "asset_name AS assetName, " +
            "asset_type AS assetType, " +
            "location_description AS location, " +
            "owner_user_id AS ownerUserId " +
            "FROM secure_assets " +
            "WHERE status = 'ACTIVE' " +
            "ORDER BY asset_id"
        );
    }

    @GetMapping
    public List<Map<String, Object>> permissions(Authentication auth) {
        requireAdmin(auth);

        return jdbc.queryForList(
            "SELECT p.permission_id AS permissionId, " +
            "p.user_id AS userId, " +
            "u.full_name AS fullName, " +
            "u.email AS email, " +
            "p.asset_id AS assetId, " +
            "s.asset_name AS assetName, " +
            "p.is_active AS active, " +
            "p.valid_from AS validFrom, " +
            "p.valid_until AS validUntil " +
            "FROM asset_permissions p " +
            "JOIN users u ON u.user_id = p.user_id " +
            "JOIN secure_assets s ON s.asset_id = p.asset_id " +
            "ORDER BY p.permission_id DESC"
        );
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> grant(
            @RequestBody Map<String, Object> body,
            Authentication auth) {

        requireAdmin(auth);

        int userId = number(body, "userId");
        int assetId = number(body, "assetId");

        LocalDateTime start = dateTime(body, "validFrom");
        LocalDateTime end = dateTime(body, "validUntil");
        LocalDateTime nowUtc = LocalDateTime.now(Clock.systemUTC());

        if (!start.isBefore(end)) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Expiry must be later than the start time"
            );
        }

        if (!end.isAfter(nowUtc)) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Expiry must be in the future"
            );
        }

        Integer userCount = jdbc.queryForObject(
            "SELECT COUNT(*) FROM users " +
            "WHERE user_id = ? AND status = 'ACTIVE'",
            Integer.class,
            userId
        );

        Integer assetCount = jdbc.queryForObject(
            "SELECT COUNT(*) FROM secure_assets " +
            "WHERE asset_id = ? AND status = 'ACTIVE'",
            Integer.class,
            assetId
        );

        if (userCount == null || userCount == 0) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Active user not found"
            );
        }

        if (assetCount == null || assetCount == 0) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Active locker not found"
            );
        }

        String startUtc = start.format(UTC_FORMAT);
        String endUtc = end.format(UTC_FORMAT);

        List<Map<String, Object>> existing = jdbc.queryForList(
            "SELECT permission_id FROM asset_permissions " +
            "WHERE user_id = ? AND asset_id = ? " +
            "ORDER BY permission_id DESC LIMIT 1",
            userId,
            assetId
        );

        if (existing.isEmpty()) {
            jdbc.update(
                "INSERT INTO asset_permissions " +
                "(user_id, asset_id, is_active, allowed_start, " +
                "allowed_end, valid_from, valid_until) " +
                "VALUES (?, ?, 1, '00:00:00', '23:59:59', ?, ?)",
                userId,
                assetId,
                startUtc,
                endUtc
            );
        } else {
            int permissionId = ((Number)
                existing.get(0).get("permission_id")).intValue();

            jdbc.update(
                "UPDATE asset_permissions SET " +
                "is_active = 1, " +
                "allowed_start = '00:00:00', " +
                "allowed_end = '23:59:59', " +
                "valid_from = ?, valid_until = ? " +
                "WHERE permission_id = ?",
                startUtc,
                endUtc,
                permissionId
            );
        }

        return Map.of(
            "message", "View-only permission granted",
            "userId", userId,
            "assetId", assetId,
            "validFrom", start.toString(),
            "validUntil", end.toString(),
            "capability", "VIEW_ONLY"
        );
    }

    @DeleteMapping("/{permissionId}")
    public Map<String, Object> revoke(
            @PathVariable int permissionId,
            Authentication auth) {

        requireAdmin(auth);

        int updated = jdbc.update(
            "UPDATE asset_permissions " +
            "SET is_active = 0 " +
            "WHERE permission_id = ?",
            permissionId
        );

        if (updated == 0) {
            throw new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "Permission not found"
            );
        }

        return Map.of("message", "Permission revoked");
    }

    private int number(Map<String, Object> body, String key) {
        try {
            Object value = body.get(key);

            if (value == null) {
                throw new NumberFormatException();
            }

            return Integer.parseInt(String.valueOf(value));
        } catch (Exception ex) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                key + " must be a valid number"
            );
        }
    }

    private LocalDateTime dateTime(
            Map<String, Object> body,
            String key) {

        try {
            Object value = body.get(key);

            if (value == null) {
                throw new IllegalArgumentException();
            }

            String input = String.valueOf(value);

            return LocalDateTime.parse(
                input,
                DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")
            );
        } catch (Exception ex) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                key + " must use yyyy-MM-dd'T'HH:mm:ss format (UTC)"
            );
        }
    }
}
