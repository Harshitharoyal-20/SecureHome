
package com.security.home.controller;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/permissions")
@CrossOrigin(origins = {
    "http://localhost:5173",
    "https://secure-home-kappa.vercel.app"
})
public class AdminPermissionController {

    private final JdbcTemplate jdbc;

    public AdminPermissionController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    private void requireAdmin(Authentication auth) {
        if (auth == null || auth.getAuthorities().stream()
                .noneMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "Only administrators can manage permissions"
            );
        }
    }

    @GetMapping("/users")
    public List<Map<String, Object>> users(Authentication auth) {
        requireAdmin(auth);

        return jdbc.queryForList(
            "SELECT user_id AS userId, full_name AS fullName, email " +
            "FROM users WHERE status = 'ACTIVE' ORDER BY user_id"
        );
    }

    @GetMapping("/assets")
    public List<Map<String, Object>> assets(Authentication auth) {
        requireAdmin(auth);

        return jdbc.queryForList(
            "SELECT asset_id AS assetId, asset_name AS assetName, " +
            "asset_type AS assetType, location_description AS location, " +
            "owner_user_id AS ownerUserId " +
            "FROM secure_assets WHERE status = 'ACTIVE' ORDER BY asset_id"
        );
    }

    @GetMapping
    public List<Map<String, Object>> permissions(Authentication auth) {
        requireAdmin(auth);

        return jdbc.queryForList(
            "SELECT p.permission_id AS permissionId, " +
            "p.user_id AS userId, u.full_name AS fullName, " +
            "u.email AS email, p.asset_id AS assetId, " +
            "s.asset_name AS assetName, p.is_active AS active, " +
            "p.valid_from AS validFrom, p.valid_until AS validUntil " +
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

        if (!start.isBefore(end)) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Expiry must be later than the start time"
            );
        }

        Integer userCount = jdbc.queryForObject(
            "SELECT COUNT(*) FROM users " +
            "WHERE user_id = ? AND status = 'ACTIVE'",
            Integer.class, userId
        );

        Integer assetCount = jdbc.queryForObject(
            "SELECT COUNT(*) FROM secure_assets " +
            "WHERE asset_id = ? AND status = 'ACTIVE'",
            Integer.class, assetId
        );

        if (userCount == null || userCount == 0) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, "Active user not found"
            );
        }

        if (assetCount == null || assetCount == 0) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, "Active locker not found"
            );
        }

        // Reactivate/update the existing permission for this user and asset.
        List<Map<String, Object>> existing = jdbc.queryForList(
            "SELECT permission_id FROM asset_permissions " +
            "WHERE user_id = ? AND asset_id = ? " +
            "ORDER BY permission_id DESC LIMIT 1",
            userId, assetId
        );

        if (existing.isEmpty()) {
            jdbc.update(
                "INSERT INTO asset_permissions " +
                "(user_id, asset_id, is_active, allowed_start, " +
                "allowed_end, valid_from, valid_until) " +
                "VALUES (?, ?, 1, '00:00:00', '23:59:59', ?, ?)",
                userId, assetId,
                Timestamp.valueOf(start), Timestamp.valueOf(end)
            );
        } else {
            int permissionId = ((Number)
                existing.get(0).get("permission_id")).intValue();

            jdbc.update(
                "UPDATE asset_permissions SET is_active = 1, " +
                "allowed_start = '00:00:00', allowed_end = '23:59:59', " +
                "valid_from = ?, valid_until = ? " +
                "WHERE permission_id = ?",
                Timestamp.valueOf(start),
                Timestamp.valueOf(end),
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
            "UPDATE asset_permissions SET is_active = 0 " +
            "WHERE permission_id = ?",
            permissionId
        );

        if (updated == 0) {
            throw new ResponseStatusException(
                HttpStatus.NOT_FOUND, "Permission not found"
            );
        }

        return Map.of("message", "Permission revoked");
    }

    private int number(Map<String, Object> body, String key) {
        try {
            return Integer.parseInt(String.valueOf(body.get(key)));
        } catch (Exception ex) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, key + " must be a valid number"
            );
        }
    }

    private LocalDateTime dateTime(
            Map<String, Object> body, String key) {
        try {
            return LocalDateTime.parse(
                String.valueOf(body.get(key))
            );
        } catch (Exception ex) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                key + " must use the format YYYY-MM-DDTHH:mm:ss"
            );
        }
    }
}
