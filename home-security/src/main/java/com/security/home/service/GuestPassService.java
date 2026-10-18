
package com.security.home.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
public class GuestPassService {

    private final JdbcTemplate jdbc;

    public GuestPassService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public Map<String, Object> validateGuestPass(
            Long guestPassId, Long guestUserId, Long assetId) {

        String decision = "DENIED";
        String reason;
        Long eventId = null;

        if (guestPassId == null || guestUserId == null || assetId == null) {
            return Map.of(
                "decision", decision,
                "reason", "Guest user, pass ID and locker ID are required"
            );
        }

        List<Map<String, Object>> guests = jdbc.queryForList(
            "SELECT u.user_id FROM users u " +
            "JOIN roles r ON u.role_id = r.role_id " +
            "WHERE u.user_id = ? AND u.status = 'ACTIVE' " +
            "AND r.role_name = 'GUEST'",
            guestUserId
        );

        List<Map<String, Object>> assets = jdbc.queryForList(
            "SELECT asset_id FROM secure_assets " +
            "WHERE asset_id = ? AND status = 'ACTIVE'",
            assetId
        );

        List<Map<String, Object>> passes = jdbc.queryForList(
            "SELECT guest_pass_id, created_by, valid_from, valid_until " +
            "FROM guest_passes " +
            "WHERE guest_pass_id = ? AND status = 'ACTIVE'",
            guestPassId
        );

        if (guests.isEmpty()) {
            reason = "Active guest account not found";
        } else if (assets.isEmpty()) {
            reason = "Locker is inactive or does not exist";
        } else if (passes.isEmpty()) {
            reason = "Guest pass does not exist or is inactive";
        } else {
            Map<String, Object> pass = passes.get(0);

            LocalDateTime start = ((Timestamp)
                pass.get("valid_from")).toLocalDateTime();

            LocalDateTime end = ((Timestamp)
                pass.get("valid_until")).toLocalDateTime();

            LocalDateTime now = LocalDateTime.now();

            if (now.isBefore(start) || now.isAfter(end)) {
                reason = "Guest pass is outside its validity period";
            } else {
                decision = "ALLOWED";
                reason = "Guest account, pass, validity and locker verified";
            }
        }

        jdbc.update(
            "INSERT INTO access_events " +
            "(user_id, guest_pass_id, asset_id, decision, reason) " +
            "VALUES (?, ?, ?, ?, ?)",
            guestUserId, guestPassId, assetId, decision, reason
        );

        eventId = jdbc.queryForObject(
            "SELECT LAST_INSERT_ID()", Long.class
        );

        jdbc.update(
            "INSERT INTO audit_logs (user_id, action, details) " +
            "VALUES (?, ?, ?)",
            guestUserId,
            "GUEST_ACCESS_" + decision,
            "Pass ID: " + guestPassId +
            ", Asset ID: " + assetId + ". " + reason
        );

        if ("DENIED".equals(decision) && eventId != null) {
            List<Map<String, Object>> admins = jdbc.queryForList(
                "SELECT u.user_id FROM users u " +
                "JOIN roles r ON u.role_id = r.role_id " +
                "WHERE r.role_name = 'ADMIN' AND u.status = 'ACTIVE'"
            );

            for (Map<String, Object> admin : admins) {
                jdbc.update(
                    "INSERT INTO security_alerts " +
                    "(event_id, recipient_user_id, severity, message) " +
                    "VALUES (?, ?, ?, ?)",
                    eventId,
                    ((Number) admin.get("user_id")).longValue(),
                    "MEDIUM",
                    "Guest access denied. Pass ID: " + guestPassId +
                    ". Asset ID: " + assetId + ". " + reason
                );
            }
        }

        return Map.of(
            "decision", decision,
            "reason", reason,
            "guestPassId", guestPassId,
            "assetId", assetId
        );
    }
}
