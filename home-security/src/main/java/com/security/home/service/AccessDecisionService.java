
package com.security.home.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
public class AccessDecisionService {

    private static final Set<String> PRIVILEGED_EMAILS = Set.of(
        "sivakumar6413@gmail.com",
        "pranawii0713@gmail.com",
        "harshitha0064@gmail.com"
    );

    private final JdbcTemplate jdbc;

    public AccessDecisionService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public Map<String, Object> checkAccess(Long userId, Long assetId) {

        String decision = "DENIED";
        String reason;
        LocalDateTime now = LocalDateTime.now();
        Long eventId = null;

        if (userId == null || assetId == null) {
            return Map.of(
                "decision", decision,
                "reason", "User ID and locker ID are required"
            );
        }

        List<Map<String, Object>> users = jdbc.queryForList(
            "SELECT user_id, email FROM users " +
            "WHERE user_id = ? AND status = 'ACTIVE'",
            userId
        );

        List<Map<String, Object>> assets = jdbc.queryForList(
            "SELECT asset_id FROM secure_assets " +
            "WHERE asset_id = ? AND status = 'ACTIVE'",
            assetId
        );

        String email = "";

        if (!users.isEmpty() && users.get(0).get("email") != null) {
            email = String.valueOf(users.get(0).get("email"))
                .trim()
                .toLowerCase();
        }

        boolean isAdmin = PRIVILEGED_EMAILS.contains(email);

        if (users.isEmpty()) {
            reason = "User is inactive or does not exist";
        } else if (assets.isEmpty()) {
            reason = "Locker is inactive or does not exist";
        } else if (isAdmin) {
            decision = "ALLOWED";
            reason = "Approved administrator access granted";
        } else {
            List<Map<String, Object>> permissions = jdbc.queryForList(
                "SELECT allowed_start, allowed_end " +
                "FROM asset_permissions " +
                "WHERE user_id = ? " +
                "AND asset_id = ? " +
                "AND is_active = 1 " +
                "AND valid_from IS NOT NULL " +
                "AND valid_until IS NOT NULL " +
                "AND valid_from <= ? " +
                "AND valid_until >= ?",
                userId,
                assetId,
                Timestamp.valueOf(now),
                Timestamp.valueOf(now)
            );

            LocalTime currentTime = now.toLocalTime();
            boolean permitted = false;

            for (Map<String, Object> permission : permissions) {
                Object startValue = permission.get("allowed_start");
                Object endValue = permission.get("allowed_end");

                if (startValue == null || endValue == null) {
                    continue;
                }

                LocalTime start = startValue instanceof java.sql.Time
                    ? ((java.sql.Time) startValue).toLocalTime()
                    : LocalTime.parse(startValue.toString());

                LocalTime end = endValue instanceof java.sql.Time
                    ? ((java.sql.Time) endValue).toLocalTime()
                    : LocalTime.parse(endValue.toString());

                if (isWithinWindow(currentTime, start, end)) {
                    permitted = true;
                    break;
                }
            }

            if (permitted) {
                decision = "ALLOWED";
                reason = "Active locker permission and time checks passed";
            } else {
                reason = "No active locker permission for this time";
            }
        }

        jdbc.update(
            "INSERT INTO access_events " +
            "(user_id, policy_id, asset_id, decision, reason) " +
            "VALUES (?, NULL, ?, ?, ?)",
            userId,
            assetId,
            decision,
            reason
        );

        eventId = jdbc.queryForObject(
            "SELECT LAST_INSERT_ID()",
            Long.class
        );

        jdbc.update(
            "INSERT INTO audit_logs (user_id, action, details) " +
            "VALUES (?, ?, ?)",
            userId,
            "LOCKER_ACCESS_" + decision,
            "Asset ID: " + assetId + ". Reason: " + reason
        );

        if ("DENIED".equals(decision) && eventId != null) {
            Set<Long> recipients = new LinkedHashSet<>();
            recipients.add(userId);

            List<Long> adminIds = jdbc.query(
                "SELECT user_id FROM users " +
                "WHERE status = 'ACTIVE' " +
                "AND LOWER(email) IN (?, ?, ?)",
                (rs, rowNum) -> rs.getLong("user_id"),
                "sivakumar6413@gmail.com",
                "pranawii0713@gmail.com",
                "harshitha0064@gmail.com"
            );

            recipients.addAll(adminIds);

            for (Long recipientId : recipients) {
                jdbc.update(
                    "INSERT INTO security_alerts " +
                    "(event_id, recipient_user_id, severity, message) " +
                    "VALUES (?, ?, ?, ?)",
                    eventId,
                    recipientId,
                    "MEDIUM",
                    "Denied locker access. Asset ID: " +
                    assetId + ". Reason: " + reason
                );
            }
        }

        return Map.of(
            "decision", decision,
            "reason", reason,
            "userId", userId,
            "assetId", assetId
        );
    }

    private boolean isWithinWindow(
            LocalTime now,
            LocalTime start,
            LocalTime end) {

        if (start.equals(end)) {
            return true;
        }

        if (start.isBefore(end)) {
            return !now.isBefore(start) && !now.isAfter(end);
        }

        return !now.isBefore(start) || !now.isAfter(end);
    }
}
