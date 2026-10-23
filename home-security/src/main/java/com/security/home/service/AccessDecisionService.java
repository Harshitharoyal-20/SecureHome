
package com.security.home.service;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Time;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.Map;

@Service
public class AccessDecisionService {

    private final JdbcTemplate jdbc;

    public AccessDecisionService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public Map<String, Object> checkAccess(Long userId, Long assetId) {

        String decision = "DENIED";
        String reason;
        Long policyId = null;

        if (userId == null || assetId == null) {
            return Map.of(
                "decision", decision,
                "reason", "User ID and locker ID are required"
            );
        }

        List<Map<String, Object>> users = jdbc.queryForList(
            "SELECT user_id FROM users " +
            "WHERE user_id = ? AND status = 'ACTIVE'",
            userId
        );

        List<Map<String, Object>> assets = jdbc.queryForList(
            "SELECT asset_id FROM secure_assets " +
            "WHERE asset_id = ? AND status = 'ACTIVE'",
            assetId
        );

        if (users.isEmpty()) {
            reason = "User is inactive or does not exist";
        } else if (assets.isEmpty()) {
            reason = "Locker is inactive or does not exist";
        } else {
            LocalDateTime now = LocalDateTime.now();
            LocalTime currentTime = now.toLocalTime();

            List<Map<String, Object>> policies = jdbc.queryForList(
                "SELECT policy_id, allowed_start, allowed_end " +
                "FROM access_policies " +
                "WHERE user_id = ? AND is_active = 1",
                userId
            );

            for (Map<String, Object> policy : policies) {
                LocalTime start = ((Time)
                    policy.get("allowed_start")).toLocalTime();

                LocalTime end = ((Time)
                    policy.get("allowed_end")).toLocalTime();

                if (isWithinWindow(currentTime, start, end)) {
                    policyId = ((Number)
                        policy.get("policy_id")).longValue();
                    break;
                }
            }

            if (policyId == null) {
                reason = "No active policy permits access at this time";
            } else {
                List<Map<String, Object>> permissions =
                    jdbc.queryForList(
                        "SELECT allowed_start, allowed_end, " +
                        "valid_from, valid_until " +
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

                boolean permitted = false;

                for (Map<String, Object> permission : permissions) {
                    Time startValue = (Time)
                        permission.get("allowed_start");

                    Time endValue = (Time)
                        permission.get("allowed_end");

                    if (startValue == null || endValue == null) {
                        continue;
                    }

                    LocalTime start = startValue.toLocalTime();
                    LocalTime end = endValue.toLocalTime();

                    if (isWithinWindow(currentTime, start, end)) {
                        permitted = true;
                        break;
                    }
                }

                if (permitted) {
                    decision = "ALLOWED";
                    reason = "User, policy, locker and permission time checks passed";
                } else {
                    reason = "No active locker permission for this time";
                }
            }
        }

        jdbc.update(
            "INSERT INTO access_events " +
            "(user_id, policy_id, asset_id, decision, reason) " +
            "VALUES (?, ?, ?, ?, ?)",
            userId, policyId, assetId, decision, reason
        );

        Long eventId = jdbc.queryForObject(
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
            List<Map<String, Object>> admins = jdbc.queryForList(
                "SELECT u.user_id FROM users u " +
                "JOIN roles r ON u.role_id = r.role_id " +
                "WHERE r.role_name = 'ADMIN' " +
                "AND u.status = 'ACTIVE'"
            );

            for (Map<String, Object> admin : admins) {
                Long adminId = ((Number)
                    admin.get("user_id")).longValue();

                jdbc.update(
                    "INSERT INTO security_alerts " +
                    "(event_id, recipient_user_id, severity, message) " +
                    "VALUES (?, ?, ?, ?)",
                    eventId,
                    adminId,
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
            LocalTime now, LocalTime start, LocalTime end) {

        if (start.equals(end)) {
            return true;
        }

        if (start.isBefore(end)) {
            return !now.isBefore(start) && !now.isAfter(end);
        }

        return !now.isBefore(start) || !now.isAfter(end);
    }
}
