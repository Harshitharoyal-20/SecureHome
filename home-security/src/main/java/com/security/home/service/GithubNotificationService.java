package com.security.home.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.util.List;
import java.util.Map;

@Service
public class GithubNotificationService {

    private static final Logger log = LoggerFactory.getLogger(GithubNotificationService.class);

    private final JdbcTemplate jdbc;

    public GithubNotificationService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostConstruct
    public void initTable() {
        try {
            jdbc.execute(
                "CREATE TABLE IF NOT EXISTS github_access_notifications (" +
                "  id BIGINT AUTO_INCREMENT PRIMARY KEY," +
                "  github_username VARCHAR(100) NOT NULL," +
                "  full_name VARCHAR(150)," +
                "  email VARCHAR(150)," +
                "  access_time DATETIME DEFAULT CURRENT_TIMESTAMP," +
                "  is_dismissed TINYINT(1) DEFAULT 0" +
                ")"
            );
            log.info("Initialized github_access_notifications table successfully.");
        } catch (Exception ex) {
            log.warn("Could not ensure github_access_notifications table: {}", ex.getMessage());
        }
    }

    public void recordAccess(String githubUsername, String fullName, String email) {
        if (githubUsername == null || githubUsername.trim().isEmpty()) {
            githubUsername = "GitHub User";
        }
        String cleanUsername = githubUsername.trim();

        try {
            // Check if there is already an active notification for this username within the last 15 minutes
            Integer recentCount = jdbc.queryForObject(
                "SELECT COUNT(*) FROM github_access_notifications " +
                "WHERE LOWER(github_username) = LOWER(?) " +
                "AND access_time >= DATE_SUB(NOW(), INTERVAL 15 MINUTE) " +
                "AND is_dismissed = 0",
                Integer.class,
                cleanUsername
            );

            if (recentCount == null || recentCount == 0) {
                jdbc.update(
                    "INSERT INTO github_access_notifications " +
                    "(github_username, full_name, email, access_time, is_dismissed) " +
                    "VALUES (?, ?, ?, NOW(), 0)",
                    cleanUsername,
                    fullName != null ? fullName.trim() : cleanUsername,
                    email != null ? email.trim() : ""
                );
                log.info("Recorded GitHub access notification for user: {}", cleanUsername);
            }
        } catch (Exception ex) {
            log.error("Failed to record GitHub access notification: {}", ex.getMessage());
        }
    }

    public List<Map<String, Object>> getActiveNotifications() {
        try {
            return jdbc.queryForList(
                "SELECT id, " +
                "github_username AS githubUsername, " +
                "full_name AS fullName, " +
                "email, " +
                "access_time AS accessTime, " +
                "CONCAT(github_username, ' is trying to access') AS message " +
                "FROM github_access_notifications " +
                "WHERE is_dismissed = 0 " +
                "ORDER BY id DESC LIMIT 20"
            );
        } catch (Exception ex) {
            log.error("Failed to query GitHub access notifications: {}", ex.getMessage());
            return List.of();
        }
    }

    public boolean dismissNotification(long id) {
        try {
            int updated = jdbc.update(
                "UPDATE github_access_notifications SET is_dismissed = 1 WHERE id = ?",
                id
            );
            return updated > 0;
        } catch (Exception ex) {
            log.error("Failed to dismiss notification {}: {}", id, ex.getMessage());
            return false;
        }
    }

    public void dismissAll() {
        try {
            jdbc.update("UPDATE github_access_notifications SET is_dismissed = 1 WHERE is_dismissed = 0");
        } catch (Exception ex) {
            log.error("Failed to dismiss all notifications: {}", ex.getMessage());
        }
    }
}
