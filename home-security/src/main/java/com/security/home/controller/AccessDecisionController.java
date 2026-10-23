
package com.security.home.controller;

import com.security.home.dto.AccessDecisionRequest;
import com.security.home.service.AccessDecisionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = {
    "http://localhost:5173",
    "https://secure-home-kappa.vercel.app"
})
public class AccessDecisionController {

    private final AccessDecisionService service;
    private final JdbcTemplate jdbc;

    public AccessDecisionController(
            AccessDecisionService service,
            JdbcTemplate jdbc) {
        this.service = service;
        this.jdbc = jdbc;
    }

    @PostMapping("/access-check")
    public ResponseEntity<Map<String, Object>> checkAccess(
            @RequestBody AccessDecisionRequest request,
            Authentication authentication) {

        if (authentication == null
                || !authentication.isAuthenticated()
                || "anonymousUser".equals(
                    String.valueOf(authentication.getPrincipal()))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Login required"));
        }

        if (request.getAssetId() == null) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Locker ID is required"));
        }

        List<Integer> userIds;

        if (authentication.getPrincipal() instanceof OAuth2User oauth) {
            Object providerId = oauth.getAttribute("id");

            if (providerId == null) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "GitHub account ID is missing"));
            }

            userIds = jdbc.query(
                "SELECT u.user_id FROM oauth_account_links o " +
                "JOIN users u ON u.user_id = o.user_id " +
                "WHERE LOWER(o.provider) = 'github' " +
                "AND o.provider_user_id = ? " +
                "AND u.status = 'ACTIVE' LIMIT 1",
                (rs, rowNum) -> rs.getInt("user_id"),
                String.valueOf(providerId)
            );
        } else {
            userIds = jdbc.query(
                "SELECT user_id FROM users " +
                "WHERE LOWER(email) = LOWER(?) " +
                "AND status = 'ACTIVE' LIMIT 1",
                (rs, rowNum) -> rs.getInt("user_id"),
                authentication.getName()
            );
        }

        if (userIds.isEmpty()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Active user account not found"));
        }

        return ResponseEntity.ok(
            service.checkAccess(
                userIds.get(0).longValue(),
                request.getAssetId()
            )
        );
    }
}
