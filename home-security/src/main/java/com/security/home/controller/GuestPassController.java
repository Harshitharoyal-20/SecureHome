
package com.security.home.controller;

import com.security.home.dto.GuestAccessRequest;
import com.security.home.service.GuestPassService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class GuestPassController {

    private final GuestPassService service;
    private final JdbcTemplate jdbc;

    public GuestPassController(
            GuestPassService service, JdbcTemplate jdbc) {
        this.service = service;
        this.jdbc = jdbc;
    }

    @PostMapping("/guest-access-check")
    public ResponseEntity<Map<String, Object>> checkGuestAccess(
            @RequestBody GuestAccessRequest request,
            Principal principal) {

        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Login required"));
        }

        if (request.getGuestPassId() == null ||
                request.getAssetId() == null) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Pass ID and locker ID are required"));
        }

        var users = jdbc.queryForList(
            "SELECT user_id FROM users " +
            "WHERE email = ? AND status = 'ACTIVE'",
            principal.getName()
        );

        if (users.isEmpty()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Active account not found"));
        }

        Long userId = ((Number)
            users.get(0).get("user_id")).longValue();

        var roles = jdbc.queryForList(
            "SELECT r.role_name FROM users u " +
            "JOIN roles r ON u.role_id = r.role_id " +
            "WHERE u.user_id = ?",
            userId
        );

        if (roles.isEmpty() ||
                !"GUEST".equals(roles.get(0).get("role_name"))) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Guest account required"));
        }

        return ResponseEntity.ok(
            service.validateGuestPass(
                request.getGuestPassId(),
                userId,
                request.getAssetId()
            )
        );
    }
}
