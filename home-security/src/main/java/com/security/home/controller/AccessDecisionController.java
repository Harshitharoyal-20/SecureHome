
package com.security.home.controller;

import com.security.home.dto.AccessDecisionRequest;
import com.security.home.service.AccessDecisionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api")
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
            Principal principal) {

        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Login required"));
        }

        if (request.getAssetId() == null) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Locker ID is required"));
        }

        var users = jdbc.queryForList(
            "SELECT user_id FROM users " +
            "WHERE email = ? AND status = 'ACTIVE'",
            principal.getName()
        );

        if (users.isEmpty()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Active user account not found"));
        }

        Long userId = ((Number)
            users.get(0).get("user_id")).longValue();

        return ResponseEntity.ok(
            service.checkAccess(userId, request.getAssetId())
        );
    }
}
