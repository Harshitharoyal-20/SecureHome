
package com.security.home.controller;

import com.security.home.entity.SecureAsset;
import com.security.home.repository.SecureAssetRepository;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.ZoneId;
import java.util.List;

@RestController
@RequestMapping("/api/lockers")
@CrossOrigin(origins = {
    "http://localhost:5173",
    "https://secure-home-kappa.vercel.app"
})
public class SecureAssetController {

    private static final ZoneId APP_ZONE =
            ZoneId.of("Asia/Kolkata");

    private final SecureAssetRepository repository;
    private final JdbcTemplate jdbcTemplate;

    public SecureAssetController(
            SecureAssetRepository repository,
            JdbcTemplate jdbcTemplate) {
        this.repository = repository;
        this.jdbcTemplate = jdbcTemplate;
    }

    private boolean isAdmin(Authentication auth) {
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }

    private void requireAdmin(Authentication auth) {
        if (!isAdmin(auth)) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "Only administrators can modify lockers");
        }
    }

    private int getUserId(Authentication auth) {
        if (auth == null) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Login required");
        }

        String username = auth.getName();

        List<Integer> ids = jdbcTemplate.query(
                "SELECT user_id FROM users " +
                "WHERE email = ? AND status = 'ACTIVE'",
                (rs, row) -> rs.getInt("user_id"),
                username);

        if (!ids.isEmpty()) {
            return ids.get(0);
        }

        ids = jdbcTemplate.query(
                "SELECT u.user_id FROM users u " +
                "JOIN oauth_account_links o ON o.user_id = u.user_id " +
                "WHERE o.provider = 'github' " +
                "AND o.provider_user_id = ? " +
                "AND u.status = 'ACTIVE'",
                (rs, row) -> rs.getInt("user_id"),
                username);

        if (!ids.isEmpty()) {
            return ids.get(0);
        }

        throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "Active SecureHome user not found for this login");
    }

    private boolean hasAccess(Integer assetId, int userId) {
        Integer count = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM secure_assets s " +
            "WHERE s.asset_id = ? " +
            "AND s.status = 'ACTIVE' " +
            "AND (" +
            "s.owner_user_id = ? OR EXISTS (" +
            "SELECT 1 FROM asset_permissions p " +
            "WHERE p.asset_id = s.asset_id " +
            "AND p.user_id = ? " +
            "AND p.is_active = 1 " +
            "AND p.valid_from IS NOT NULL " +
            "AND p.valid_until IS NOT NULL " +
            "AND NOW() >= p.valid_from " +
            "AND NOW() <= p.valid_until " +
            "AND CURRENT_TIME >= p.allowed_start " +
            "AND CURRENT_TIME <= p.allowed_end" +
            "))",
            Integer.class,
            assetId,
            userId,
            userId
        );

        return count != null && count > 0;
    }

    @GetMapping
    public List<SecureAsset> getLockers(Authentication auth) {
        if (isAdmin(auth)) {
            return repository.findByStatus("ACTIVE");
        }

        int userId = getUserId(auth);

        return repository.findByStatus("ACTIVE").stream()
                .filter(asset ->
                        hasAccess(asset.getAssetId(), userId))
                .toList();
    }

    @GetMapping("/{id}")
    public SecureAsset getLocker(
            @PathVariable Integer id,
            Authentication auth) {

        SecureAsset asset = repository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Locker not found"));

        if (!"ACTIVE".equalsIgnoreCase(asset.getStatus())) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND,
                    "Locker is inactive");
        }

        if (!isAdmin(auth) &&
                !hasAccess(id, getUserId(auth))) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "You do not currently have permission to view this locker");
        }

        return asset;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public SecureAsset createLocker(
            @Valid @RequestBody SecureAsset asset,
            Authentication auth) {

        requireAdmin(auth);

        asset.setAssetName(asset.getAssetName().trim());
        asset.setAssetType(
                asset.getAssetType().trim().toUpperCase());
        asset.setLocationDescription(
                asset.getLocationDescription().trim());
        asset.setStatus(
                asset.getStatus().trim().toUpperCase());

        if (asset.getOwnerUserId() == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Owner is required");
        }

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM users " +
                "WHERE user_id = ? AND status = 'ACTIVE'",
                Integer.class,
                asset.getOwnerUserId());

        if (count == null || count == 0) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Active owner not found");
        }

        return repository.save(asset);
    }

    @PutMapping("/{id}")
    public SecureAsset updateLocker(
            @PathVariable Integer id,
            @Valid @RequestBody SecureAsset input,
            Authentication auth) {

        requireAdmin(auth);

        SecureAsset existing = repository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Locker not found"));

        existing.setAssetName(input.getAssetName().trim());
        existing.setAssetType(
                input.getAssetType().trim().toUpperCase());
        existing.setLocationDescription(
                input.getLocationDescription().trim());
        existing.setStatus(
                input.getStatus().trim().toUpperCase());

        if (input.getOwnerUserId() != null) {
            Integer count = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM users " +
                    "WHERE user_id = ? AND status = 'ACTIVE'",
                    Integer.class,
                    input.getOwnerUserId());

            if (count == null || count == 0) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Active owner not found");
            }

            existing.setOwnerUserId(input.getOwnerUserId());
        }

        return repository.save(existing);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteLocker(
            @PathVariable Integer id,
            Authentication auth) {

        requireAdmin(auth);

        SecureAsset existing = repository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Locker not found"));

        try {
            repository.delete(existing);
            repository.flush();
        } catch (
                org.springframework.dao.DataIntegrityViolationException ex) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "This locker has related records. " +
                    "Set its status to INACTIVE instead.");
        }
    }
}
