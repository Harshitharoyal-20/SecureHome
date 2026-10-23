
package com.security.home.controller;

import com.security.home.entity.SecureAsset;
import com.security.home.repository.SecureAssetRepository;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.util.List;

@RestController
@RequestMapping("/api/lockers")
@CrossOrigin(origins = {
        "http://localhost:5173",
       "https://secure-home-kappa.vercel.app"
})
public class SecureAssetController {

    private final SecureAssetRepository repository;
    private final JdbcTemplate jdbcTemplate;

    public SecureAssetController(
            SecureAssetRepository repository,
            JdbcTemplate jdbcTemplate) {
        this.repository = repository;
        this.jdbcTemplate = jdbcTemplate;
    }

    private boolean isAdmin(Authentication authentication) {
        return authentication != null &&
                authentication.getAuthorities().stream()
                        .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }

    
private int getUserId(Authentication authentication) {
    if (authentication == null) {
        throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED, "Login required");
    }

    String username = authentication.getName();

    List<Integer> ids = jdbcTemplate.query(
            "SELECT user_id FROM users " +
            "WHERE email = ? AND status = 'ACTIVE'",
            (rs, rowNum) -> rs.getInt("user_id"),
            username
    );

    if (!ids.isEmpty()) {
        return ids.get(0);
    }

    // Resolve a GitHub OAuth ID to its SecureHome database user.
    ids = jdbcTemplate.query(
            "SELECT u.user_id " +
            "FROM users u " +
            "JOIN oauth_accounts o ON o.user_id = u.user_id " +
            "WHERE o.provider = 'github' " +
            "AND o.provider_user_id = ? " +
            "AND u.status = 'ACTIVE'",
            (rs, rowNum) -> rs.getInt("user_id"),
            username
    );

    if (!ids.isEmpty()) {
        return ids.get(0);
    }

    throw new ResponseStatusException(
            HttpStatus.FORBIDDEN,
            "Active SecureHome user not found for this login");
}


    private void requireAdmin(Authentication authentication) {
        if (!isAdmin(authentication)) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "Only administrators can modify lockers");
        }
    }

    private boolean hasAccess(Integer assetId, int userId) {
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM secure_assets s " +
                "WHERE s.asset_id = ? AND s.status = 'ACTIVE' " +
                "AND (s.owner_user_id = ? OR EXISTS (" +
                "SELECT 1 FROM asset_permissions p " +
                "WHERE p.asset_id = s.asset_id " +
                "AND p.user_id = ? AND p.is_active = 1 " +
                "AND (p.allowed_start IS NULL OR CURRENT_TIME >= p.allowed_start) " +
                "AND (p.allowed_end IS NULL OR CURRENT_TIME <= p.allowed_end)))",
                Integer.class, assetId, userId, userId);

        return count != null && count > 0;
    }

    @GetMapping
    public List<SecureAsset> getLockers(Authentication authentication) {
        System.out.println(
                "ORM asset count: " + repository.findAll().size());

        if (isAdmin(authentication)) {
            return repository.findByStatus("ACTIVE");
        }

        int userId = getUserId(authentication);

        return repository.findByStatus("ACTIVE").stream()
                .filter(asset -> hasAccess(asset.getAssetId(), userId))
                .toList();
    }

    @GetMapping("/{id}")
    public SecureAsset getLocker(
            @PathVariable Integer id,
            Authentication authentication) {

        SecureAsset asset = repository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Locker not found"));

        if (isAdmin(authentication)) {
            return asset;
        }

        int userId = getUserId(authentication);

        if (!hasAccess(id, userId)) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN, "You do not have access to this locker");
        }

        return asset;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public SecureAsset createLocker(
            @Valid @RequestBody SecureAsset asset,
            Authentication authentication) {

        requireAdmin(authentication);

        asset.setAssetName(asset.getAssetName().trim());
        asset.setAssetType(asset.getAssetType().trim().toUpperCase());
        asset.setLocationDescription(
                asset.getLocationDescription().trim());
        asset.setStatus(asset.getStatus().trim().toUpperCase());

        if (asset.getOwnerUserId() == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Owner is required");
        }

        Integer ownerCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM users WHERE user_id = ? AND status = 'ACTIVE'",
                Integer.class, asset.getOwnerUserId());

        if (ownerCount == null || ownerCount == 0) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Active owner not found");
        }

        return repository.save(asset);
    }

    @PutMapping("/{id}")
    public SecureAsset updateLocker(
            @PathVariable Integer id,
            @Valid @RequestBody SecureAsset input,
            Authentication authentication) {

        requireAdmin(authentication);

        SecureAsset existing = repository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Locker not found"));

        existing.setAssetName(input.getAssetName().trim());
        existing.setAssetType(input.getAssetType().trim().toUpperCase());
        existing.setLocationDescription(
                input.getLocationDescription().trim());
        existing.setStatus(input.getStatus().trim().toUpperCase());

        if (input.getOwnerUserId() != null) {
            Integer ownerCount = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM users WHERE user_id = ? AND status = 'ACTIVE'",
                    Integer.class, input.getOwnerUserId());

            if (ownerCount == null || ownerCount == 0) {
                throw new ResponseStatusException(
                        HttpStatus.BAD_REQUEST, "Active owner not found");
            }

            existing.setOwnerUserId(input.getOwnerUserId());
        }

        return repository.save(existing);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteLocker(
            @PathVariable Integer id,
            Authentication authentication) {

        requireAdmin(authentication);

        SecureAsset existing = repository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Locker not found"));

        try {
            repository.delete(existing);
            repository.flush();
        } catch (org.springframework.dao.DataIntegrityViolationException ex) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "This locker has related records. Change its status to INACTIVE instead.");
        }
    }
}
