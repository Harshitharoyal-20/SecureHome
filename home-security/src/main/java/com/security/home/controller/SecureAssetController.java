
package com.security.home.controller;

import com.security.home.entity.SecureAsset;
import com.security.home.repository.SecureAssetRepository;
import jakarta.validation.Valid;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Locale;
import java.util.Set;

@RestController
@RequestMapping("/api/lockers")
@CrossOrigin(origins = {
    "http://localhost:5173",
    "https://secure-home-kappa.vercel.app"
})
public class SecureAssetController {

    private static final Set<String> PRIVILEGED_EMAILS = Set.of(
        "sivakumar6413@gmail.com",
        "pranawii0713@gmail.com",
        "harshitha0064@gmail.com"
    );

    private final SecureAssetRepository repository;
    private final JdbcTemplate jdbc;

    public SecureAssetController(
            SecureAssetRepository repository,
            JdbcTemplate jdbc) {
        this.repository = repository;
        this.jdbc = jdbc;
    }

    private int getUserId(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()
                || "anonymousUser".equals(
                    String.valueOf(auth.getPrincipal()))) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Please log in first."
            );
        }

        if (auth.getPrincipal() instanceof OAuth2User oauth) {
            Object githubId = oauth.getAttribute("id");

            if (githubId != null) {
                List<Integer> ids = jdbc.query(
                    "SELECT u.user_id " +
                    "FROM oauth_account_links o " +
                    "JOIN users u ON u.user_id = o.user_id " +
                    "WHERE LOWER(o.provider) = 'github' " +
                    "AND o.provider_user_id = ? " +
                    "AND u.status = 'ACTIVE' " +
                    "LIMIT 1",
                    (rs, rowNum) -> rs.getInt("user_id"),
                    String.valueOf(githubId)
                );

                if (!ids.isEmpty()) {
                    return ids.get(0);
                }
            }
        }

        List<Integer> emailIds = jdbc.query(
            "SELECT u.user_id FROM users u " +
            "WHERE LOWER(u.email) = LOWER(?) " +
            "AND u.status = 'ACTIVE' LIMIT 1",
            (rs, rowNum) -> rs.getInt("user_id"),
            auth.getName()
        );

        if (!emailIds.isEmpty()) {
            return emailIds.get(0);
        }

        throw new ResponseStatusException(
            HttpStatus.FORBIDDEN,
            "No active application user is linked to this login."
        );
    }

    private String findUserEmail(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }

        if (auth.getPrincipal() instanceof OAuth2User oauth) {
            Object githubId = oauth.getAttribute("id");

            if (githubId != null) {
                List<String> emails = jdbc.query(
                    "SELECT u.email " +
                    "FROM oauth_account_links o " +
                    "JOIN users u ON u.user_id = o.user_id " +
                    "WHERE LOWER(o.provider) = 'github' " +
                    "AND o.provider_user_id = ? " +
                    "AND u.status = 'ACTIVE' " +
                    "LIMIT 1",
                    (rs, rowNum) -> rs.getString("email"),
                    String.valueOf(githubId)
                );

                if (!emails.isEmpty()) {
                    return emails.get(0);
                }
            }
        }

        List<String> emails = jdbc.query(
            "SELECT email FROM users " +
            "WHERE LOWER(email) = LOWER(?) " +
            "AND status = 'ACTIVE' LIMIT 1",
            (rs, rowNum) -> rs.getString("email"),
            auth.getName()
        );

        return emails.isEmpty() ? null : emails.get(0);
    }

    private boolean isAdmin(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }

        if (auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()))) {
            return true;
        }

        String email = findUserEmail(auth);

        return email != null
            && PRIVILEGED_EMAILS.contains(
                email.trim().toLowerCase(Locale.ROOT)
            );
    }

    private boolean isSecurity(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }

        if (auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().toUpperCase(Locale.ROOT).contains("SECURITY"))) {
            return true;
        }

        String email = findUserEmail(auth);

        return email != null
            && "mahesh0562@gmail.com".equalsIgnoreCase(email.trim());
    }

    private void requireAdmin(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Please sign in first."
            );
        }

        if (!isAdmin(auth)) {
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN,
                "Only administrators can modify lockers."
            );
        }
    }

    private boolean hasAccess(Integer assetId, int userId) {
        Integer count = jdbc.queryForObject(
            "SELECT COUNT(*) " +
            "FROM secure_assets s " +
            "WHERE s.asset_id = ? " +
            "AND s.status = 'ACTIVE' " +
            "AND (" +
            "s.owner_user_id = ? " +
            "OR EXISTS (" +
            "SELECT 1 FROM asset_permissions p " +
            "WHERE p.asset_id = s.asset_id " +
            "AND p.user_id = ? " +
            "AND p.is_active = 1 " +
            "AND p.valid_from IS NOT NULL " +
            "AND p.valid_until IS NOT NULL " +
            "AND UTC_TIMESTAMP() BETWEEN p.valid_from AND p.valid_until " +
            "AND (" +
            "p.allowed_start IS NULL OR p.allowed_end IS NULL " +
            "OR p.allowed_start = p.allowed_end " +
            "OR (p.allowed_start = '00:00:00' AND p.allowed_end = '23:59:59') " +
            "OR CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '+05:30') BETWEEN p.allowed_start AND p.allowed_end " +
            "OR CURTIME() BETWEEN p.allowed_start AND p.allowed_end" +
            ")" +
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
        if (auth == null || !auth.isAuthenticated()) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Please log in first."
            );
        }

        if (isAdmin(auth) || isSecurity(auth)) {
            return repository.findByStatus("ACTIVE");
        }

        int userId = getUserId(auth);

        return repository.findByStatus("ACTIVE").stream()
            .filter(asset -> hasAccess(asset.getAssetId(), userId))
            .toList();
    }

    @GetMapping("/{id}")
    public SecureAsset getLocker(
            @PathVariable Integer id,
            Authentication auth) {

        if (auth == null || !auth.isAuthenticated()) {
            throw new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Please log in first."
            );
        }

        SecureAsset asset = repository.findById(id)
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "Locker not found."
            ));

        if (!"ACTIVE".equalsIgnoreCase(asset.getStatus())) {
            throw new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "This locker is inactive."
            );
        }

        if (!isAdmin(auth) && !isSecurity(auth)) {
            int userId = getUserId(auth);

            if (!hasAccess(id, userId)) {
                throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "You can't view this locker because you don't have permission."
                );
            }
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
        asset.setAssetType(asset.getAssetType().trim().toUpperCase(Locale.ROOT));
        asset.setLocationDescription(
            asset.getLocationDescription().trim()
        );
        asset.setStatus(asset.getStatus().trim().toUpperCase(Locale.ROOT));

        if (asset.getOwnerUserId() == null) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Owner is required."
            );
        }

        Integer count = jdbc.queryForObject(
            "SELECT COUNT(*) FROM users " +
            "WHERE user_id = ? AND status = 'ACTIVE'",
            Integer.class,
            asset.getOwnerUserId()
        );

        if (count == null || count == 0) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Active owner not found."
            );
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
                "Locker not found."
            ));

        existing.setAssetName(input.getAssetName().trim());
        existing.setAssetType(
            input.getAssetType().trim().toUpperCase(Locale.ROOT)
        );
        existing.setLocationDescription(
            input.getLocationDescription().trim()
        );
        existing.setStatus(
            input.getStatus().trim().toUpperCase(Locale.ROOT)
        );

        if (input.getOwnerUserId() != null) {
            Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM users " +
                "WHERE user_id = ? AND status = 'ACTIVE'",
                Integer.class,
                input.getOwnerUserId()
            );

            if (count == null || count == 0) {
                throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Active owner not found."
                );
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
                "Locker not found."
            ));

        try {
            repository.delete(existing);
            repository.flush();
        } catch (DataIntegrityViolationException ex) {
            throw new ResponseStatusException(
                HttpStatus.CONFLICT,
                "This locker has related records. Set its status to INACTIVE instead."
            );
        }
    }
}
