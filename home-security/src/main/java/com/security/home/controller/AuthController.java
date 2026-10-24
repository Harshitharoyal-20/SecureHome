
package com.security.home.controller;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.security.home.security.PasswordVerificationFilter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AuthController {

    private static final Set<String> PRIVILEGED_EMAILS = Set.of(
        "sivakumar6413@gmail.com",
        "pranawii0713@gmail.com",
        "harshitha0064@gmail.com"
    );

    private static final String SECURITY_EMAIL = "mahesh0562@gmail.com";

    private final JdbcTemplate jdbc;
    private final com.security.home.service.GithubNotificationService githubNotificationService;

    public AuthController(JdbcTemplate jdbc, com.security.home.service.GithubNotificationService githubNotificationService) {
        this.jdbc = jdbc;
        this.githubNotificationService = githubNotificationService;
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> currentUser(
            Authentication authentication,
            HttpServletRequest request) {

        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("authenticated", false));
        }

        HttpSession session = request.getSession(false);

        boolean passwordVerified = session != null
                && Boolean.TRUE.equals(
                        session.getAttribute(
                                PasswordVerificationFilter.VERIFIED_ATTRIBUTE));

        boolean oauthAuthenticated =
                authentication instanceof OAuth2AuthenticationToken
                || (session != null
                    && Boolean.TRUE.equals(
                        session.getAttribute(
                            PasswordVerificationFilter.OAUTH_AUTHENTICATED_ATTRIBUTE)));

        List<String> authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        Integer userId = null;
        String email = "";
        String fullName = "";
        String roleName = "";
        boolean isGithub = false;

        if (authentication.getPrincipal() instanceof OAuth2User oauth) {
            isGithub = true;
            Object providerId = oauth.getAttribute("id");

            if (providerId != null) {
                List<Map<String, Object>> linked = jdbc.queryForList(
                    "SELECT u.user_id, u.full_name, u.email, r.role_name " +
                    "FROM oauth_account_links o " +
                    "JOIN users u ON u.user_id = o.user_id " +
                    "JOIN roles r ON r.role_id = u.role_id " +
                    "WHERE LOWER(o.provider) = 'github' " +
                    "AND o.provider_user_id = ? " +
                    "AND u.status = 'ACTIVE' LIMIT 1",
                    String.valueOf(providerId)
                );

                if (!linked.isEmpty()) {
                    Map<String, Object> row = linked.get(0);
                    userId = ((Number) row.get("user_id")).intValue();
                    fullName = row.get("full_name") == null ? "" : String.valueOf(row.get("full_name"));
                    email = row.get("email") == null ? "" : String.valueOf(row.get("email")).trim();
                    roleName = row.get("role_name") == null ? "" : String.valueOf(row.get("role_name"));
                }
            }

            if (email.isBlank() && oauth.getAttribute("email") != null) {
                email = String.valueOf(oauth.getAttribute("email")).trim();
            }
            if (fullName.isBlank()) {
                Object name = oauth.getAttribute("name");
                fullName = name != null ? String.valueOf(name) : String.valueOf(oauth.getAttribute("login"));
            }

            try {
                Object loginObj = oauth.getAttribute("login");
                String login = loginObj != null ? String.valueOf(loginObj) : (fullName.isBlank() ? "github-user" : fullName);
                githubNotificationService.recordAccess(login, fullName, email);
            } catch (Exception ignored) {
            }
        } else {
            String loginName = authentication.getName();
            List<Map<String, Object>> found = jdbc.queryForList(
                "SELECT u.user_id, u.full_name, u.email, r.role_name " +
                "FROM users u " +
                "JOIN roles r ON r.role_id = u.role_id " +
                "WHERE LOWER(u.email) = LOWER(?) " +
                "AND u.status = 'ACTIVE' LIMIT 1",
                loginName
            );

            if (!found.isEmpty()) {
                Map<String, Object> row = found.get(0);
                userId = ((Number) row.get("user_id")).intValue();
                fullName = row.get("full_name") == null ? "" : String.valueOf(row.get("full_name"));
                email = row.get("email") == null ? "" : String.valueOf(row.get("email")).trim();
                roleName = row.get("role_name") == null ? "" : String.valueOf(row.get("role_name"));
            } else {
                email = loginName;
            }
        }

        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);

        boolean isAdmin =
            "ADMIN".equalsIgnoreCase(roleName)
            || authorities.contains("ROLE_ADMIN")
            || PRIVILEGED_EMAILS.contains(normalizedEmail);

        boolean isSecurity =
            roleName.toUpperCase(Locale.ROOT).contains("SECURITY")
            || authorities.stream().anyMatch(a -> a.toUpperCase(Locale.ROOT).contains("SECURITY"))
            || SECURITY_EMAIL.equalsIgnoreCase(normalizedEmail);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("authenticated", true);
        result.put("username", !email.isBlank() ? email : authentication.getName());
        result.put("userId", userId);
        result.put("fullName", fullName);
        result.put("email", email);
        result.put("role", roleName);
        result.put("isGithub", isGithub);
        result.put("isAdmin", isAdmin);
        result.put("isSecurity", isSecurity);
        result.put("authorities", authorities);
        result.put("passwordVerified", passwordVerified);
        result.put("oauthAuthenticated", oauthAuthenticated);

        return ResponseEntity.ok(result);
    }
}
