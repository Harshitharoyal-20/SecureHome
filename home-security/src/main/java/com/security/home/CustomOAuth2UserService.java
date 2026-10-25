
package com.security.home;

import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

@Service
public class CustomOAuth2UserService
        implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final JdbcTemplate jdbcTemplate;
    private final com.security.home.service.GithubNotificationService githubNotificationService;
    private final DefaultOAuth2UserService delegate =
            new DefaultOAuth2UserService();
    private final RestTemplate restTemplate = new RestTemplate();
    private final BCryptPasswordEncoder passwordEncoder =
            new BCryptPasswordEncoder();

    public CustomOAuth2UserService(
            JdbcTemplate jdbcTemplate,
            com.security.home.service.GithubNotificationService githubNotificationService) {
        this.jdbcTemplate = jdbcTemplate;
        this.githubNotificationService = githubNotificationService;
    }

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest request)
            throws OAuth2AuthenticationException {

        OAuth2User githubUser = delegate.loadUser(request);

        Object githubId = githubUser.getAttributes().get("id");

        if (githubId == null) {
            throw oauthError("invalid_user_info",
                    "GitHub account ID was not provided");
        }

        String providerUserId = githubId.toString();

        List<Map<String, Object>> links = jdbcTemplate.queryForList(
                "SELECT u.user_id, u.status, u.email, r.role_name " +
                "FROM oauth_account_links l " +
                "JOIN users u ON u.user_id = l.user_id " +
                "JOIN roles r ON r.role_id = u.role_id " +
                "WHERE l.provider = ? AND l.provider_user_id = ?",
                "github", providerUserId
        );

        String roleName;
        String email = "";

        if (!links.isEmpty()) {
            Map<String, Object> linkedUser = links.get(0);

            if (!"ACTIVE".equalsIgnoreCase(
                    String.valueOf(linkedUser.get("status")))) {
                throw oauthError("access_denied",
                        "Your SecureHome account is inactive");
            }

            roleName = String.valueOf(linkedUser.get("role_name"));
            Object existingEmail = linkedUser.get("email");
            if (existingEmail != null) {
                email = existingEmail.toString();
            }

        } else {
            email = resolveUserEmail(request, githubUser);

            Integer existingUser = jdbcTemplate.query(
                    "SELECT user_id FROM users WHERE LOWER(email) = LOWER(?)",
                    rs -> rs.next() ? rs.getInt("user_id") : null,
                    email
            );

            if (existingUser != null) {
                // Seamlessly link this GitHub account to the existing user
                jdbcTemplate.update(
                        "INSERT INTO oauth_account_links (provider, provider_user_id, user_id) " +
                        "VALUES (?, ?, ?) " +
                        "ON DUPLICATE KEY UPDATE user_id = VALUES(user_id)",
                        "github", providerUserId, existingUser
                );

                String existingRole = jdbcTemplate.query(
                        "SELECT r.role_name FROM users u JOIN roles r ON r.role_id = u.role_id WHERE u.user_id = ?",
                        rs -> rs.next() ? rs.getString("role_name") : null,
                        existingUser
                );
                roleName = (existingRole != null && !existingRole.isBlank()) ? existingRole : "FAMILY_MEMBER";
            } else {
                Integer familyRoleId = jdbcTemplate.query(
                        "SELECT role_id FROM roles WHERE role_name = ?",
                        rs -> rs.next() ? rs.getInt("role_id") : null,
                        "FAMILY_MEMBER"
                );

                if (familyRoleId == null) {
                    familyRoleId = jdbcTemplate.query(
                            "SELECT role_id FROM roles ORDER BY role_id ASC LIMIT 1",
                            rs -> rs.next() ? rs.getInt("role_id") : 2
                    );
                }

                String name = githubUser.getAttribute("name");
                String login = githubUser.getAttribute("login");

                if (name == null || name.isBlank()) {
                    name = login;
                }

                if (name == null || name.isBlank()) {
                    name = "GitHub User";
                }

                String unusablePasswordHash =
                        passwordEncoder.encode(UUID.randomUUID().toString());

                KeyHolder keyHolder = new GeneratedKeyHolder();
                String finalName = name;
                String finalEmail = email;
                int finalRoleId = familyRoleId != null ? familyRoleId : 2;

                int inserted = jdbcTemplate.update(connection -> {
                    PreparedStatement ps = connection.prepareStatement(
                            "INSERT INTO users " +
                            "(full_name, email, password_hash, role_id, status) " +
                            "VALUES (?, ?, ?, ?, 'ACTIVE')",
                            Statement.RETURN_GENERATED_KEYS
                    );
                    ps.setString(1, finalName);
                    ps.setString(2, finalEmail);
                    ps.setString(3, unusablePasswordHash);
                    ps.setInt(4, finalRoleId);
                    return ps;
                }, keyHolder);

                Number generatedId = keyHolder.getKey();

                if (inserted != 1 || generatedId == null) {
                    throw oauthError("server_error",
                            "Could not create your SecureHome account");
                }

                int userId = generatedId.intValue();

                jdbcTemplate.update(
                        "INSERT INTO oauth_account_links " +
                        "(provider, provider_user_id, user_id) " +
                        "VALUES (?, ?, ?)",
                        "github", providerUserId, userId
                );

                roleName = "FAMILY_MEMBER";
            }
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet<>(
                githubUser.getAuthorities()
        );

        authorities.add(new SimpleGrantedAuthority("ROLE_" + roleName));

        try {
            String githubLogin = githubUser.getAttribute("login") != null
                    ? String.valueOf(githubUser.getAttribute("login"))
                    : "github-user";
            String githubName = githubUser.getAttribute("name") != null
                    ? String.valueOf(githubUser.getAttribute("name"))
                    : githubLogin;
            String userEmail = githubUser.getAttribute("email") != null
                    ? String.valueOf(githubUser.getAttribute("email"))
                    : (email != null ? email : "");
            githubNotificationService.recordAccess(githubLogin, githubName, userEmail);
        } catch (Exception ignored) {
        }

        return new DefaultOAuth2User(
                authorities,
                githubUser.getAttributes(),
                "id"
        );
    }

    private String resolveUserEmail(OAuth2UserRequest request, OAuth2User githubUser) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(
                    request.getAccessToken().getTokenValue());
            headers.set("Accept", "application/vnd.github+json");

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            List<Map<String, Object>> emails = restTemplate.exchange(
                    "https://api.github.com/user/emails",
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<
                            List<Map<String, Object>>>() {}
            ).getBody();

            if (emails != null && !emails.isEmpty()) {
                // Priority 1: Primary and verified
                for (Map<String, Object> item : emails) {
                    if (Boolean.TRUE.equals(item.get("primary"))
                            && Boolean.TRUE.equals(item.get("verified"))) {
                        Object email = item.get("email");
                        if (email != null && !email.toString().isBlank()) {
                            return email.toString().trim();
                        }
                    }
                }

                // Priority 2: Any verified email
                for (Map<String, Object> item : emails) {
                    if (Boolean.TRUE.equals(item.get("verified"))) {
                        Object email = item.get("email");
                        if (email != null && !email.toString().isBlank()) {
                            return email.toString().trim();
                        }
                    }
                }

                // Priority 3: Primary email (even if freshly created / unverified)
                for (Map<String, Object> item : emails) {
                    if (Boolean.TRUE.equals(item.get("primary"))) {
                        Object email = item.get("email");
                        if (email != null && !email.toString().isBlank()) {
                            return email.toString().trim();
                        }
                    }
                }

                // Priority 4: Any listed email
                for (Map<String, Object> item : emails) {
                    Object email = item.get("email");
                    if (email != null && !email.toString().isBlank()) {
                        return email.toString().trim();
                    }
                }
            }
        } catch (Exception ignored) {
            // Continue to attribute fallbacks if GitHub /user/emails API request fails
        }

        // Priority 5: Profile attribute email
        Object attrEmail = githubUser.getAttribute("email");
        if (attrEmail != null && !attrEmail.toString().isBlank()) {
            return attrEmail.toString().trim();
        }

        // Priority 6: Official GitHub noreply email address
        Object login = githubUser.getAttribute("login");
        Object id = githubUser.getAttribute("id");
        if (login != null && !login.toString().isBlank()) {
            return login.toString().trim().toLowerCase() + "@users.noreply.github.com";
        }
        if (id != null) {
            return "user" + id + "@users.noreply.github.com";
        }

        return "github_" + UUID.randomUUID().toString().substring(0, 8) + "@securehome.local";
    }

    private OAuth2AuthenticationException oauthError(
            String code, String description) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(code), description);
    }
}
