
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
    private final DefaultOAuth2UserService delegate =
            new DefaultOAuth2UserService();
    private final RestTemplate restTemplate = new RestTemplate();
    private final BCryptPasswordEncoder passwordEncoder =
            new BCryptPasswordEncoder();

    public CustomOAuth2UserService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
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
                "SELECT u.user_id, u.status, r.role_name " +
                "FROM oauth_account_links l " +
                "JOIN users u ON u.user_id = l.user_id " +
                "JOIN roles r ON r.role_id = u.role_id " +
                "WHERE l.provider = ? AND l.provider_user_id = ?",
                "github", providerUserId
        );

        String roleName;

        if (!links.isEmpty()) {
            Map<String, Object> linkedUser = links.get(0);

            if (!"ACTIVE".equalsIgnoreCase(
                    String.valueOf(linkedUser.get("status")))) {
                throw oauthError("access_denied",
                        "Your SecureHome account is inactive");
            }

            roleName = String.valueOf(linkedUser.get("role_name"));

        } else {
            String email = getVerifiedEmail(request);

            if (email == null || email.isBlank()) {
                throw oauthError("invalid_user_info",
                        "No verified GitHub email was found. " +
                        "Verify an email in GitHub and try again.");
            }

            Integer existingUser = jdbcTemplate.query(
                    "SELECT user_id FROM users WHERE email = ?",
                    rs -> rs.next() ? rs.getInt("user_id") : null,
                    email
            );

            if (existingUser != null) {
                throw oauthError("access_denied",
                        "An account already uses this email. " +
                        "Sign in using that account or contact the administrator.");
            }

            Integer familyRoleId = jdbcTemplate.query(
                    "SELECT role_id FROM roles WHERE role_name = ?",
                    rs -> rs.next() ? rs.getInt("role_id") : null,
                    "FAMILY_MEMBER"
            );

            if (familyRoleId == null) {
                throw oauthError("server_error",
                        "FAMILY_MEMBER role is missing from the database");
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

            int inserted = jdbcTemplate.update(connection -> {
                PreparedStatement ps = connection.prepareStatement(
                        "INSERT INTO users " +
                        "(full_name, email, password_hash, role_id, status) " +
                        "VALUES (?, ?, ?, ?, 'ACTIVE')",
                        Statement.RETURN_GENERATED_KEYS
                );
                ps.setString(1, finalName);
                ps.setString(2, email);
                ps.setString(3, unusablePasswordHash);
                ps.setInt(4, familyRoleId);
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

        Set<GrantedAuthority> authorities = new LinkedHashSet<>(
                githubUser.getAuthorities()
        );

        authorities.add(new SimpleGrantedAuthority("ROLE_" + roleName));

        return new DefaultOAuth2User(
                authorities,
                githubUser.getAttributes(),
                "id"
        );
    }

    private String getVerifiedEmail(OAuth2UserRequest request) {
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

        if (emails == null) {
            return null;
        }

        for (Map<String, Object> item : emails) {
            if (Boolean.TRUE.equals(item.get("primary"))
                    && Boolean.TRUE.equals(item.get("verified"))) {
                Object email = item.get("email");
                return email == null ? null : email.toString();
            }
        }

        for (Map<String, Object> item : emails) {
            if (Boolean.TRUE.equals(item.get("verified"))) {
                Object email = item.get("email");
                if (email != null) {
                    return email.toString();
                }
            }
        }

        return null;
    }

    private OAuth2AuthenticationException oauthError(
            String code, String description) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(code), description);
    }
}
