
package com.security.home;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.jdbc.core.JdbcTemplate;
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

@Service
public class CustomOAuth2UserService
        implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final JdbcTemplate jdbcTemplate;
    private final DefaultOAuth2UserService delegate =
            new DefaultOAuth2UserService();

    public CustomOAuth2UserService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request)
            throws OAuth2AuthenticationException {

        OAuth2User githubUser = delegate.loadUser(request);

        Object githubId = githubUser.getAttributes().get("id");

        if (githubId == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_user_info"),
                    "GitHub account ID was not provided"
            );
        }

        String providerUserId = githubId.toString();

        List<GrantedAuthority> databaseAuthorities =
                jdbcTemplate.query(
                        "SELECT CONCAT('ROLE_', r.role_name) " +
                        "FROM oauth_account_links l " +
                        "JOIN users u ON u.user_id = l.user_id " +
                        "JOIN roles r ON r.role_id = u.role_id " +
                        "WHERE l.provider = ? " +
                        "AND l.provider_user_id = ? " +
                        "AND u.status = 'ACTIVE'",
                        (rs, rowNum) -> new SimpleGrantedAuthority(
                                rs.getString(1)
                        ),
                        "github",
                        providerUserId
                );

        if (databaseAuthorities.isEmpty()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("access_denied"),
                    "GitHub account is not linked to an active application user"
            );
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet<>(
                githubUser.getAuthorities()
        );
        authorities.addAll(databaseAuthorities);

        return new DefaultOAuth2User(
                authorities,
                githubUser.getAttributes(),
                "id"
        );
    }
}
