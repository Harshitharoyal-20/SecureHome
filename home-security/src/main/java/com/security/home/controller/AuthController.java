
package com.security.home.controller;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.security.home.security.PasswordVerificationFilter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AuthController {

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

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("authenticated", true);
        result.put("username", authentication.getName());
        result.put("authorities", authorities);
        result.put("passwordVerified", passwordVerified);
        result.put("oauthAuthenticated", oauthAuthenticated);

        return ResponseEntity.ok(result);
    }
}
