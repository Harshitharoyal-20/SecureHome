
package com.security.home.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AuthController {

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> currentUser(
            Authentication authentication) {

        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("authenticated", false));
        }

        List<String> authorities = authentication.getAuthorities()
                .stream()
                .map(authority -> authority.getAuthority())
                .toList();

        return ResponseEntity.ok(Map.of(
                "authenticated", true,
                "username", authentication.getName(),
                "authorities", authorities
        ));
    }
}
