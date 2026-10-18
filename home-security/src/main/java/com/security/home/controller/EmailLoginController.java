
package com.security.home.controller;

import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import com.security.home.security.PasswordVerificationFilter;

@RestController
@RequestMapping("/api/auth")
public class EmailLoginController {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    public EmailLoginController(
            AuthenticationManager authenticationManager,
            SecurityContextRepository securityContextRepository) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
    }

    public record LoginRequest(String email, String password) {}

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody(required = false) LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        if (request == null
                || request.email() == null
                || request.email().isBlank()
                || request.password() == null
                || request.password().isBlank()) {

            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error",
                            "Email and password are required"));
        }

        try {
            Authentication authentication =
                    authenticationManager.authenticate(
                            new UsernamePasswordAuthenticationToken(
                                    request.email().trim(),
                                    request.password()));

            httpRequest.getSession(true);
            httpRequest.changeSessionId();

            SecurityContext context =
                    SecurityContextHolder.createEmptyContext();

            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            securityContextRepository.saveContext(
                    context,
                    httpRequest,
                    httpResponse);

            HttpSession currentSession =
                    httpRequest.getSession(false);

            if (currentSession == null) {
                SecurityContextHolder.clearContext();

                return ResponseEntity
                        .status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of(
                                "error",
                                "Unable to create login session"));
            }

            currentSession.setAttribute(
                    PasswordVerificationFilter.VERIFIED_ATTRIBUTE,
                    true);

            List<String> authorities =
                    authentication.getAuthorities()
                            .stream()
                            .map(authority -> authority.getAuthority())
                            .toList();

            return ResponseEntity.ok(
                    Map.of(
                            "authenticated", true,
                            "username", authentication.getName(),
                            "authorities", authorities));

        } catch (org.springframework.security.core.AuthenticationException ex) {

            SecurityContextHolder.clearContext();

            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                            "error",
                            "Invalid email or password"));
        }
    }
}
