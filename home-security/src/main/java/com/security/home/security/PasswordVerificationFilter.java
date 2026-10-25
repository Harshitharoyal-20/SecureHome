
package com.security.home.security;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.web.filter.OncePerRequestFilter;

public class PasswordVerificationFilter extends OncePerRequestFilter {

    public static final String VERIFIED_ATTRIBUTE =
            "SECUREHOME_PASSWORD_VERIFIED";

    public static final String OAUTH_AUTHENTICATED_ATTRIBUTE =
            "SECUREHOME_OAUTH_AUTHENTICATED";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        String path = request.getServletPath();
        String method = request.getMethod();

        return !path.startsWith("/api/")
                || path.equals("/api/me")
                || path.equals("/api/auth/login")
                || path.equals("/api/auth/password/verify")
                || path.equals("/api/auth/password/reset")
                || path.equals("/api/access-events")
                || path.startsWith("/api/access-events/")
                || path.equals("/api/security-alerts")
                || path.startsWith("/api/security-alerts/")
                || method.equalsIgnoreCase("OPTIONS");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);

        org.springframework.security.core.Authentication auth =
                org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        boolean isOAuthToken = auth != null && auth.isAuthenticated()
                && (auth instanceof org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken);

        boolean oauthAuthenticated = isOAuthToken || (session != null
                && Boolean.TRUE.equals(
                        session.getAttribute(
                                OAUTH_AUTHENTICATED_ATTRIBUTE)));

        boolean passwordVerified = session != null
                && Boolean.TRUE.equals(
                        session.getAttribute(VERIFIED_ATTRIBUTE));

        if (!oauthAuthenticated && !passwordVerified) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(
                    "{\"error\":\"AUTHENTICATION_REQUIRED\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
