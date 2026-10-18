
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

        boolean verified = session != null
                && Boolean.TRUE.equals(
                        session.getAttribute(VERIFIED_ATTRIBUTE));

        if (!verified) {
            response.setStatus(
                    HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

            response.getWriter().write(
                    "{\"error\":\"PASSWORD_VERIFICATION_REQUIRED\"}");

            return;
        }

        filterChain.doFilter(request, response);
    }
}
