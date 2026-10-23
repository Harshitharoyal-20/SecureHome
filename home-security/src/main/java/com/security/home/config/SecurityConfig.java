
package com.security.home.config;

import java.util.List;

import com.security.home.CustomOAuth2UserService;
import com.security.home.security.PasswordVerificationFilter;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(
            JdbcTemplate jdbcTemplate) {

        JdbcUserDetailsManager manager =
                new JdbcUserDetailsManager(
                        jdbcTemplate.getDataSource());

        manager.setUsersByUsernameQuery(
                "SELECT email, password_hash, " +
                "CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END " +
                "FROM users WHERE email = ?");

        manager.setAuthoritiesByUsernameQuery(
                "SELECT u.email, CONCAT('ROLE_', r.role_name) " +
                "FROM users u " +
                "JOIN roles r ON u.role_id = r.role_id " +
                "WHERE u.email = ? AND u.status = 'ACTIVE'");

        return manager;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {

        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(userDetailsService);

        provider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(provider);
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public PasswordVerificationFilter passwordVerificationFilter() {
        return new PasswordVerificationFilter();
    }

    @Bean
    public FilterRegistrationBean<PasswordVerificationFilter>
            disableContainerFilterRegistration(
                    PasswordVerificationFilter filter) {

        FilterRegistrationBean<PasswordVerificationFilter> registration =
                new FilterRegistrationBean<>(filter);

        registration.setEnabled(false);

        return registration;
    }

    @Bean
    public AuthenticationSuccessHandler oauthSuccessHandler() {
        return (request, response, authentication) -> {
            var session = request.getSession(true);

            session.setAttribute(
                    PasswordVerificationFilter.OAUTH_AUTHENTICATED_ATTRIBUTE,
                    true
            );

            session.removeAttribute(
                    PasswordVerificationFilter.VERIFIED_ATTRIBUTE
            );

            response.sendRedirect(
                    "https://secure-home-kappa.vercel.app/?oauth=success"
            );
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(
                List.of(
                        "https://secure-home-kappa.vercel.app",
                        "http://localhost:5173"
                ));

        configuration.setAllowedMethods(
                List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "PATCH",
                        "DELETE",
                        "OPTIONS"
                ));

        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            CustomOAuth2UserService customOAuth2UserService,
            PasswordVerificationFilter passwordVerificationFilter,
            SecurityContextRepository securityContextRepository,
            AuthenticationSuccessHandler oauthSuccessHandler)
            throws Exception {

        http
            .cors(cors ->
                    cors.configurationSource(
                            corsConfigurationSource()))

            .csrf(csrf -> csrf.disable())

            .securityContext(context ->
                    context.securityContextRepository(
                            securityContextRepository))

            .addFilterBefore(
                    passwordVerificationFilter,
                    AuthorizationFilter.class)

            .authorizeHttpRequests(auth -> auth

                .requestMatchers(
                        HttpMethod.OPTIONS,
                        "/**")
                .permitAll()

                .requestMatchers(
                        "/",
                        "/error",
                        "/oauth2/**",
                        "/login/**",
                        "/api/auth/login")
                .permitAll()

                .requestMatchers(
                        "/api/me",
                        "/api/auth/password/verify",
                        "/api/auth/password/reset")
                .authenticated()

                .requestMatchers("/api/admin/**")
                .hasRole("ADMIN")

                .requestMatchers("/api/guest-access-check")
                .hasRole("GUEST")

                .requestMatchers("/api/access-check")
                .hasAnyRole(
                        "ADMIN",
                        "FAMILY_MEMBER",
                        "SECURITY_STAFF")

                .requestMatchers(
                        "/api/lockers",
                        "/api/lockers/**",
                        "/api/access-events",
                        "/api/access-events/**",
                        "/api/security-alerts",
                        "/api/security-alerts/**")
                .hasAnyRole(
                        "ADMIN",
                        "FAMILY_MEMBER",
                        "SECURITY_STAFF",
                        "GUEST")

                .anyRequest().authenticated()
            )

            .oauth2Login(oauth -> oauth
                .userInfoEndpoint(userInfo ->
                        userInfo.userService(
                                customOAuth2UserService))
                .successHandler(oauthSuccessHandler)
            );

        return http.build();
    }
}
