package com.bsharan.auth_service.jwtSecurity.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;

import com.bsharan.auth_service.jwtSecurity.jwt.JwtAuthenticationFilter;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class JwtSecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration
    ) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
@Order(1)
    SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {

        http
                .securityMatcher("/api/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .anonymous(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/v1/auth/jwt/login",
                                "/api/v1/auth/register")
                        .permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        SecurityContextHolderFilter.class);

        return http.build();
    }


    // JWT chain evaluated first → matcher matches, JWT chain is used, Session-based chain is ignored
    // @Bean
    // @Order(0)
    // SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {

    //     http
    //         .securityMatcher("/api/**") // no HttpSession, JSESSIONID, formLogin
    //         .csrf(csrf -> csrf.disable())
    //         .sessionManagement(session ->
    //             session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    //             )
    //         .authorizeHttpRequests(auth -> auth
    //                     .requestMatchers(
    //                 "/api/v1/auth/jwt/login",
    //                             "/api/v1/auth/register"
    //                     ).permitAll()
    //             .anyRequest().authenticated()
    //         )
    //         // IMPORTANT: no formLogin
    //         // IMPORTANT: no logout
    //         .addFilterBefore(
    //             jwtAuthenticationFilter,
    //             AnonymousAuthenticationFilter.class
    //         )
    //         .exceptionHandling(ex -> ex
    //             // 401 - not logged in
    //             .authenticationEntryPoint((request, response, authException) -> {
    //                 response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    //                 response.setContentType("application/json");

    //                 response.getWriter().write("""
    //                     {
    //                     "status": 401,
    //                     "message": "(JwtAuthenticationFilter) Please login to access this resource"
    //                     }
    //                 """);
    //             })

    //             // 403 - logged in but not allowed
    //             .accessDeniedHandler((request, response, accessDeniedException) -> {
    //                 response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    //                 response.setContentType("application/json");

    //                 String apiPath = request.getRequestURI();

    //                 response.getWriter().write("""
    //                     {
    //                     "status": 403,
    //                     "message": "(JwtAuthenticationFilter) You are not authorized to access this API: %s"
    //                     }
    //                 """.formatted(apiPath));
    //             })
    //         );

    //     return http.build();
    // }
}
