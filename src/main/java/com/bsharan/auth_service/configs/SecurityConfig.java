package com.bsharan.auth_service.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            // APIs → disable CSRF for now
            .csrf(csrf -> csrf.disable())
            // Authorization rules (used AFTER login)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/v1/auth/register", "/login").permitAll()
                .requestMatchers("/api/v1/users").hasRole("ADMIN")
                .requestMatchers("/api/v1/users/id/**").hasRole("ADMIN")
                .requestMatchers("/api/v1/users/email/**").authenticated()
                .requestMatchers("/api/v1/users/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginProcessingUrl("/login")        // endpoint
                .usernameParameter("email")          // read from request
                .passwordParameter("password")
                .successHandler((req, res, auth) -> {
                    res.setStatus(200);
                })
                .failureHandler((req, res, ex) -> {
                    res.sendError(401, "Invalid email or password");
                })
            )
            // Logout clears HttpSession(SecurityContext) + Remove session cookie
            .logout(logout -> logout
                .logoutUrl("/logout")              // API endpoint
                .invalidateHttpSession(true)       // Destroy HttpSession
                .clearAuthentication(true)         // Clear SecurityContext
                .deleteCookies("JSESSIONID")       // Remove session cookie
                .logoutSuccessHandler((request, response, authentication) -> {
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType("application/json");
                    response.getWriter().write("""
                        {
                        "status": 200,
                        "message": "Logged out successfully"
                        }
                    """);
                })
            )
            .exceptionHandling(ex -> ex
                // 401 - not logged in
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");

                    response.getWriter().write("""
                        {
                        "status": 401,
                        "message": "Please login to access this resource"
                        }
                    """);
                })

                // 403 - logged in but not allowed
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType("application/json");

                    String apiPath = request.getRequestURI();

                    response.getWriter().write("""
                        {
                        "status": 403,
                        "message": "You are not authorized to access this API: %s"
                        }
                    """.formatted(apiPath));
                })
            );

        return http.build();
    }
}
