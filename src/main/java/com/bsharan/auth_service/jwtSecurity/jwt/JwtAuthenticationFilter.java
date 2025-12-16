package com.bsharan.auth_service.jwtSecurity.jwt;

import java.io.IOException;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bsharan.auth_service.jwtSecurity.userdetails.JwtUserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtPublicKeyProvider jwtPublicKeyProvider;

    @Value("${jwt.issuer}")
    private String jwtIssuer;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {
        SecurityContextHolder.clearContext();

        String authHeader = request.getHeader("Authorization");
        System.out.println("AUTH HEADER = " + authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authHeader.substring(7);

        try {
            Claims claims = parseAndValidate(jwt);

            JwtUserDetails principal = buildPrincipal(claims);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    principal,
                    null,
                    principal.getAuthorities());

            SecurityContextHolder.getContext()
                    .setAuthentication(authentication);

        } catch (Exception ex) {
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        filterChain.doFilter(request, response);
    }
    
    private Claims parseAndValidate(String jwt) {

        PublicKey publicKey = jwtPublicKeyProvider.getPublicKey();

        Claims claims = Jwts.parserBuilder()
                .requireIssuer(jwtIssuer)
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(jwt)
                .getBody();

        return claims;
    }

    private JwtUserDetails buildPrincipal(Claims claims) {

        UUID userId = UUID.fromString(claims.getSubject());
        String email = claims.get("email", String.class);

        @SuppressWarnings("unchecked")
        List<String> roles = claims.get("roles", List.class);

        Set<GrantedAuthority> authorities =
                roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());

        return new JwtUserDetails(
                userId,
                email,
                null, // password not needed
                authorities,
                true
        );
    }
}

