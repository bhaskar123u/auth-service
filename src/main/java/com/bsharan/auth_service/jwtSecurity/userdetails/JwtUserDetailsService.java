package com.bsharan.auth_service.jwtSecurity.userdetails;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Primary;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.bsharan.auth_service.entities.User;
import com.bsharan.auth_service.repositories.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@Primary
@RequiredArgsConstructor
public class JwtUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found"));

        Set<GrantedAuthority> authorities =
                user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                    .collect(Collectors.toSet());

        return new JwtUserDetails(
                user.getId(),
                user.getEmail(),
                user.getPassword(),   // BCrypt hash
                authorities,
                user.isEnabled()
        ); 
        // this object becomes Authentication.getPrincipal(), AuthenticationManager wraps this spring security set authentication.principal = JwtUserDetails. After successful authentication, Spring erases credentials, password hash is no longer used after login
        /*
        Authentication
        ├── principal   → JwtUserDetails
        ├── credentials → null (after auth)
        ├── authorities → same as in JwtUserDetails
        ├── authenticated → true

        In your JWT flow: Authentication lives only for the duration of the request (ThreadLocal), then is discarded. No HttpSession, no server-side memory growth. Everything we need is in SecurityContextHolder.getContext().getAuthentication()
        */
    }
}

