package com.bsharan.auth_service.jwtSecurity.userdetails;

import java.util.Collection;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Getter;

@Getter
public class JwtUserDetails implements UserDetails {

    private final UUID userId;
    private final String email;
    private final String password;
    private final Set<GrantedAuthority> authorities;
    private final boolean enabled;

    public JwtUserDetails(
            UUID userId,
            String email,
            String password,
            Set<GrantedAuthority> authorities,
            boolean enabled) {

        this.userId = userId;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
        this.enabled = enabled;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return enabled;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }
}

