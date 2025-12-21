package com.bsharan.auth_service.components;

import java.util.UUID;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.bsharan.auth_service.repositories.UserRepository;

import lombok.RequiredArgsConstructor;

@Component("userSecurity")
@RequiredArgsConstructor
public class UserSecurity {

    private final UserRepository userRepository;

    public boolean isOwner(String userId) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getName() == null) {
            return false;
        }

        String email = auth.getName(); // principal = email (LOCKED)

        return userRepository
                .findByEmail(email)
                .map(user -> user.getId().equals(UUID.fromString(userId)))
                .orElse(false);
    }
}
