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
        String loggedInEmail = auth.getName();

        return userRepository.findById(UUID.fromString(userId))
            .map(user -> user.getEmail().equals(loggedInEmail))
            .orElse(false);
    }
}

