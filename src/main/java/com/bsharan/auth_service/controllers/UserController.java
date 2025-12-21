package com.bsharan.auth_service.controllers;

import com.bsharan.auth_service.dtos.UserDto;
import com.bsharan.auth_service.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Iterable<UserDto>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/email/{email}")
    @PreAuthorize("""
        hasRole('ADMIN') or
        #email == authentication.name
    """)
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable String email) {
        return ResponseEntity.ok(userService.getUserByEmail(email));
    }

    @GetMapping("/id/{userId}")
    @PreAuthorize("""
        hasRole('ADMIN') or
        @userSecurity.isOwner(#userId)
    """)
    public ResponseEntity<UserDto> getUserById(@PathVariable String userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    @PutMapping("/{userId}")
    @PreAuthorize("""
        hasRole('ADMIN') or
        @userSecurity.isOwner(#userId)
    """)
    public ResponseEntity<UserDto> updateUser(
            @PathVariable String userId,
            @RequestBody UserDto userDto
    ) {
        return ResponseEntity.ok(userService.updateUser(userDto, userId));
    }

    @DeleteMapping("/{userId}")
    @PreAuthorize("""
        hasRole('ADMIN') or
        @userSecurity.isOwner(#userId)
    """)
    public ResponseEntity<Void> deleteUser(@PathVariable String userId) {
        userService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }
}
