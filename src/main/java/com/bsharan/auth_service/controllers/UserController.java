package com.bsharan.auth_service.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bsharan.auth_service.dtos.UserDto;
import com.bsharan.auth_service.services.UserService;

import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserService userService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Iterable<UserDto>> getAllUsers() {
        return ResponseEntity.status(HttpStatus.OK).body(userService.getAllUsers());
    }

    @GetMapping("/email/{emailId}")
    @PreAuthorize("""
        hasRole('ADMIN') or
        #emailId == authentication.name
    """)
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable String emailId) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.getUserByEmail(emailId));
    }

    @GetMapping("/id/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDto> getUserById(@PathVariable String userId) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.getUserById(userId));
    }

    @DeleteMapping("/{userId}")
    @PreAuthorize("""
    hasRole('ADMIN') or
    (hasRole('USER') and @userSecurity.isOwner(#userId))
    """)
    public void deleteUserById(@PathVariable String userId) {
        userService.deleteUser(userId);
    }

    @PutMapping("/{userId}")
    @PreAuthorize("""
    hasRole('ADMIN') or
    (hasRole('USER') and @userSecurity.isOwner(#userId))
    """)
    public ResponseEntity<UserDto> updateUserById(@RequestBody UserDto userDto, @PathVariable String userId) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.updateUser(userDto, userId));
    }
}
