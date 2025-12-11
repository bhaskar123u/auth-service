package com.bsharan.auth_service.services.implementations;

import org.springframework.stereotype.Service;

import com.bsharan.auth_service.dtos.UserDto;
import com.bsharan.auth_service.services.AuthService;
import com.bsharan.auth_service.services.UserService;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserService userService;

    @Override
    public UserDto registerUser(UserDto userDto) {
        // perform other tasks for registration
        return userService.createUser(userDto);
    }
    
}
