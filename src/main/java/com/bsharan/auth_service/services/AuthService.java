package com.bsharan.auth_service.services;

import com.bsharan.auth_service.dtos.UserDto;

public interface AuthService {
    UserDto registerUser(UserDto userDto);
}
