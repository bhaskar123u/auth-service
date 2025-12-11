package com.bsharan.auth_service.services;

import com.bsharan.auth_service.dtos.UserDto;

public interface UserService {
    UserDto createUser(UserDto userDto);

    UserDto getUserByEmail(String email);

    UserDto updateUser(UserDto userDto, String userId);

    void deleteUser(String userId);

    UserDto getUserById(String userId);

    Iterable<UserDto> getAllUsers();
}
