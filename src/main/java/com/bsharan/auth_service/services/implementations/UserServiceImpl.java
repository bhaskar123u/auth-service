package com.bsharan.auth_service.services.implementations;

import java.util.UUID;

import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.bsharan.auth_service.dtos.UserDto;
import com.bsharan.auth_service.entities.User;
import com.bsharan.auth_service.enums.Provider;
import com.bsharan.auth_service.exceptions.ResourceNotFoundException;
import com.bsharan.auth_service.repositories.UserRepository;
import com.bsharan.auth_service.services.UserService;
import com.bsharan.auth_service.utils.Utils;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {

        if (userDto.getEmail() == null || userDto.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }

        if (userDto.getPassword() == null || userDto.getPassword().isBlank()) {
            throw new IllegalArgumentException("Password is required");
        }

        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

        User user = modelMapper.map(userDto, User.class);
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        user.setEnabled(true);
        user.setProvider(Provider.LOCAL);

        User savedUser = userRepository.save(user);
        return modelMapper.map(savedUser, UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() ->
                new ResourceNotFoundException("User not found"));
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    public UserDto getUserById(String userId) {
        UUID uuid = Utils.parseUUID(userId);
        User user = userRepository.findById(uuid)
            .orElseThrow(() ->
                new ResourceNotFoundException("User not found"));
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    @Transactional
    public UserDto updateUser(UserDto userDto, String userId) {

        UUID uuid = Utils.parseUUID(userId);
        User existingUser = userRepository.findById(uuid)
            .orElseThrow(() ->
                new ResourceNotFoundException("User not found"));

        if (userDto.getName() != null) {
            existingUser.setName(userDto.getName());
        }

        if (userDto.getImage() != null) {
            existingUser.setImage(userDto.getImage());
        }

        User updatedUser = userRepository.save(existingUser);
        return modelMapper.map(updatedUser, UserDto.class);
    }

    @Override
    public void deleteUser(String userId) {
        UUID uuid = Utils.parseUUID(userId);
        User user = userRepository.findById(uuid)
            .orElseThrow(() ->
                new ResourceNotFoundException("User not found"));
        userRepository.delete(user);
    }

    @Override
    public Iterable<UserDto> getAllUsers() {
        return userRepository.findAll()
            .stream()
            .map(user -> modelMapper.map(user, UserDto.class))
            .toList();
    }
}

