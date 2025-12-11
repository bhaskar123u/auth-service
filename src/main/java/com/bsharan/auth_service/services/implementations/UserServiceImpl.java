package com.bsharan.auth_service.services.implementations;

import java.util.UUID;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import com.bsharan.auth_service.dtos.UserDto;
import com.bsharan.auth_service.entities.User;
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

    @Override
    @Transactional
    public UserDto createUser(UserDto userDto) {

        if (userDto.getEmail().isEmpty())
            throw new IllegalArgumentException("Email is required");

        if (userRepository.existsByEmail(userDto.getEmail()))
            throw new IllegalArgumentException("Email already exists");

        User user = modelMapper.map(userDto, User.class);
        User savedUser = userRepository.save(user);

        return modelMapper.map(savedUser, UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {
        User user = userRepository
                .findByEmail(email)
                .orElseThrow(() -> {
            return new ResourceNotFoundException("user with given emailId is not found");
        });

        return modelMapper.map(user, UserDto.class);
    }
    
    @Override
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uuID = Utils.parseUUID(userId);
        User existingUser = userRepository
                .findById(uuID)
                .orElseThrow(() -> {
            return new ResourceNotFoundException("user with given emailId is not found");
                });
        
        if (userDto.getName() != null)
            existingUser.setName(userDto.getName());
        if (userDto.getProvider() != null)
            existingUser.setProvider(userDto.getProvider());
        if (userDto.getImage() != null)
            existingUser.setImage(userDto.getImage());
        if (userDto.getPassword() != null)
            existingUser.setPassword(userDto.getPassword());
        existingUser.setEnabled(userDto.isEnabled());

        User updatedUser = userRepository.save(existingUser);
        return modelMapper.map(updatedUser, UserDto.class);
    }

    @Override
    public void deleteUser(String userId) {
        UUID uuID = Utils.parseUUID(userId);
        User user = userRepository.findById(uuID).orElseThrow(() -> {
            return new ResourceNotFoundException("user with given userId is not found");
        });
        userRepository.delete(user);
    }

    @Override
    public UserDto getUserById(String userId) {
        User user = userRepository.findById(Utils.parseUUID(userId)).orElseThrow(()->{
            return new ResourceNotFoundException("user with given userId is not found");
        });
        return modelMapper.map(user, UserDto.class);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return userRepository
                .findAll()
                .stream()
                .map(user -> modelMapper.map(user, UserDto.class))
                .toList();
    }
    
}
