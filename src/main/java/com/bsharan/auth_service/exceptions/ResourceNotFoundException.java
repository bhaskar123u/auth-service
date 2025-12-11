package com.bsharan.auth_service.exceptions;

import com.bsharan.auth_service.utils.Constants;

public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
    
    public ResourceNotFoundException() {
        super(Constants.RESOURCE_NOT_FOUND);
    } 
}
