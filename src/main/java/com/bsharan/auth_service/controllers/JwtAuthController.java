package com.bsharan.auth_service.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bsharan.auth_service.dtos.JwtLoginRequest;
import com.bsharan.auth_service.dtos.JwtLoginResponse;
import com.bsharan.auth_service.jwtSecurity.jwt.JwtTokenService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth/jwt")
public class JwtAuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;

    @PostMapping("/login")
    public ResponseEntity<JwtLoginResponse> jwtLogin(
            @RequestBody JwtLoginRequest request) {

        // creates unauthenticated token and passed to authenticationManager, authenticationManager passes it to applicable provider
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
            );
        /*
            A carrier object is created with following details
        
            authenticated = false
            principal = email
            credentials = password
            
            internally ProviderManager.authenticate() is invoked as
            for (AuthenticationProvider provider : providers) {
                if (provider.supports(authentication.getClass())) 
                {
                    return provider.authenticate(authentication);
                }                
            }
        
            Each AuthenticationProvider implements: boolean supports(Class<?> authentication)
            for UsernamePasswordAuthenticationToken -> DaoAuthenticationProvider
        
            UsernamePasswordAuthenticationToken (unauthenticated)
                    ↓
            DaoAuthenticationProvider (will use JwtUserDetailsService)
                    ↓
            UsernamePasswordAuthenticationToken (authenticated)
        */

        
        JwtLoginResponse response = jwtTokenService.createJwtToken(authentication);

        return ResponseEntity.ok(response);
    }
}
