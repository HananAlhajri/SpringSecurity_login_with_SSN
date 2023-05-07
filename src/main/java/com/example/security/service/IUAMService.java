package com.example.security.service;

import com.example.security.auth.dto.AuthenticationRequest;
import com.example.security.auth.AuthenticationResponse;
import com.example.security.auth.dto.RegisterRequest;

public interface IUAMService {
    AuthenticationResponse register(RegisterRequest request);
    AuthenticationResponse authenticate(AuthenticationRequest request);

}
