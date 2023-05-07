package com.example.security.auth.service;

import com.example.security.auth.dto.AuthenticationRequest;
import com.example.security.auth.AuthenticationResponse;
import com.example.security.auth.dto.RegisterRequest;
import com.example.security.entity.User;
import com.example.security.repo.UserRepository;
import com.example.security.service.IUAMService;
import com.example.security.auth.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService implements IUAMService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public AuthenticationResponse register(RegisterRequest request) {
        //create user , save to db , return the generated token out of it

        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .SSN(request.getSSN())
                .password(passwordEncoder.encode(request.getPassword())) //to encode the password before saving it to db
                .role(request.getRole())
                .build();

        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    //authentication manager BEAN has method called authenticate that allows us to authenticate a user by their username and password
    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getSSN(),
                        request.getPassword()
                )
        ); // if the username or pass incorrect , and exception will be thrown

        //if we reached here , this means that the username and password are correct
        //now, we just need to create a token for it to send it back
        var user = userRepository.findBySSN(request.getSSN()).orElseThrow(); //YOU NEED TO throw the correct exception and handle it
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();

    }
}
