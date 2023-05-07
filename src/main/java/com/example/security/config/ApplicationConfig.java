package com.example.security.config;

import com.example.security.entity.Role;
import com.example.security.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//at the startup spring will go to this class and inject all the beans in it
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    //This class contains all config for the app and its beans
    //All beans must be public

    private final UserRepository userRepository;

    //to indicate that this method is a bean
    @Bean
    public UserDetailsService userDetailsService(){
        //fetch user from db
        return username -> userRepository.findBySSN(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    // the data access object that is responsible to fetch user details and encode password and so on
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        //First: we need to tell the auth provider which user details service to use in order to fetch info about our user
        //because --> we might have multiple implementation of the userDetails, one getting info from db, another one on different profile such as in memory
        authProvider.setUserDetailsService(userDetailsService());
        //Second: we need to provide which password encoder we are using within our app, if we are using specific one you need to precise this one
        //because --> when we want to auth a user we need to know which password encoder to be able to decode a password using the correct algorithm
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    //the one responsible to manage the authentication, has many methods that help to auth a user by their username and password
                                                        //config: will hold the info about the auth manager 
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();

    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
