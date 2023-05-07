package com.example.security.config;

import com.example.security.auth.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.example.security.entity.Permission.*;
import static com.example.security.entity.Role.ADMIN;
import static com.example.security.entity.Role.MANAGER;
import static org.springframework.http.HttpMethod.*;

//The two annotations need to be together when we work with spring 3
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private static final String[] SECURED_URLs = {"/api/v1/manage-users/**", "/api/v1/management/**"};
    private static final String[] SECURED_URLs_for_admin = {"/api/v1/admin/**"};
    private static final String[] UN_SECURED_URLs = {"/api/v1/auth/**"};



    //as the app start spring security will try to look for bean of type:
     // SpringSecurityFilterChain: the bean that is responsible for configuring all the http security of our app

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                //first disable this one (SEARCH AND READ WHAT IS THIS?)
                .csrf().disable()

                //we can choose and decide the methods or urls we want to secure
        // BUT, in every app there are a white list: it means that we have some endpoints that does not need any auth or token
        // EXAMPLE: Create account -> does not need a token cause there is no token yet
                .authorizeHttpRequests()
                .requestMatchers(UN_SECURED_URLs)//white list, two stars means all the methods in that controller
                .permitAll()
                .requestMatchers(SECURED_URLs).hasAnyRole(ADMIN.name(), MANAGER.name())

                .requestMatchers(GET, SECURED_URLs).hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                .requestMatchers(POST, SECURED_URLs).hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                .requestMatchers(PUT, SECURED_URLs).hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                .requestMatchers(DELETE, SECURED_URLs).hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

//                .requestMatchers(SECURED_URLs_for_admin).hasRole(ADMIN.name())
//
//                .requestMatchers(GET, SECURED_URLs_for_admin).hasAuthority(ADMIN_READ.name())
//                .requestMatchers(POST, SECURED_URLs_for_admin).hasAuthority(ADMIN_CREATE.name())
//                .requestMatchers(PUT, SECURED_URLs_for_admin).hasAuthority(ADMIN_UPDATE.name())
//                .requestMatchers(DELETE, SECURED_URLs_for_admin).hasAuthority(ADMIN_DELETE.name())
//                .hasAnyAuthority("ADMIN", "TEACHER")
                .anyRequest()//any other request than the white list, AUTHENTICATE it
                .authenticated()
                .and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)//how we want to create our session: stateless or steteful
                .and().authenticationProvider(authenticationProvider)
                .addFilterBefore(
                        jwtAuthFilter,
                        UsernamePasswordAuthenticationFilter.class
                );// execute this filter before usernamepssowrd filter!
                return http.build();
    }

}
