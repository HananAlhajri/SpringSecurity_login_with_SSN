package com.example.security.auth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;


    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        //request: our request from user, we can extract data from the request
        //response: then we can provide a response to that request, provide new data such as header for example
        //filterChain: is the chain of responsibility design patters contains list of other filters that we need to execute
            //when we call filterChain.doInternalFilter it will call the next filter with the chain

        String authHeader = request.getHeader("Authorization");

        //Now check the jwtToken whether its null OR does not start with Bearer then SPACE, make an early return
        //IMPORTANT NOTE: the authHeader MUST start with the word Bearer then SPACE
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }

        //this is the header that contains the JWT token or the bearer token, it is called by these two names
        //when we make a call we need to pass the JWT auth Token within the header called authorization
        //Now since we checked the authHeader, and it did not return, we should extract the token
                                        //why position 7? count Bearer with the SPACE, it is 7
        String jwtToken = authHeader.substring(7);

        //Now call UserDetailsService to check is the user exist in our database or not?
             //but we need to call JwtService first to extract the username (or email in our case)
        String userSSN = jwtService.extractUsername(jwtToken);//to do extract the userEmail from JWT token , I need a class the can manipulate this Jwt Token
                                //check if user already auth , no need to auth again so do not enter this if
        if (userSSN != null && SecurityContextHolder.getContext().getAuthentication() == null){
            //check if the user is in the db                    in this case its email
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userSSN);
            if(jwtService.isTokenValid(jwtToken, userDetails)){
                //update security context and send the request to our dispatcher
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // if we have credentials we can pass it here
                        userDetails.getAuthorities()
                );
                //give it some more details
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                //final step update security context holder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            //ALWAYS call the filterChain.doFilter WE ALWAYS NEED to pass the hand to the next filters to be executed
            filterChain.doFilter(request, response);

        }


    }
}
