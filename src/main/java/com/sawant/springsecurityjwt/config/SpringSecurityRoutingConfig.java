package com.sawant.springsecurityjwt.config;

import com.sawant.springsecurityjwt.model.AuthenticationRequest;
import com.sawant.springsecurityjwt.model.AuthenticationResponse;
import com.sawant.springsecurityjwt.service.MyUserDetailsService;
import com.sawant.springsecurityjwt.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import static org.springframework.web.reactive.function.BodyInserters.fromValue;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RequestPredicates.POST;

@Slf4j
@Configuration
public class SpringSecurityRoutingConfig {


    @Value("${welcome.url}")
    private String welcomeUrl;

    @Value("${authenticate.url}")
    private String authenticateUrl;

    @Autowired
    private MyUserDetailsService userdetailService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Bean
    public RouterFunction<ServerResponse> welcome(){
        return RouterFunctions.route(GET(welcomeUrl), request ->{
            return ServerResponse.ok().contentType(MediaType.TEXT_PLAIN).body(fromValue("Welcome"));
        });
    }

    @Bean
    public RouterFunction<ServerResponse> createAuthenticationToken(){
        return RouterFunctions.route(POST(authenticateUrl), request ->{
            AuthenticationRequest authenticationRequest=request.bodyToMono(AuthenticationRequest.class).block();
            try {
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
            }catch (BadCredentialsException e){
               System.out.println("bad credentials");
            }
            final UserDetails userDetails=userdetailService.loadUserByUsername(authenticationRequest.getUsername());
            final String jwt=jwtUtil.generateToken(userDetails);

            return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).body(fromValue(new AuthenticationResponse(jwt)));
        });
    }
}
