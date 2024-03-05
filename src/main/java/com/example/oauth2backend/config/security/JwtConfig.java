package com.example.oauth2backend.config.security;

import com.example.oauth2backend.oauth.token.AuthTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {
    @Value("${jwt.secret}")
    private String secret;

    @Bean
    protected AuthTokenProvider jwtProvider() {
        return new AuthTokenProvider(secret);
    }
}
