package com.example.oauth2backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class Oauth2BackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2BackendApplication.class, args);
    }

}
