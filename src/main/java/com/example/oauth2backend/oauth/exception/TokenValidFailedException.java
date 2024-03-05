package com.example.oauth2backend.oauth.exception;

public class TokenValidFailedException extends RuntimeException {
    public TokenValidFailedException() {
        super("Filed to generate Token.");
    }
}
