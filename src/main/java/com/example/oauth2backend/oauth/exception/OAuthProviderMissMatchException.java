package com.example.oauth2backend.oauth.exception;

public class OAuthProviderMissMatchException extends RuntimeException {
    public OAuthProviderMissMatchException(final String message) {
        super(message);
    }
}
