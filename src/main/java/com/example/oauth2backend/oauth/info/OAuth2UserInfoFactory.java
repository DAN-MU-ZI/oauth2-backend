package com.example.oauth2backend.oauth.info;

import com.example.oauth2backend.oauth.entity.ProviderType;
import com.example.oauth2backend.oauth.info.impl.GoogleOAuth2UserInfo;
import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(final ProviderType providerType,
                                                   final Map<String, Object> attributes) {
        return switch (providerType) {
            case GOOGLE -> new GoogleOAuth2UserInfo(attributes);
            default -> throw new IllegalArgumentException("Invalid Provider Type.");
        };
    }
}
