package com.example.oauth2backend.oauth.entity;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum RoleType {
    USER("ROLE_USER", "일반 사용자 권한"),
    ADMIN("ROLE_ADMIN", "관리자 권한"),
    GUEST("ROLE_GUEST", "게스트 권한");

    private final String code;
    private final String displayName;

    private static final Map<String, RoleType> CODE_TO_ROLE_TYPE;

    static {
        CODE_TO_ROLE_TYPE = Arrays.stream(RoleType.values())
                .collect(Collectors.toMap(RoleType::getCode, Function.identity()));
    }

    public static RoleType of(final String code) {
        return CODE_TO_ROLE_TYPE.getOrDefault(code, GUEST);
    }
}
