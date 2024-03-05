package com.example.oauth2backend.oauth.entity;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class RoleTypeTest {
    @DisplayName("없는 사용자 권한에 따른 기본값 반환")
    @Test
    void givenNone_whenCallOf_thenReturnGuest() {
        assertThat(RoleType.of(null)).isEqualTo(RoleType.GUEST);
    }

    @DisplayName("목록에 존재하는 사용자 권한에 맞게 반환")
    @Test
    void givenStringRoleType_whenCallOf_thenReturnRoleTypeAsEnum() {
        for (RoleType roleType : RoleType.values()) {
            String code = roleType.getCode();
            assertThat(RoleType.of(code)).isEqualTo(roleType);
        }
    }
}