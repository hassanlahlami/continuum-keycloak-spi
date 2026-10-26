package com.continuum.keycloak.mapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.IDToken;

class TenantClaimMapperTest {

    private final TenantClaimMapper mapper = new TenantClaimMapper();

    private IDToken map(UserModel user) {
        UserSessionModel session = mock(UserSessionModel.class);
        when(session.getUser()).thenReturn(user);
        IDToken token = new IDToken();
        mapper.setClaim(token, null, session, null, null);
        return token;
    }

    @Test
    void copiesPlatformAttributesIntoClaims() {
        UserModel user = mock(UserModel.class);
        when(user.getFirstAttribute("tenant_id")).thenReturn("t-1");
        when(user.getFirstAttribute("continuum_user_id")).thenReturn("u-1");
        when(user.getFirstAttribute("authz_version")).thenReturn("7");

        IDToken token = map(user);

        assertEquals("t-1", token.getOtherClaims().get("tenant_id"));
        assertEquals("u-1", token.getOtherClaims().get("continuum_user_id"));
        assertEquals("7", token.getOtherClaims().get("authz_version"));
    }

    @Test
    void omitsClaimsWhenAttributesMissingOrBlank() {
        UserModel user = mock(UserModel.class);
        when(user.getFirstAttribute("tenant_id")).thenReturn(" ");

        IDToken token = map(user);

        assertFalse(token.getOtherClaims().containsKey("tenant_id"));
        assertFalse(token.getOtherClaims().containsKey("continuum_user_id"));
    }

    @Test
    void registeredUnderStableId() {
        assertEquals("continuum-tenant-claim-mapper", mapper.getId());
    }
}
