package com.continuum.keycloak.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.common.ClientConnection;

class AdminNetworkAuthenticatorTest {

    AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
    ClientConnection conn = mock(ClientConnection.class);
    UserModel user = mock(UserModel.class);
    SubjectCredentialManager creds = mock(SubjectCredentialManager.class);
    AuthenticatorConfigModel cfg = new AuthenticatorConfigModel();
    AdminNetworkAuthenticator auth = new AdminNetworkAuthenticator();

    @BeforeEach
    void setUp() {
        cfg.setConfig(Map.of(AdminNetworkAuthenticatorFactory.ALLOWED_CIDRS, "10.20.0.0/16, 192.168.1.5"));
        when(ctx.getAuthenticatorConfig()).thenReturn(cfg);
        when(ctx.getConnection()).thenReturn(conn);
        when(ctx.getUser()).thenReturn(user);
        when(user.credentialManager()).thenReturn(creds);
        when(creds.getStoredCredentialsByTypeStream(anyString())).thenAnswer(i -> Stream.<CredentialModel>empty());
    }

    private void withKey() {
        when(creds.getStoredCredentialsByTypeStream("webauthn")).thenAnswer(i -> Stream.of(new CredentialModel()));
    }

    @Test
    void allowedNetworkWithKeySucceeds() {
        when(conn.getRemoteAddr()).thenReturn("10.20.3.4");
        withKey();
        auth.authenticate(ctx);
        verify(ctx).success();
    }

    @Test
    void outsideNetworkDenied() {
        when(conn.getRemoteAddr()).thenReturn("10.21.0.1");
        withKey();
        auth.authenticate(ctx);
        verify(ctx).failure(AuthenticationFlowError.ACCESS_DENIED);
        verify(ctx, never()).success();
    }

    @Test
    void noKeyDenied() {
        when(conn.getRemoteAddr()).thenReturn("192.168.1.5");
        auth.authenticate(ctx);
        verify(ctx).failure(AuthenticationFlowError.ACCESS_DENIED);
    }

    @Test
    void keyCheckCanBeDisabled() {
        cfg.setConfig(Map.of(AdminNetworkAuthenticatorFactory.ALLOWED_CIDRS, "10.0.0.0/8",
                AdminNetworkAuthenticatorFactory.REQUIRE_FIDO2, "false"));
        when(conn.getRemoteAddr()).thenReturn("10.1.1.1");
        auth.authenticate(ctx);
        verify(ctx).success();
    }

    @Test
    void emptyAllowlistDeniesEveryone() {
        cfg.setConfig(Map.of());
        when(conn.getRemoteAddr()).thenReturn("10.1.1.1");
        withKey();
        auth.authenticate(ctx);
        verify(ctx).failure(AuthenticationFlowError.ACCESS_DENIED);
    }

    @Test
    void cidrMatcherEdgeCases() {
        assertTrue(CidrMatcher.matches("10.20.255.255", "10.20.0.0/16"));
        assertTrue(CidrMatcher.matches("10.0.0.1", "10.0.0.0/31"));
        assertFalse(CidrMatcher.matches("10.0.0.2", "10.0.0.0/31"));
        assertTrue(CidrMatcher.matches("fd00::1", "fd00::/8"));
        assertFalse(CidrMatcher.matches("10.0.0.1", "fd00::/8"));
        assertFalse(CidrMatcher.matches("evil.example.com", "10.0.0.0/8"));
        assertFalse(CidrMatcher.matches(null, "10.0.0.0/8"));
        assertFalse(CidrMatcher.matches("10.0.0.1", "10.0.0.0/99"));
    }
}
