package com.continuum.keycloak.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.UserModel;

class AccountStatusAuthenticatorTest {

    static final String UID = "11111111-1111-1111-1111-111111111111";
    static final String TID = "22222222-2222-2222-2222-222222222222";

    AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
    UserModel user = mock(UserModel.class);
    AccountStatusClient client = mock(AccountStatusClient.class);
    AccountStatusAuthenticator auth = new AccountStatusAuthenticator(c -> client);

    @BeforeEach
    void setUp() {
        when(ctx.getUser()).thenReturn(user);
        when(user.getFirstAttribute("continuum_user_id")).thenReturn(UID);
        when(user.getFirstAttribute("tenant_id")).thenReturn(TID);
    }

    @Test
    void allowedSucceeds() throws Exception {
        when(client.getStatus(UID, TID)).thenReturn(new AccountStatusClient.Decision(true, null));
        auth.authenticate(ctx);
        verify(ctx).success();
    }

    @Test
    void deniedFails() throws Exception {
        when(client.getStatus(UID, TID)).thenReturn(new AccountStatusClient.Decision(false, "TENANT_SUSPENDED"));
        auth.authenticate(ctx);
        verify(ctx).failure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
        verify(ctx, never()).success();
    }

    @Test
    void backendErrorFailsClosed() throws Exception {
        when(client.getStatus(UID, TID)).thenThrow(new IllegalStateException("account status HTTP 503"));
        auth.authenticate(ctx);
        verify(ctx).failure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
        verify(ctx, never()).success();
    }

    @Test
    void missingAttributeFailsClosedWithoutCall() throws Exception {
        when(user.getFirstAttribute("tenant_id")).thenReturn(null);
        auth.authenticate(ctx);
        verify(ctx).failure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
        verify(client, never()).getStatus(any(), any());
    }

    @Test
    void malformedUuidFailsClosed() throws Exception {
        when(user.getFirstAttribute("continuum_user_id")).thenReturn("not-a-uuid");
        auth.authenticate(ctx);
        verify(ctx).failure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
        verify(client, never()).getStatus(any(), any());
    }
}
