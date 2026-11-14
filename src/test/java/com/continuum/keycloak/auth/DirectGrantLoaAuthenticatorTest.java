package com.continuum.keycloak.auth;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel.ExecutionStatus;

class DirectGrantLoaAuthenticatorTest {

    AuthenticationFlowContext ctx = mock(AuthenticationFlowContext.class);
    AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
    RealmModel realm = mock(RealmModel.class);
    AuthenticatorConfigModel cfg = new AuthenticatorConfigModel();
    Map<String, ExecutionStatus> statuses = new HashMap<>();
    DirectGrantLoaAuthenticator auth = new DirectGrantLoaAuthenticator(true);

    @BeforeEach
    void setUp() {
        cfg.setConfig(new HashMap<>(Map.of(DirectGrantLoaAuthenticatorFactory.LOA, "2")));
        when(ctx.getAuthenticatorConfig()).thenReturn(cfg);
        when(ctx.getAuthenticationSession()).thenReturn(authSession);
        when(ctx.getSession()).thenReturn(mock(KeycloakSession.class));
        when(ctx.getRealm()).thenReturn(realm);
        when(ctx.getUser()).thenReturn(mock(UserModel.class));
        when(authSession.getExecutionStatus()).thenReturn(statuses);
        execution("e-user", "direct-grant-validate-username", ExecutionStatus.SUCCESS);
        execution("e-pwd", "direct-grant-validate-password", ExecutionStatus.SUCCESS);
    }

    private void execution(String id, String providerId, ExecutionStatus status) {
        AuthenticationExecutionModel m = new AuthenticationExecutionModel();
        m.setId(id);
        m.setAuthenticator(providerId);
        when(realm.getAuthenticationExecutionById(id)).thenReturn(m);
        statuses.put(id, status);
    }

    private void verifyLoaRaisedTo(String level) {
        verify(authSession).setAuthNote(Constants.LEVEL_OF_AUTHENTICATION, level);
        verify(ctx).success();
    }

    private void verifyLoaUntouched() {
        verify(authSession, never()).setAuthNote(eq(Constants.LEVEL_OF_AUTHENTICATION), anyString());
        verify(ctx).success();
    }

    @Test
    void otpSucceededRaisesLoa() {
        execution("e-otp", "direct-grant-validate-otp", ExecutionStatus.SUCCESS);
        auth.authenticate(ctx);
        verifyLoaRaisedTo("2");
    }

    @Test
    void otpSkippedKeepsLoa() {
        execution("e-otp", "direct-grant-validate-otp", ExecutionStatus.SKIPPED);
        auth.authenticate(ctx);
        verifyLoaUntouched();
    }

    @Test
    void otpNeverRunKeepsLoa() {
        auth.authenticate(ctx);
        verifyLoaUntouched();
    }

    @Test
    void conditionTrueIsNotEvidence() {
        execution("e-cond", "conditional-user-configured", ExecutionStatus.EVALUATED_TRUE);
        auth.authenticate(ctx);
        verifyLoaUntouched();
    }

    @Test
    void allRequiredAuthenticatorsMustSucceed() {
        cfg.getConfig().put(DirectGrantLoaAuthenticatorFactory.REQUIRED_AUTHENTICATORS,
                "direct-grant-validate-password, direct-grant-validate-otp");
        execution("e-otp", "direct-grant-validate-otp", ExecutionStatus.SUCCESS);
        auth.authenticate(ctx);
        verifyLoaRaisedTo("2");
    }

    @Test
    void oneMissingRequiredAuthenticatorKeepsLoa() {
        cfg.getConfig().put(DirectGrantLoaAuthenticatorFactory.REQUIRED_AUTHENTICATORS,
                "direct-grant-validate-otp,webauthn-authenticator");
        execution("e-otp", "direct-grant-validate-otp", ExecutionStatus.SUCCESS);
        auth.authenticate(ctx);
        verifyLoaUntouched();
    }

    @Test
    void disabledNeverRaisesLoa() {
        execution("e-otp", "direct-grant-validate-otp", ExecutionStatus.SUCCESS);
        new DirectGrantLoaAuthenticator(false).authenticate(ctx);
        verifyLoaUntouched();
    }

    @Test
    void factoryIsDisabledByDefault() {
        DirectGrantLoaAuthenticatorFactory factory = new DirectGrantLoaAuthenticatorFactory();
        factory.init(null);
        execution("e-otp", "direct-grant-validate-otp", ExecutionStatus.SUCCESS);
        factory.create(mock(KeycloakSession.class)).authenticate(ctx);
        verifyLoaUntouched();
    }

    @Test
    void neverLowersAHigherLoa() {
        execution("e-otp", "direct-grant-validate-otp", ExecutionStatus.SUCCESS);
        when(authSession.getAuthNote(Constants.LEVEL_OF_AUTHENTICATION)).thenReturn("3");
        auth.authenticate(ctx);
        verifyLoaUntouched();
    }

    @Test
    void missingOrInvalidLoaConfigKeepsLoa() {
        execution("e-otp", "direct-grant-validate-otp", ExecutionStatus.SUCCESS);
        cfg.getConfig().put(DirectGrantLoaAuthenticatorFactory.LOA, "abc");
        auth.authenticate(ctx);
        cfg.getConfig().put(DirectGrantLoaAuthenticatorFactory.LOA, "0");
        auth.authenticate(ctx);
        when(ctx.getAuthenticatorConfig()).thenReturn(null);
        auth.authenticate(ctx);
        verify(authSession, never()).setAuthNote(eq(Constants.LEVEL_OF_AUTHENTICATION), anyString());
    }

    @Test
    void noUserKeepsLoa() {
        execution("e-otp", "direct-grant-validate-otp", ExecutionStatus.SUCCESS);
        when(ctx.getUser()).thenReturn(null);
        auth.authenticate(ctx);
        verifyLoaUntouched();
    }

    @Test
    void unknownExecutionIdIsIgnored() {
        statuses.put("e-gone", ExecutionStatus.SUCCESS);
        auth.authenticate(ctx);
        verifyLoaUntouched();
    }
}
