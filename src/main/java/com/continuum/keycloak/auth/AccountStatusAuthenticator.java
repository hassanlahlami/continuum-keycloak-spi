package com.continuum.keycloak.auth;

import java.time.Duration;
import java.util.UUID;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Post-credentials step (§4.5.2): asks the backend whether the account may open a session
 * (active assignment, tenant not suspended). Fail-closed: a missing attribute, a backend
 * error/timeout or any non-conforming answer denies the login. Keycloak holds no business logic.
 */
public class AccountStatusAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(AccountStatusAuthenticator.class);

    private final ClientFactory clientFactory;

    @FunctionalInterface
    public interface ClientFactory {
        AccountStatusClient create(AuthenticationFlowContext context);
    }

    public AccountStatusAuthenticator(ClientFactory clientFactory) {
        this.clientFactory = clientFactory;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String userId = user == null ? null : user.getFirstAttribute("continuum_user_id");
        String tenantId = user == null ? null : user.getFirstAttribute("tenant_id");
        if (!isUuid(userId) || !isUuid(tenantId)) {
            deny(context, "MISSING_ATTRIBUTES");
            return;
        }
        try {
            AccountStatusClient.Decision d = clientFactory.create(context).getStatus(userId, tenantId);
            if (d.allowed()) {
                context.success();
            } else {
                deny(context, d.reason() == null ? "DENIED" : d.reason());
            }
        } catch (Exception e) {
            LOG.warn("Account status check failed, denying login (fail-closed)", e);
            deny(context, "BACKEND_UNAVAILABLE");
        }
    }

    private static void deny(AuthenticationFlowContext context, String reason) {
        LOG.infof("Login denied: %s", reason);
        context.failure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED);
    }

    private static boolean isUuid(String s) {
        if (s == null) {
            return false;
        }
        try {
            UUID.fromString(s);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    static Duration timeoutOf(String ms) {
        try {
            return Duration.ofMillis(Long.parseLong(ms));
        } catch (NumberFormatException e) {
            return Duration.ofSeconds(3);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // no form to process
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // none
    }

    @Override
    public void close() {
        // stateless
    }
}
