package com.continuum.keycloak.auth;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.util.AcrStore;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel.ExecutionStatus;

/**
 * Sets the level of authentication (LoA) of a direct-grant login from evidence, never from configuration alone.
 *
 * <p>The built-in "Condition - Level of Authentication" cannot drive a direct grant: the requested LoA is only
 * set by the authorization endpoint, so every LoA &gt;= 2 condition evaluates false at the token endpoint and the
 * token gets {@code acr=1}. This authenticator, placed last (REQUIRED) in the direct-grant flow, raises the LoA to
 * the configured level only when every configured authenticator (default: the direct-grant OTP check) finished
 * with SUCCESS in this very authentication session. Otherwise it leaves the LoA unchanged, so a drifted flow can
 * only under-state the {@code acr}, never over-state it. It never fails the login.
 *
 * <p>Shelved (ADR 0014, decision 2026-11-14: no {@code acr >= 2} from a REST login): inert unless the server is
 * started with {@code --spi-authenticator--continuum-direct-grant-loa--raise-loa=true}; when disabled it only calls
 * {@code success()} and never touches the LoA, even if wired into a flow.
 */
public class DirectGrantLoaAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(DirectGrantLoaAuthenticator.class);

    private final boolean enabled;

    public DirectGrantLoaAuthenticator(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (!enabled) {
            LOG.debugf("%s: disabled (SPI option raise-loa=false), LoA left unchanged", DirectGrantLoaAuthenticatorFactory.PROVIDER_ID);
            context.success();
            return;
        }
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        Integer loa = configuredLoa(cfg);
        Set<String> required = requiredAuthenticators(cfg);
        if (loa == null || required.isEmpty()) {
            LOG.warnf("%s: missing or invalid config, LoA left unchanged", DirectGrantLoaAuthenticatorFactory.PROVIDER_ID);
        } else if (context.getUser() != null
                && allSucceeded(context.getRealm(), context.getAuthenticationSession(), required)) {
            raise(context.getSession(), context.getAuthenticationSession(), loa);
        }
        context.success();
    }

    private static void raise(KeycloakSession session, AuthenticationSessionModel authSession, int loa) {
        AcrStore store = new AcrStore(session, authSession);
        if (store.getLevelOfAuthenticationFromCurrentAuthentication() < loa) {
            store.setLevelAuthenticatedToCurrentRequest(loa);
        }
    }

    private static boolean allSucceeded(RealmModel realm, AuthenticationSessionModel authSession, Set<String> required) {
        Set<String> succeeded = authSession.getExecutionStatus().entrySet().stream()
                .filter(e -> e.getValue() == ExecutionStatus.SUCCESS)
                .map(Map.Entry::getKey)
                .map(realm::getAuthenticationExecutionById)
                .filter(Objects::nonNull)
                .map(AuthenticationExecutionModel::getAuthenticator)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        return succeeded.containsAll(required);
    }

    static Integer configuredLoa(AuthenticatorConfigModel cfg) {
        String raw = cfg == null || cfg.getConfig() == null ? null
                : cfg.getConfig().get(DirectGrantLoaAuthenticatorFactory.LOA);
        try {
            int loa = Integer.parseInt(raw == null ? "" : raw.trim());
            return loa >= 1 ? loa : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static Set<String> requiredAuthenticators(AuthenticatorConfigModel cfg) {
        String raw = cfg == null || cfg.getConfig() == null ? null
                : cfg.getConfig().get(DirectGrantLoaAuthenticatorFactory.REQUIRED_AUTHENTICATORS);
        if (raw == null || raw.isBlank()) {
            raw = DirectGrantLoaAuthenticatorFactory.DEFAULT_REQUIRED_AUTHENTICATORS;
        }
        return Arrays.stream(raw.split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
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
    }

    @Override
    public void close() {
    }
}
