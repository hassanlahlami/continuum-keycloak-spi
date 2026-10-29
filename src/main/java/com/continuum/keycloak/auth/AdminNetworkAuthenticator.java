package com.continuum.keycloak.auth;

import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Admin-console gate (§4.5.2): the login must come from the administration network (CIDR
 * allowlist) and the user must own a FIDO2/WebAuthn credential. Fail-closed: empty allowlist,
 * unknown address or no security key denies the login. The second-factor ceremony itself is
 * handled by the WebAuthn step of the same flow.
 */
public class AdminNetworkAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(AdminNetworkAuthenticator.class);

    static final List<String> WEBAUTHN_CREDENTIAL_TYPES = List.of("webauthn", "webauthn-passwordless");

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        var config = context.getAuthenticatorConfig();
        String allowed = config == null ? null : config.getConfig().get(AdminNetworkAuthenticatorFactory.ALLOWED_CIDRS);
        String remote = context.getConnection() == null ? null : context.getConnection().getRemoteAddr();
        if (!CidrMatcher.matchesAny(remote, CidrMatcher.split(allowed))) {
            deny(context, "NETWORK_NOT_ALLOWED");
            return;
        }
        boolean requireKey = config == null
                || !"false".equalsIgnoreCase(config.getConfig().get(AdminNetworkAuthenticatorFactory.REQUIRE_FIDO2));
        if (requireKey && !hasSecurityKey(context.getUser())) {
            deny(context, "NO_SECURITY_KEY");
            return;
        }
        context.success();
    }

    private static boolean hasSecurityKey(UserModel user) {
        if (user == null) {
            return false;
        }
        return WEBAUTHN_CREDENTIAL_TYPES.stream()
                .anyMatch(t -> user.credentialManager().getStoredCredentialsByTypeStream(t).findAny().isPresent());
    }

    private static void deny(AuthenticationFlowContext context, String reason) {
        LOG.infof("Admin login denied: %s", reason);
        context.failure(AuthenticationFlowError.ACCESS_DENIED);
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
