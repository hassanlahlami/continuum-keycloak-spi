package com.continuum.keycloak.auth;

import java.util.List;
import java.util.Map;

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class AccountStatusAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "continuum-account-status";
    static final String BACKEND_URL = "backendUrl";
    static final String TOKEN_URL = "tokenUrl";
    static final String CLIENT_ID = "clientId";
    static final String CLIENT_SECRET = "clientSecret";
    static final String TIMEOUT_MS = "timeoutMs";

    private static final List<ProviderConfigProperty> CONFIG = List.of(
            prop(BACKEND_URL, "Backend base URL", "Backend root, e.g. http://backend:8080", ProviderConfigProperty.STRING_TYPE),
            prop(TOKEN_URL, "Token endpoint", "Keycloak token endpoint used for client credentials", ProviderConfigProperty.STRING_TYPE),
            prop(CLIENT_ID, "Service client id", "Client credentials client (continuum-keycloak)", ProviderConfigProperty.STRING_TYPE),
            prop(CLIENT_SECRET, "Service client secret", "Client secret", ProviderConfigProperty.PASSWORD),
            prop(TIMEOUT_MS, "Timeout (ms)", "Per-request timeout; on expiry the login is denied", ProviderConfigProperty.STRING_TYPE));

    private static ProviderConfigProperty prop(String name, String label, String help, String type) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(name);
        p.setLabel(label);
        p.setHelpText(help);
        p.setType(type);
        return p;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new AccountStatusAuthenticator(AccountStatusAuthenticatorFactory::clientFrom);
    }

    static AccountStatusClient clientFrom(AuthenticationFlowContext context) {
        Map<String, String> c = context.getAuthenticatorConfig().getConfig();
        return new HttpAccountStatusClient(c.get(BACKEND_URL), c.get(TOKEN_URL), c.get(CLIENT_ID),
                c.get(CLIENT_SECRET), AccountStatusAuthenticator.timeoutOf(c.get(TIMEOUT_MS)));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Continuum account status";
    }

    @Override
    public String getReferenceCategory() {
        return "continuum-account-status";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[] {Requirement.REQUIRED, Requirement.DISABLED};
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Denies login when the backend reports no active assignment or a suspended tenant (fail-closed).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
