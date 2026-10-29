package com.continuum.keycloak.auth;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class AdminNetworkAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "continuum-admin-network";
    static final String ALLOWED_CIDRS = "allowedCidrs";
    static final String REQUIRE_FIDO2 = "requireFido2";

    private static final List<ProviderConfigProperty> CONFIG = List.of(
            prop(ALLOWED_CIDRS, "Allowed networks (CIDR)", "Comma-separated CIDR list of the administration network; empty denies everyone",
                    ProviderConfigProperty.STRING_TYPE, null),
            prop(REQUIRE_FIDO2, "Require FIDO2 key", "User must own a WebAuthn credential",
                    ProviderConfigProperty.BOOLEAN_TYPE, "true"));

    private static ProviderConfigProperty prop(String name, String label, String help, String type, String def) {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName(name);
        p.setLabel(label);
        p.setHelpText(help);
        p.setType(type);
        p.setDefaultValue(def);
        return p;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new AdminNetworkAuthenticator();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Continuum admin network + FIDO2";
    }

    @Override
    public String getReferenceCategory() {
        return "continuum-admin-network";
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
        return "Requires the administration network and a FIDO2 key for continuum-admin (fail-closed).";
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
