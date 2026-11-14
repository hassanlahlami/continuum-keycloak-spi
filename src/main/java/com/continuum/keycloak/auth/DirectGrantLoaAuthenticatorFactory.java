package com.continuum.keycloak.auth;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class DirectGrantLoaAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "continuum-direct-grant-loa";
    static final String LOA = "loa";
    static final String REQUIRED_AUTHENTICATORS = "requiredAuthenticators";
    /** Technical default: provider id of the built-in direct-grant OTP authenticator. */
    static final String DEFAULT_REQUIRED_AUTHENTICATORS = "direct-grant-validate-otp";
    /**
     * Server-level SPI option, off by default (ADR 0014: no acr >= 2 from a REST login). Not named "enabled": that key is
     * Keycloak's own provider switch, and enabled=false unregisters the provider, so any flow referencing it fails (500).
     */
    static final String RAISE_LOA_OPTION = "raise-loa";

    private boolean enabled;

    private static final List<ProviderConfigProperty> CONFIG = List.of(
            prop(LOA, "Level of authentication",
                    "LoA set when all required authenticators succeeded (integer >= 1, mapped to acr by the acr-loa map); empty or invalid leaves the LoA unchanged",
                    ProviderConfigProperty.STRING_TYPE, null),
            prop(REQUIRED_AUTHENTICATORS, "Required authenticators",
                    "Comma-separated authenticator provider ids that must have finished with SUCCESS in this login",
                    ProviderConfigProperty.STRING_TYPE, DEFAULT_REQUIRED_AUTHENTICATORS));

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
        return new DirectGrantLoaAuthenticator(enabled);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Continuum direct-grant level of authentication";
    }

    @Override
    public String getReferenceCategory() {
        return PROVIDER_ID;
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
        return "Shelved, inert unless SPI option raise-loa=true. Direct grant only, last REQUIRED step: sets the LoA when the required authenticators (default OTP) succeeded in this login; never fails it.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }

    @Override
    public void init(Config.Scope config) {
        enabled = config != null && Boolean.TRUE.equals(config.getBoolean(RAISE_LOA_OPTION, false));
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
