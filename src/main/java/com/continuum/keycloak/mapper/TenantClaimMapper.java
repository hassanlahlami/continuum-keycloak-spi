package com.continuum.keycloak.mapper;

import java.util.List;
import java.util.Map;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

/**
 * Adds the platform claims (§4.5.2) to the tokens: {@code tenant_id}, {@code continuum_user_id}
 * and {@code authz_version}. Values come from user attributes provisioned by the backend, so
 * Keycloak holds no business logic (§4.5.3). A missing attribute yields no claim: the backend
 * resource server then rejects the token (fail-closed).
 */
public class TenantClaimMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "continuum-tenant-claim-mapper";

    /** User attribute name → token claim name. */
    static final Map<String, String> CLAIMS = Map.of(
            "tenant_id", "tenant_id",
            "continuum_user_id", "continuum_user_id",
            "authz_version", "authz_version");

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Continuum tenant claims";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Adds tenant_id, continuum_user_id and authz_version from the user attributes.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> props = new java.util.ArrayList<>();
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(props, TenantClaimMapper.class);
        return props;
    }

    @Override
    protected void setClaim(IDToken token, org.keycloak.models.ProtocolMapperModel mappingModel,
                            UserSessionModel userSession, KeycloakSession keycloakSession,
                            ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();
        CLAIMS.forEach((attribute, claim) -> {
            String value = user.getFirstAttribute(attribute);
            if (value != null && !value.isBlank()) {
                token.getOtherClaims().put(claim, value);
            }
        });
    }
}
