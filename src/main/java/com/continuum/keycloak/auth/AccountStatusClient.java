package com.continuum.keycloak.auth;

/** Calls the backend getAccountLoginStatus operation (contracts/openapi/internal/keycloak.yaml). */
public interface AccountStatusClient {

    /** Login decision; {@code reason} is a machine code, null when allowed. */
    record Decision(boolean allowed, String reason) {
    }

    /** @throws Exception on any transport, auth or protocol failure (the caller fails closed). */
    Decision getStatus(String continuumUserId, String tenantId) throws Exception;
}
