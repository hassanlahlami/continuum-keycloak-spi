package com.continuum.keycloak.auth;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

import org.keycloak.util.JsonSerialization;

/** Client-credentials HTTP implementation; any non-200 response is an error. */
public class HttpAccountStatusClient implements AccountStatusClient {

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();

    private final String backendUrl;
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;
    private final Duration timeout;

    public HttpAccountStatusClient(String backendUrl, String tokenUrl, String clientId,
                                   String clientSecret, Duration timeout) {
        this.backendUrl = backendUrl.replaceAll("/+$", "");
        this.tokenUrl = tokenUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.timeout = timeout;
    }

    @Override
    public Decision getStatus(String continuumUserId, String tenantId) throws Exception {
        String token = fetchToken();
        URI uri = URI.create(backendUrl + "/internal/accounts/" + enc(continuumUserId)
                + "/status?tenantId=" + enc(tenantId));
        HttpResponse<String> resp = HTTP.send(
                HttpRequest.newBuilder(uri).timeout(timeout)
                        .header("Authorization", "Bearer " + token)
                        .header("Accept", "application/json").GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("account status HTTP " + resp.statusCode());
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> body = JsonSerialization.readValue(resp.body(), Map.class);
        if (!(body.get("allowed") instanceof Boolean allowed)) {
            throw new IllegalStateException("account status: missing 'allowed'");
        }
        Object reason = body.get("reason");
        return new Decision(allowed, reason == null ? null : reason.toString());
    }

    private String fetchToken() throws Exception {
        String form = "grant_type=client_credentials&client_id=" + enc(clientId)
                + "&client_secret=" + enc(clientSecret);
        HttpResponse<String> resp = HTTP.send(
                HttpRequest.newBuilder(URI.create(tokenUrl)).timeout(timeout)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form)).build(),
                HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("service token HTTP " + resp.statusCode());
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> body = JsonSerialization.readValue(resp.body(), Map.class);
        Object token = body.get("access_token");
        if (token == null) {
            throw new IllegalStateException("service token: no access_token");
        }
        return token.toString();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
