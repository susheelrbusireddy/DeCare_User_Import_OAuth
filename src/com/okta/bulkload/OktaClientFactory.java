package com.okta.bulkload;

import com.okta.sdk.client.AuthorizationMode;
import com.okta.sdk.client.ClientBuilder;
import com.okta.sdk.client.Clients;
import com.okta.sdk.resource.client.ApiClient;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Builds a shared {@link ApiClient} using OAuth 2.0 private-key JWT (service app).
 */
public final class OktaClientFactory {

    private OktaClientFactory() {
    }

    public static ApiClient create(Properties configuration) {
        String orgUrl = resolveOrgUrl(configuration);
        String clientId = require(configuration, "clientId");
        String privateKey = resolvePrivateKey(configuration);

        Set<String> scopes = parseScopes(configuration.getProperty(
                "oauthScopes", "okta.users.manage"));

        ClientBuilder builder = Clients.builder()
                .setOrgUrl(orgUrl)
                .setAuthorizationMode(AuthorizationMode.PRIVATE_KEY)
                .setClientId(clientId)
                .setScopes(scopes)
                .setPrivateKey(privateKey)
                .setRetryMaxAttempts(Integer.parseInt(
                        configuration.getProperty("rateLimitMaxRetries", "5")))
                .setRetryMaxElapsed(Integer.parseInt(
                        configuration.getProperty("rateLimitRequestTimeoutSeconds", "0")));

        String kid = configuration.getProperty("kid");
        if (kid != null && !kid.trim().isEmpty()) {
            builder.setKid(kid.trim());
        }

        String accessToken = configuration.getProperty("oauth2AccessToken");
        if (accessToken != null && !accessToken.trim().isEmpty()) {
            builder.setOAuth2AccessToken(accessToken.trim());
        }

        return builder.build();
    }

    private static String resolveOrgUrl(Properties configuration) {
        String orgUrl = configuration.getProperty("orgUrl");
        if (orgUrl == null || orgUrl.trim().isEmpty()) {
            orgUrl = configuration.getProperty("org");
        }
        if (orgUrl == null || orgUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("orgUrl (or org) is required in configuration");
        }
        orgUrl = orgUrl.trim();
        if (!orgUrl.startsWith("https://") && !orgUrl.startsWith("http://")) {
            orgUrl = "https://" + orgUrl;
        }
        return orgUrl;
    }

    private static String resolvePrivateKey(Properties configuration) {
        String inlineKey = configuration.getProperty("privateKey");
        if (inlineKey != null && !inlineKey.trim().isEmpty()) {
            return inlineKey.trim();
        }

        String keyPath = configuration.getProperty("privateKeyPath");
        if (keyPath == null || keyPath.trim().isEmpty()) {
            throw new IllegalArgumentException(
                    "privateKeyPath or privateKey (PEM) is required for OAuth 2.0");
        }

        Path path = Paths.get(keyPath.trim());
        if (!Files.isReadable(path)) {
            throw new IllegalArgumentException("privateKeyPath is not readable: " + path);
        }
        try {
            return Files.readString(path);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read privateKeyPath: " + path, e);
        }
    }

    private static Set<String> parseScopes(String scopesProperty) {
        return Arrays.stream(scopesProperty.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static String require(Properties configuration, String key) {
        String value = configuration.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(key + " is required in configuration");
        }
        return value.trim();
    }
}
