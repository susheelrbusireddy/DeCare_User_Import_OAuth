package com.okta.bulkload;

import com.okta.sdk.resource.model.PasswordCredential;
import com.okta.sdk.resource.model.PasswordCredentialHash;
import com.okta.sdk.resource.model.PasswordCredentialHashAlgorithm;
import com.okta.sdk.resource.model.UserCredentialsWritable;

import java.util.Base64;

/**
 * Parses LDAP-style {@code {SSHA}...} values from CSV into Okta imported-password credentials.
 */
public final class ImportedPasswordSupport {

    private ImportedPasswordSupport() {
    }

    public static UserCredentialsWritable credentialsFromCsv(
            String shaValue,
            String saltOrder) {

        int braceIndex = shaValue.indexOf('}');
        if (braceIndex < 0) {
            throw new IllegalArgumentException("Password value must contain algorithm prefix like {SSHA}");
        }

        String algorithmPrefix = shaValue.substring(0, braceIndex + 1);
        String encodedPayload = shaValue.substring(braceIndex + 1);

        PasswordCredentialHash hash = new PasswordCredentialHash();
        hash.setAlgorithm(PasswordCredentialHashAlgorithm.SHA_1);

        if (algorithmPrefix.startsWith("{SSHA")) {
            byte[] comboValue = Base64.getDecoder().decode(encodedPayload);
            int arrayLength = comboValue.length;

            byte[] saltOutput = new byte[8];
            byte[] hashOutput = new byte[arrayLength - 8];

            if ("prefix".equalsIgnoreCase(saltOrder)) {
                System.arraycopy(comboValue, 0, saltOutput, 0, 8);
                System.arraycopy(comboValue, 8, hashOutput, 0, hashOutput.length);
            } else {
                System.arraycopy(comboValue, arrayLength - 8, saltOutput, 0, 8);
                System.arraycopy(comboValue, 0, hashOutput, 0, arrayLength - 8);
            }

            String hashpswd = Base64.getMimeEncoder().encodeToString(hashOutput).replace("\r\n", "");
            String salt = Base64.getMimeEncoder().encodeToString(saltOutput).replace("\r\n", "");

            hash.setValue(hashpswd);
            hash.setSalt(salt);
            hash.setSaltOrder(normalizeSaltOrder(saltOrder));
        } else {
            throw new IllegalArgumentException(
                    "Unsupported password format: " + algorithmPrefix + " (only {SSHA} is supported)");
        }

        PasswordCredential password = new PasswordCredential();
        password.setHash(hash);

        UserCredentialsWritable credentials = new UserCredentialsWritable();
        credentials.setPassword(password);
        return credentials;
    }

    private static String normalizeSaltOrder(String saltOrder) {
        if ("prefix".equalsIgnoreCase(saltOrder)) {
            return "PREFIX";
        }
        return "POSTFIX";
    }
}
