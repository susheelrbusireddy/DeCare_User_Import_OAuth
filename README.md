# Okta bulk user import

Command-line tool that bulk-imports users from CSV into Okta using the [Okta Java Management SDK](https://github.com/okta/okta-sdk-java) (v25.0.3) with **OAuth 2.0 private-key JWT** authentication (service application). Supports **imported password hashes** (LDAP-style `{SSHA}`) so migrated users can sign in without resetting passwords.

## Requirements

- Java 11+
- Maven 3.6+
- An Okta org with a **service app** configured for OAuth 2.0 client credentials (private key JWT)
- Scope: `okta.users.manage` (add `okta.groups.manage` if using `groupIDs`)

See Okta’s guide: [Build an OAuth 2.0 service app](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/).

**Service app settings**

- Grant type: **Client Credentials**
- Authentication: **Public key / Private key**
- **Disable “Require DPoP”** for this app unless you have a specific reason to use it. Server-side bulk import with the Java SDK expects standard private-key JWT; DPoP-enabled apps can fail at client creation with `invalid_dpop_proof`.

## How it works

```
CSV file → Producer thread → BlockingQueue → Consumer thread(s) → UserApi.createUser()
                                                      ↓
                              success / reject / replay CSV files
```

| Component | Role |
|-----------|------|
| `BulkLoader` | Orchestrates producer/consumer threads, writes result CSVs |
| `OktaClientFactory` | Builds a shared `ApiClient` with OAuth private-key JWT and SDK retry settings |
| `ImportedPasswordSupport` | Converts CSV `{SSHA}...` values into Okta imported-password credentials |

- One **producer** reads the input CSV and enqueues rows.
- **N consumers** (`numConsumers`) dequeue rows and call `UserApi.createUser()`.
- A single shared Okta client is used across all consumers; the SDK caches and refreshes OAuth access tokens automatically.

## Configuration

Copy the example file and fill in your values:

```bash
cp src/main/resources/config.properties.example src/main/resources/config.properties
```

> **Important:** Java `.properties` files only treat `#` as a comment when it starts the line. Do **not** put inline comments on the same line as a value (e.g. `clientId=abc  # my app` — the comment becomes part of the value).

### OAuth / Okta API

| Property | Required | Description |
|----------|----------|-------------|
| `orgUrl` | Yes | Okta org URL, e.g. `https://your-domain.okta.com` (legacy alias: `org`) |
| `clientId` | Yes | Service app client ID |
| `privateKeyPath` or `privateKey` | Yes | PEM private key file path or inline PEM content |
| `oauthScopes` | No | Default: `okta.users.manage` (comma-separated) |
| `kid` | No | Public key ID when the app has multiple keys |
| `oauth2AccessToken` | No | Pre-obtained token; if set, private-key exchange is skipped |
| `rateLimitMaxRetries` | No | SDK retries for 429/503/504 (default: `5`) |
| `rateLimitRequestTimeoutSeconds` | No | Max seconds to spend retrying; `0` = no cap (default) |
| `activateUsers` | No | Activate users on create (default: `true`) |

### CSV schema mapping

| Property | Description |
|----------|-------------|
| `csvHeaderRow` | Comma-separated CSV column names (must match file header) |
| `csvLoginField` | Column used as Okta login |
| `csvPasswordField` | Column with `{SSHA}` hash (excluded from profile mapping) |
| `csvHeader.<column>` | Maps CSV column → Okta profile field name |

### Groups and concurrency

| Property | Description |
|----------|-------------|
| `groupIDs` | Comma-separated Okta group IDs to assign on create (requires `okta.groups.manage`) |
| `saltOrder` | `POSTFIX` (default) or `PREFIX` — SSHA salt byte order |
| `numConsumers` | Worker threads (default: `1`; increase cautiously for throughput) |
| `bufferSize` | Producer queue capacity (default: `10000`) |

## Build

```bash
mvn package
```

Produces a shaded (fat) JAR:

```
target/DeCare-user-import.jar
```

The build uses `maven-shade-plugin` with signature-file exclusions so signed dependency JARs do not cause `Invalid signature file digest` errors at runtime.

## Run

```bash
java -jar target/DeCare-user-import.jar <config_file> <csv_file>
```

Example (from project root):

```bash
java -jar target/DeCare-user-import.jar src/main/resources/config.properties Users/testusers.csv
```

### Deployed layout (`Jars/`)

For a portable deployment, copy the JAR, config, private key, and CSV into one directory and run from there:

```bash
cp target/DeCare-user-import.jar Jars/
cd Jars
java -jar DeCare-user-import.jar config.properties testusers.csv
```

Use an **absolute path** for `privateKeyPath` if you run from a different working directory.

## Output files

Output files are written next to the input CSV, using the same base name:

| File | Contents |
|------|----------|
| `*_success.csv` | Original columns plus Okta `id` and `status` |
| `*_reject.csv` | Permanent failures plus `errorCode` and `errorCause` |
| `*_replay.csv` | Rows that hit HTTP 429 after SDK retries — re-run this file after rate limits reset |

Progress is printed to stdout (a dot every 100 successes). SDK and error logs go to `ldapbridge.log` in the working directory (console logging is suppressed).

## CSV format

Header row plus one user per line. Example:

```csv
firstName,lastName,email,login,value
Jane,Doe,jane.doe@example.com,jane.doe@example.com,{SSHA}ALr+xvReNxlnO/aBb9G5Ac3Kh7j3fbUHg2ixZw==
```

- Profile fields are mapped via `csvHeader.*` properties.
- The password column must contain an LDAP-style **`{SSHA}`** Base64 hash (SHA-1 imported credentials). Other hash formats are not supported.
- `saltOrder` controls whether the 8-byte salt is at the start (`PREFIX`) or end (`POSTFIX`) of the decoded payload.

## Rate limiting

Okta enforces API rate limits with HTTP **429** responses. See [Rate limits](https://developer.okta.com/docs/reference/rate-limits/) and [Monitor and troubleshoot rate limits](https://developer.okta.com/docs/reference/rl2-monitor/).

The Okta Java SDK automatically retries **429**, **503**, and **504** using `X-Rate-Limit-Reset` and exponential backoff ([SDK connection retry docs](https://github.com/okta/okta-sdk-java#connection-retry)). This project configures that via `rateLimitMaxRetries` and `rateLimitRequestTimeoutSeconds` in `OktaClientFactory`.

If a row still fails with 429 after SDK retries, the tool writes it to `*_replay.csv` instead of `*_reject.csv`. Re-run the replay file later, or lower `numConsumers` to reduce request pressure.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Invalid signature file digest for Manifest` | Stale shaded JAR | Rebuild with `mvn package` (current `pom.xml` excludes signature files) |
| `privateKeyPath is not readable` | Wrong path or inline `#` comment in config | Fix path; move comments to their own lines |
| `invalid_dpop_proof` / `Request execution failed` at startup | DPoP required on service app | Disable **Require DPoP** on the app (Applications → General) |
| All rows in `*_reject.csv` | Bad credentials, duplicate login, missing scope, etc. | Check `errorCode` / `errorCause` columns |
| Rows in `*_replay.csv` | Org rate limit exceeded | Wait and re-run the replay file; reduce `numConsumers` |

## Project layout

```
src/com/okta/bulkload/
  BulkLoader.java              Main entry, producer/consumer pipeline
  OktaClientFactory.java       OAuth client configuration
  ImportedPasswordSupport.java {SSHA} password parsing
src/main/resources/
  config.properties.example    Configuration template
  logback.xml                  File logging (ERROR level)
Users/                         Sample CSV input files
Jars/                          Example deployment directory
```
