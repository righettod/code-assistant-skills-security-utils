---
name: secure-jwt-validation
description: Generate secure validation code for access tokens that use the Json Web Token (JWT) format. Enforces secure generation of code validating a JWT-format access token. Invoke when writing any validation code for an access token that uses the JWT format. See "security-considerations" metadata for security limitations.
allowed-tools: Read Grep Glob
metadata:
  category: security
  security-considerations: 
    - This skill validates JWT tokens used as OAuth 2.0 access tokens (authorization) only; ID token claims (authentication) are out of scope and not validated.
    - The caller MUST pass the resource server URI as the expectedAudience parameter and NOT the OAuth client_id. Passing the client_id would allow an ID token to pass the audience check, undermining the protection against ID token substitution attacks. The scope claim presence and the audience value together are the primary guards when typ is JWT instead of at+JWT.
    - The public key parameter MUST be fetched from the authorization server JWKS endpoint and refreshed on key rotation. A hardcoded or stale key invalidates the signature verification guarantee.
    - The revocationChecker predicate MUST consult an up-to-date, low-latency store (e.g., Redis). A stale or heavily cached revocation list defeats the logout protection that the jti check is intended to provide.
    - The scope validation uses exact string matching. Since scope is a space-separated list per RFC 6749, the caller must pass the full expected scope string. Partial scope membership checks require a custom predicate outside this skill.
    - The headers jku and x5u are rejected by default to prevent attacker-controlled key fetching. Callers who genuinely require these headers must implement strict URL allowlisting outside this skill before enabling them.
    - The header jwk is rejected by default to prevent embedded attacker-controlled public key injection (CVE-2018-0114). This header must never be trusted regardless of context.
    - The ECDSA signature verification is vulnerable to CVE-2022-21449 (Psychic Signature) on unpatched JDK versions 15-18. Ensure the JDK is patched and the JWT library used is not affected by this vulnerability. This cannot be mitigated in application code alone.
    - ES256 (P-256) is the most widely supported EC curve and is used as the reference in code examples. ES384 (P-384) offers a higher security margin and should be preferred where the authorization server supports it.
---

# Secure JWT Access Token Validation Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to validation of an access token that uses the Json Web Token (JWT) format.

## 1. Token validation (CRITICAL)

- ALWAYS ensure that the token size does not exceed 8192 bytes before parsing to prevent denial of service.
- ALWAYS ensure that the algorithm used for the signature use asymmetric key pair, preferring Elliptic Curve (EC) over RSA.
- ALWAYS ensure that the algorithm used to validate the signature is not read from the token.
- ALWAYS ensure that the signature of the token is valid.
- ALWAYS ensure that the claim `iss` is present and not empty.
- ALWAYS ensure that the claim `scope` is present and not empty.
- ALWAYS ensure that the claim `aud` is present and not empty.
- ALWAYS ensure that the claim `sub` is present and not empty.
- ALWAYS ensure that the claim `jti` is present and not empty.
- ALWAYS ensure that the claim `jti` value is checked against a token revocation list to detect revoked tokens (e.g., after a logout event).
- ALWAYS ensure that the claim `exp` is present and not empty.
- ALWAYS ensure that the claim `iss` is validated against an expected value.
- ALWAYS ensure that the claim `scope` is validated against an expected value.
- ALWAYS ensure that the claim `aud` is validated against an expected value.
- ALWAYS ensure that the token is valid from an expiration date time perspective using the current date time using UTC timezone.
- ALWAYS ensure that the token is not used before the date time defined by the claim `nbf` using UTC timezone; if `nbf` is absent, use the current UTC datetime as the not-before reference.
- ALWAYS ensure that the header `typ` is present and not empty.
- ALWAYS ensure that the header `typ` is validated against the expected values `at+JWT` or `JWT`.
- ALWAYS ensure that if the header `kid` is present, its value only contains characters matching the pattern `[a-zA-Z0-9\-_]{1,30}` to prevent injection attacks (path traversal, SQL injection, RCE) via key ID manipulation.
- ALWAYS ensure that the headers `jku` and `x5u` are rejected if present; these headers allow the token to supply a URL for key fetching and must never be trusted.
- ALWAYS ensure that the header `jwk` is rejected if present; this header allows the token to embed a public key and must never be trusted (CVE-2018-0114).


```java
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

// BAD: No validation - Only the signature is validated and use symmetric key
public DecodedJWT badValidateToken(String token, String secret) {
    return JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
}

// GOOD: All rules are applied
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.function.Predicate;

public DecodedJWT validateToken(String token, ECPublicKey publicKey, String expectedIssuer, String expectedAudience, String expectedScope, Predicate<String> revocationChecker) {
    if (token == null || token.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 8192)
        throw new IllegalArgumentException("Token is null or exceeds maximum allowed size of 8192 bytes");

    DecodedJWT decoded = JWT.require(Algorithm.ECDSA256(publicKey, null)) // algorithm is NOT read from token
            .withIssuer(expectedIssuer)
            .withAudience(expectedAudience)
            .withClaim("scope", expectedScope)
            .build()
            .verify(token); // validates signature + exp automatically

    // Ensure required claims are present and not empty
    if (decoded.getIssuer() == null || decoded.getIssuer().isBlank())
        throw new IllegalArgumentException("Missing or empty claim: iss");

    if (decoded.getClaim("scope").isNull() || decoded.getClaim("scope").asString().isBlank())
        throw new IllegalArgumentException("Missing or empty claim: scope");

    if (decoded.getAudience() == null || decoded.getAudience().isEmpty())
        throw new IllegalArgumentException("Missing or empty claim: aud");

    if (decoded.getSubject() == null || decoded.getSubject().isBlank())
        throw new IllegalArgumentException("Missing or empty claim: sub");

    if (decoded.getId() == null || decoded.getId().isBlank())
        throw new IllegalArgumentException("Missing or empty claim: jti");

    if (revocationChecker.test(decoded.getId()))
        throw new IllegalArgumentException("Token has been revoked");

    if (decoded.getExpiresAt() == null)
        throw new IllegalArgumentException("Missing or empty claim: exp");

    // Validate expiration using UTC without mutating global timezone state
    if (decoded.getExpiresAt().toInstant().isBefore(Instant.now()))
        throw new IllegalArgumentException("Token has expired");

    // Validate not-before using UTC; fall back to current datetime if nbf is absent
    Instant notBefore = decoded.getNotBefore() != null ? decoded.getNotBefore().toInstant() : Instant.now();
    if (Instant.now().isBefore(notBefore))
        throw new IllegalArgumentException("Token not yet valid");

    // Reject headers that allow attacker-controlled key material (CVE-2018-0114, JKU/X5U abuse)
    if (!decoded.getHeaderClaim("jku").isNull())
        throw new IllegalArgumentException("Forbidden header present: jku");
    if (!decoded.getHeaderClaim("x5u").isNull())
        throw new IllegalArgumentException("Forbidden header present: x5u");
    if (!decoded.getHeaderClaim("jwk").isNull())
        throw new IllegalArgumentException("Forbidden header present: jwk");

    // Validate kid header if present to prevent injection attacks via key ID manipulation
    String kid = decoded.getHeaderClaim("kid").asString();
    if (kid != null && !kid.matches("[a-zA-Z0-9\\-_]{1,30}"))
        throw new IllegalArgumentException("Invalid kid header value");

    // Validate typ header to prevent token confusion attacks (RFC 9068)
    String tokenType = decoded.getHeaderClaim("typ").asString();
    if (tokenType == null || tokenType.isBlank())
        throw new IllegalArgumentException("Missing or empty header: typ");
    if (!"at+JWT".equals(tokenType) && !"JWT".equals(tokenType))
        throw new IllegalArgumentException("Invalid token type: " + tokenType);

    return decoded;
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] The token size does not exceed 8192 bytes before parsing.
- [ ] The algorithm used for the signature use asymmetric key pair, preferring Elliptic Curve (EC) over RSA.
- [ ] The algorithm used to validate the signature is not read from the token.
- [ ] The signature of the token is valid.
- [ ] The claim `iss` is present and not empty.
- [ ] The claim `iss` is validated against an expected value.
- [ ] The claim `scope` is present and not empty.
- [ ] The claim `scope` is validated against an expected value.
- [ ] The claim `aud` is present and not empty.
- [ ] The claim `aud` is validated against an expected value.
- [ ] The claim `sub` is present and not empty.
- [ ] The claim `jti` is present and not empty.
- [ ] The claim `jti` value is checked against a token revocation list.
- [ ] The claim `exp` is present and not empty.
- [ ] The token expiration is validated against the current UTC date time.
- [ ] The token is not used before the date time defined by the claim `nbf` using UTC timezone; if `nbf` is absent, the current UTC datetime is used as the not-before reference.
- [ ] The header `typ` is present and not empty.
- [ ] The header `typ` is validated against the expected values `at+JWT` or `JWT`.
- [ ] If the header `kid` is present, its value only contains characters matching `[a-zA-Z0-9\-_]{1,30}`.
- [ ] The headers `jku` and `x5u` are rejected if present.
- [ ] The header `jwk` is rejected if present.


## References

- [RFC 7519: JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519.html).
- [IANA: JSON Web Token (JWT) Claims](https://www.iana.org/assignments/jwt).
- [PortSwigger: JWT Attacks](https://portswigger.net/web-security/jwt).
- [Pentesterlab: JWT Vulnerabilities and Attacks Guide](https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide).
- [OWASP: JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html).
- [MITRE CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html).
- [RFC 9068: JSON Web Token Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068.html).
