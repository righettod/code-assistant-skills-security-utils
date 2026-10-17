---
name: secure-saml-response-validation
description: Generate secure validation code validating a SAML response. Enforces secure generation of code validating a SAML response. Invoke when writing any validation code for an SAML response. See "security-considerations" metadata for security limitations.
allowed-tools: Read Grep Glob
metadata:
  category: security
  security-considerations:
    - SAML response validation is a complex and error-prone operation. This skill is a best-effort attempt and may not cover all attack vectors or edge cases. It must not be used as the sole security review for a SAML integration; a manual security review by a specialist is strongly recommended.
    - This skill validates only a SAML response. Not a SAML request.
    - The trusted IdP certificate must be pre-loaded from a local truststore and never fetched dynamically from the SAML response itself, to prevent attacker-controlled certificate injection.
    - Clock skew tolerance is capped at 5 minutes. Larger values increase the replay window and should not be used.
    - The replay cache used to enforce one-time use must be backed by a shared, durable store (e.g., Redis or a database) in multi-node deployments; an in-process cache is insufficient and allows replay across nodes.
    - Attribute values extracted from validated SAML assertions are user-supplied data and must be treated as untrusted input in downstream code (e.g., sanitized before rendering or used in queries).
    - This skill does not cover XML Signature Wrapping (XSW) mitigations beyond enforcing signature validation via a trusted library. Use a library that is known to be immune to XSW attacks (e.g., OpenSAML with strict schema validation enabled).
    - The library used must not dereference external URIs during signature reference resolution; failing to block this allows SSRF attacks triggered before signature verification completes.
    - The library used must not process XSLT transforms embedded in signature blocks; failing to block this allows remote code execution during reference processing.
    - Use a library version patched against Digest Comment Injection (CVE-2025-29775), where an XML comment injected into the `<DigestValue>` element can split the digest and allow assertion tampering while keeping a valid signature.
    - Use a library version patched against parser differential attacks (CVE-2025-25291, CVE-2025-25292), where disagreements between two XML parsers in the same library allow a single valid signature to cover different NameID values depending on which parser performs extraction.

---

# SAML Response Validation Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to validation of SAML response.

## 1. SAML response validation (CRITICAL)

- ALWAYS limit the size of the SAML response input to prevent memory exhaustion and denial of service (reject inputs larger than 512 KB).
- ALWAYS parse the SAML response XML with a secure parser that disables DTD, external entities, internal entity expansion, and XInclude (apply the same controls as the `secure-xml-parsing` skill).
- ALWAYS ensure that a trusted external library is used to validate the XML digital signature of the SAML response (never implement signature verification manually).
- ALWAYS ensure that a trusted external library is used to validate the XML digital signature of every assertion contained in the SAML response (never implement signature verification manually).
- ALWAYS ensure that the signing certificate is validated against a pre-loaded trusted IdP certificate; never accept a certificate embedded in the SAML response itself.
- ALWAYS ensure that the `Issuer` element value is validated against the expected Identity Provider (IdP) entity ID.
- ALWAYS ensure that the `StatusCode` element indicates a successful authentication (`urn:oasis:names:tc:SAML:2.0:status:Success`).
- ALWAYS ensure that the `Audience` element in every assertion is validated against the expected Service Provider (SP) entity ID.
- ALWAYS ensure that the `Destination` attribute is validated against the expected Assertion Consumer Service (ACS) URL.
- ALWAYS ensure that the `InResponseTo` attribute is validated against the ID of the original authentication request sent by the SP.
- ALWAYS ensure that the `NotBefore` condition is validated against the current UTC date time, allowing a maximum clock skew tolerance of 5 minutes.
- ALWAYS ensure that the `NotOnOrAfter` condition is validated against the current UTC date time, allowing a maximum clock skew tolerance of 5 minutes.
- ALWAYS ensure that a SAML response ID is accepted only once to prevent replay attacks; store used IDs in a shared, durable cache.
- ALWAYS ensure that the `Recipient` attribute in every `SubjectConfirmationData` element of every assertion is validated against the expected Assertion Consumer Service (ACS) URL.
- ALWAYS ensure that values extracted from the SAML response (e.g., `NameID`) do not contain XML comment markers (`<!--` or `-->`); reject the response if any are found to prevent comment injection attacks.

```java
// BAD: No validation - accepts any SAML response without performing any security check
import org.opensaml.saml.saml2.core.Response;

public void badValidateSamlResponse(Response response) {
    // No checks performed: signature, issuer, audience, destination, replay, and time conditions are all skipped
}

// GOOD: All rules applied
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

public void validateSamlResponse(byte[] rawSamlResponseBytes, Response response, Credential trustedIdpCredential, String expectedIssuer, String expectedAudience, String expectedAcsUrl, String originalRequestId, Set<String> usedResponseIds) {
    // XML parsing must be performed beforehand using the secure-xml-parsing skill
    // (DTD, external entities, internal entity expansion, and XInclude all disabled)
    // Reject oversized SAML response
    if (rawSamlResponseBytes == null || rawSamlResponseBytes.length > 512 * 1024)
        throw new IllegalArgumentException("SAML response is null or exceeds maximum allowed size of 512 KB");

    // Validate response-level signature using a pre-loaded trusted IdP credential (NOT from the response)
    if (response.getSignature() == null)
        throw new IllegalArgumentException("SAML response is not signed");
    SignatureValidator.validate(response.getSignature(), trustedIdpCredential);

    // Validate Issuer against the expected IdP entity ID
    if (response.getIssuer() == null || !expectedIssuer.equals(response.getIssuer().getValue()))
        throw new IllegalArgumentException("Invalid or missing Issuer");

    // Validate StatusCode indicates successful authentication
    if (response.getStatus() == null || response.getStatus().getStatusCode() == null || !StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue()))
        throw new IllegalArgumentException("SAML response does not indicate success");

    // Validate Destination against the expected ACS URL
    if (response.getDestination() == null || !expectedAcsUrl.equals(response.getDestination()))
        throw new IllegalArgumentException("Missing or invalid Destination attribute");

    // Validate InResponseTo against the original SP authentication request ID
    if (response.getInResponseTo() == null || !originalRequestId.equals(response.getInResponseTo()))
        throw new IllegalArgumentException("Missing or invalid InResponseTo attribute");

    // Replay detection: reject previously seen response IDs
    String responseId = response.getID();
    if (responseId == null || usedResponseIds.contains(responseId))
        throw new IllegalArgumentException("SAML response ID is null or has already been used (replay detected)");
    usedResponseIds.add(responseId);

    if (response.getAssertions() == null || response.getAssertions().isEmpty())
        throw new IllegalArgumentException("SAML response contains no assertions");

    Duration clockSkewTolerance = Duration.ofMinutes(5);
    Instant now = Instant.now();

    for (Assertion assertion : response.getAssertions()) {
        // Validate each assertion signature using a pre-loaded trusted IdP credential
        if (assertion.getSignature() == null)
            throw new IllegalArgumentException("Assertion is not signed");
        SignatureValidator.validate(assertion.getSignature(), trustedIdpCredential);

        // Validate Recipient in SubjectConfirmationData against the expected ACS URL
        if (assertion.getSubject() == null || assertion.getSubject().getSubjectConfirmations() == null || assertion.getSubject().getSubjectConfirmations().isEmpty())
            throw new IllegalArgumentException("Assertion has no SubjectConfirmation");
        boolean recipientValid = assertion.getSubject().getSubjectConfirmations().stream().anyMatch(sc -> sc.getSubjectConfirmationData() != null && expectedAcsUrl.equals(sc.getSubjectConfirmationData().getRecipient()));
        if (!recipientValid)
            throw new IllegalArgumentException("Assertion SubjectConfirmationData does not contain the expected Recipient");

        // Guard: Conditions element must be present before any condition check
        Conditions conditions = assertion.getConditions();
        if (conditions == null)
            throw new IllegalArgumentException("Assertion has no Conditions element");

        // Validate Audience against the expected SP entity ID
        boolean audienceValid = conditions.getAudienceRestrictions().stream().flatMap(ar -> ar.getAudiences().stream()).anyMatch(a -> expectedAudience.equals(a.getURI()));
        if (!audienceValid)
            throw new IllegalArgumentException("Assertion does not contain the expected Audience");

        // Validate NotBefore and NotOnOrAfter with a maximum clock skew tolerance of 5 minutes
        if (conditions.getNotBefore() != null && now.isBefore(conditions.getNotBefore().toInstant().minus(clockSkewTolerance)))
            throw new IllegalArgumentException("Assertion is not yet valid (NotBefore condition violated)");
        if (conditions.getNotOnOrAfter() == null || now.isAfter(conditions.getNotOnOrAfter().toInstant().plus(clockSkewTolerance)))
            throw new IllegalArgumentException("Assertion has expired (NotOnOrAfter condition violated)");
    }

}

// BAD: Extracts NameID without checking for XML comment markers - vulnerable to comment injection attacks
public String badExtractNameId(Response response) {
    return response.getAssertions().get(0).getSubject().getNameID().getValue();
}

// GOOD: Rejects NameID values containing XML comment markers to prevent comment injection attacks
public String extractNameId(Response response) {
    String nameId = response.getAssertions().get(0).getSubject().getNameID().getValue();
    if (nameId == null || nameId.contains("<!--") || nameId.contains("-->"))
        throw new IllegalArgumentException("NameID contains forbidden XML comment markers");
    return nameId;
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] SAML response size is limited to 512 KB before parsing.
- [ ] XML parsing is configured with DTD, external entities, internal entity expansion, and XInclude disabled (apply all controls from the `secure-xml-parsing` skill).
- [ ] The SAML response XML digital signature is validated using a trusted external library (signature verification is not implemented manually).
- [ ] Every assertion XML digital signature is validated using a trusted external library (signature verification is not implemented manually).
- [ ] The signing certificate is validated against a pre-loaded trusted IdP certificate, not one embedded in the response.
- [ ] The `Issuer` element is validated against the expected IdP entity ID.
- [ ] The `StatusCode` confirms successful authentication (`urn:oasis:names:tc:SAML:2.0:status:Success`).
- [ ] The `Audience` in every assertion is validated against the expected SP entity ID.
- [ ] The `Destination` attribute is validated against the expected ACS URL.
- [ ] The `InResponseTo` attribute is validated against the original authentication request ID.
- [ ] The `NotBefore` condition is validated against the current UTC time with at most 5 minutes of clock skew tolerance.
- [ ] The `NotOnOrAfter` condition is validated against the current UTC time with at most 5 minutes of clock skew tolerance.
- [ ] The SAML response ID is checked against a durable cache and stored to prevent replay attacks.
- [ ] The `Recipient` attribute in every `SubjectConfirmationData` element of every assertion is validated against the expected ACS URL.
- [ ] Values extracted from the SAML response (e.g., `NameID`) are checked for XML comment markers (`<!--`, `-->`); the response is rejected if any are found.

## References

- [Secure XML Parsing Skill from GitHub](https://github.com/righettod/code-assistant-skills-security-utils/blob/main/.claude/skills/secure-xml-parsing/SKILL.md).
- [SAML Security Cheat Sheet from OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html).
- [SAML Vulnerabilities and Attacks: A Practical Guide from Pentesterlab](https://pentesterlab.com/blog/saml-vulnerabilities-attacks-guide).
- [The Fragile Lock - Novel Bypasses For SAML Authentication from PortSwigger](https://portswigger.net/research/the-fragile-lock).
- [SAML roulette - The hacker always wins from PortSwigger](https://portswigger.net/research/saml-roulette-the-hacker-always-wins).
- [Security Assertion Markup Language (SAML) V2.0 Specification from OASIS](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf).
- [Improper Verification of Cryptographic Signature (CWE-347) from MITRE](https://cwe.mitre.org/data/definitions/347.html).
- [Authentication Bypass by Capture-replay (CWE-294) from MITRE](https://cwe.mitre.org/data/definitions/294.html).
- [Forge Web Credentials: SAML Tokens (ATT&CK T1606.002) from MITRE](https://attack.mitre.org/techniques/T1606/002/).
