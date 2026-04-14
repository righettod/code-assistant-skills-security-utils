---
name: secure-message-digest-generation
description: Generate secure message digest (often called hash) generation code. Enforces secure generation of a message digest. Invoke when writing any message digest generation related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure Message Digest Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to message digest generation.

## 1. Secure algorithm usage and hash collision prevention (CRITICAL)

- ALWAYS ensure that the hashing algorithm used is the strongest that exists, from a cryptography perspective, at the moment at which the code is generated. In case of any doubt always use `SHA3-512` algorithm. 
- ALWAYS ensure that the hashing algorithm used is post-quantum resistant.
- ALWAYS ensure that each value used to create the digest is explicitly separated by the character `|` (appended after every value, even when only one value is provided) prior to the final concatenated value being provided to the hashing function.
- ALWAYS encode the input string to bytes using the `UTF-8` charset explicitly — never rely on the platform default charset, as it may vary across environments and produce different digests for the same input.
- ALWAYS convert null or empty values to an explicit empty string `""` before including them in the digest input — never skip or silently drop them, as omitting a value changes the digest in the same way a different value would.
- ALWAYS encode the raw digest bytes as a lowercase hexadecimal string — never return raw bytes or use Base64, as hex is the canonical, human-readable, and interoperable representation for message digests.

```java
// BAD: Weak algorithm, platform charset, no separator, raw bytes returned
public byte[] computeDigestInsecure(Object[] values) {
    StringBuilder combined = new StringBuilder();
    for (Object value : values) {
        combined.append(value != null ? value.toString() : ""); // no separator — hash collision risk
    }
    MessageDigest md = MessageDigest.getInstance("SHA1"); // weak, not post-quantum resistant
    byte[] hashBytes = md.digest(combined.toString().getBytes()); // platform default charset — non-deterministic
    return hashBytes; // raw bytes — not hex-encoded
}

// GOOD: All rules applied
public String computeDigestSecure(Object[] values) {
    StringBuilder combined = new StringBuilder();
    for (Object value : values) {
        // Rule 5: explicit empty string for null/empty — never skip
        combined.append((value == null || value.toString().isEmpty()) ? "" : value.toString());
        // Rule 3: separator after every value, including single values
        combined.append("|");
    }
    // Rule 1 & 2: SHA3-512 — strongest available, post-quantum resistant
    MessageDigest md = MessageDigest.getInstance("SHA3-512");
    // Rule 4: explicit UTF-8 — never rely on platform default
    byte[] hashBytes = md.digest(combined.toString().getBytes(StandardCharsets.UTF_8));
    // Rule 6: lowercase hex — canonical, human-readable, interoperable
    String hexDigest = HexFormat.of().formatHex(hashBytes);
    return hexDigest;
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] The hashing algorithm used is the strongest that exists, from a cryptography perspective, at the moment at which the code is generated.
- [ ] The hashing algorithm used is post-quantum resistant.
- [ ] A separator character `|` is appended after each value (including single values) used to create the data provided to the hashing function.
- [ ] The input string is encoded to bytes using the `UTF-8` charset explicitly, not the platform default.
- [ ] Null or empty values are explicitly converted to an empty string `""` and included in the digest input — never skipped or dropped.
- [ ] The digest output is encoded as a lowercase hexadecimal string — not returned as raw bytes or Base64.

## References

- [Post-Quantum Cryptography from NIST](https://csrc.nist.gov/projects/post-quantum-cryptography).
- [SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions from NIST](https://csrc.nist.gov/pubs/fips/202/final).
- [Flickr's API Signature Forgery Vulnerability from IOACTIVE](https://www.ioactive.com/wp-content/uploads/2012/08/flickr_api_signature_forgery.pdf).
- [Everything you need to know about hash length extension attacks from SKULLSECURITY](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks).
- [Cryptographic_Storage_Cheat_Sheet from OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
- [Hexadecimal from Wikipedia](https://en.wikipedia.org/wiki/Hexadecimal).
- [UTF-8 from Wikipedia](https://en.wikipedia.org/wiki/UTF-8).