---
name: secure-relative-url-validation
description: Generate secure relative url validation code. Enforces secure generation of code validating an relative url. Invoke when writing any relative url validation related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure URL Validation Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to validation of an relative URL.

## 1. URL validation (CRITICAL)

- ALWAYS ensure that the input data is recursively URL decoded prior to be validated. A decoding iteration count threshold of 4 is used and an error must be raised if the threshold is reached.
- ALWAYS ensure that the input data, once URL decoded, start with one of the following character: slash, letter, number, dash, underscore.
- ALWAYS ensure that the input data is a valid URL according to the [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986).
- ALWAYS ensure that URL is not a absolute URL.
- ALWAYS ensure that URL never start with `//`.

```java
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

// BAD: No validation — user input used directly as redirect target
// accepts "//evil.com", "%2F%2Fevil.com", "https://evil.com"
String url = request.getParameter("url");
response.sendRedirect(url);

// GOOD: All rules are applied
public static String parseRelativeUrl(String input) {
    if (input == null || input.isEmpty()) {
        throw new IllegalArgumentException("URL must not be null or empty.");
    }

    // Rule: recursively URL-decode to defeat encoding bypass attempts (%2F%2F, etc.)
    final int MAX_DECODE_ITERATIONS = 4;
    String decoded = input;
    String previous;
    int iterations = 0;
    do {
        if (iterations++ >= MAX_DECODE_ITERATIONS) {
            throw new IllegalArgumentException("URL decoding exceeded maximum iteration threshold (" + MAX_DECODE_ITERATIONS + ").");
        }
        previous = decoded;
        decoded = URLDecoder.decode(previous, StandardCharsets.UTF_8);
    } while (!decoded.equals(previous));

    // Rule: decoded value must start with slash, letter, number, dash, or underscore
    if (!decoded.matches("^[/a-zA-Z0-9\\-_].*")) {
        throw new IllegalArgumentException("URL must start with a slash, letter, number, dash, or underscore.");
    }

    // Rule: must not start with "//" (protocol relative reference)
    if (decoded.startsWith("//")) {
        throw new IllegalArgumentException("URL must not be a protocol relative reference (must not start with '//').");
    }

    // Rule: must be a valid URI per RFC 3986
    URI uri;
    try {
        uri = new URI(decoded);
    } catch (URISyntaxException e) {
        throw new IllegalArgumentException("URL is not a valid RFC 3986 URI: " + e.getMessage(), e);
    }

    // Rule: must not be an absolute URL (i.e. must have no scheme)
    if (uri.isAbsolute()) {
        throw new IllegalArgumentException("URL must not be absolute (must not have a scheme like \"https://\").");
    }

    return decoded;
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] The input data is recursively URL decoded prior to be validated, with a maximum of 4 decode iterations enforced and an error raised if the threshold is reached.
- [ ] The decoded URL starts with a slash, letter, number, dash, or underscore.
- [ ] The input data is valid according to the RFC 3986.
- [ ] The URL is not an absolute one.
- [ ] The URL do not start with `//`.

## References

- [Unvalidated Redirects and Forwards Cheat Sheet from OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).
- [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986).
- [WHATWG URL Living Standard](https://url.spec.whatwg.org/).
- [Absolute URLs vs. relative URLs](https://developer.mozilla.org/en-US/docs/Learn_web_development/Howto/Web_mechanics/What_is_a_URL#absolute_urls_vs._relative_urls).
- [CWE Open Redirect](https://cwe.mitre.org/data/definitions/601.html).
