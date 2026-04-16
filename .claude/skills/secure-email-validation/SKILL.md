---
name: secure-email-validation
description: Generate secure email address validation code. Enforces secure generation of code validating an email address. Invoke when writing any email address validation related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure Email Address Validation Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to validation of an email address.

## 1. Email address validation (CRITICAL)

- ALWAYS ensure that the email address is a valid email address, from a parser perspective, following RFCs on email addresses.
- ALWAYS ensure that the email address is not using "Encoded-word" format.
- ALWAYS ensure that the email address is not using comment format.
- ALWAYS ensure that the email address is not using "Punycode" format.
- ALWAYS ensure that the email address is not using UUCP style addresses.
- ALWAYS ensure that the email address is not using address literals.
- ALWAYS ensure that the email address is not using source routes.
- ALWAYS ensure that the email address is not using the "percent hack".
- ALWAYS enforce RFC 5321 length limits: local part ≤ 64 characters, domain ≤ 255 characters, total address ≤ 320 characters.
- ALWAYS ensure that the email address does not contain newline or carriage-return characters (CRLF injection prevention).
- ALWAYS ensure that the domain part contains at least one dot (reject single-label domains such as localhost or internal hostnames).
- ALWAYS ensure that the local part is not a quoted string (i.e. not wrapped in double quotes).

```java
// BAD: No validation is applied
import jakarta.mail.internet.InternetAddress;

public static InternetAddress readEmailInsecure(String address) throws AddressException {
    return new InternetAddress(address);
}

// GOOD: All points are applied
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;

public static InternetAddress readEmailSecure(String email) throws AddressException {
    if (email == null || email.isBlank()) {
        throw new AddressException("Email address must not be null or blank");
    }

    // 1. Parse and validate via RFC-compliant parser
    InternetAddress address = new InternetAddress(email, true);
    address.validate();

    String raw = address.getAddress();

    // 2. No encoded-word format: =?charset?encoding?text?=
    if (email.contains("=?") && email.contains("?=")) {
        throw new AddressException("Encoded-word format is not allowed: " + email);
    }

    // 3. No comment format: parentheses ( )
    if (raw.contains("(") || raw.contains(")")) {
        throw new AddressException("Comment format is not allowed: " + email);
    }

    // 4. No Punycode format: xn-- in domain
    String domain = raw.substring(raw.lastIndexOf('@') + 1);
    if (domain.toLowerCase().contains("xn--")) {
        throw new AddressException("Punycode format is not allowed: " + email);
    }

    // 5. No UUCP style addresses: bang paths using !
    if (raw.contains("!")) {
        throw new AddressException("UUCP-style addresses are not allowed: " + email);
    }

    // 6. No address literals: domain in square brackets [...]
    if (domain.startsWith("[") && domain.endsWith("]")) {
        throw new AddressException("Address literals are not allowed: " + email);
    }

    // 7. No source routes: input starts with @ (e.g. @relay:user@domain or @r1,@r2:user@domain)
    if (email.startsWith("@")) {
        throw new AddressException("Source routes are not allowed: " + email);
    }

    // 8. No percent hack: % in the local part
    String localPart = raw.substring(0, raw.lastIndexOf('@'));
    if (localPart.contains("%")) {
        throw new AddressException("Percent hack is not allowed: " + email);
    }

    // 9. RFC 5321 length limits
    if (localPart.length() > 64) {
        throw new AddressException("Local part exceeds 64 characters: " + email);
    }
    if (domain.length() > 255) {
        throw new AddressException("Domain exceeds 255 characters: " + email);
    }
    if (raw.length() > 320) {
        throw new AddressException("Email address exceeds 320 characters: " + email);
    }

    // 10. No CRLF injection: newline or carriage-return characters
    if (email.contains("\n") || email.contains("\r")) {
        throw new AddressException("Newline characters are not allowed: " + email);
    }

    // 11. No single-label domain: domain must contain at least one dot
    if (!domain.contains(".")) {
        throw new AddressException("Single-label domains are not allowed: " + email);
    }

    // 12. No quoted local part: local part must not be wrapped in double quotes
    if (localPart.startsWith("\"") && localPart.endsWith("\"")) {
        throw new AddressException("Quoted local parts are not allowed: " + email);
    }

    return address;
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] The email address is a valid email address, from a parser perspective, following RFCs on email addresses.
- [ ] The email address is not using "Encoded-word" format.
- [ ] The email address is not using comment format.
- [ ] The email address is not using "Punycode" format.
- [ ] The email address is not using UUCP style addresses.
- [ ] The email address is not using address literals.
- [ ] The email address is not using source routes.
- [ ] The email address is not using the "percent hack".
- [ ] The local part is ≤ 64 characters, the domain is ≤ 255 characters, and the total address is ≤ 320 characters (RFC 5321).
- [ ] The email address does not contain newline or carriage-return characters.
- [ ] The domain part contains at least one dot (no single-label domains).
- [ ] The local part is not a quoted string (not wrapped in double quotes).

## References

- [Research on email address parser bypass from PortSwigger](https://portswigger.net/research/splitting-the-email-atom).
- [MIME (Multipurpose Internet Mail Extensions) part three:Message Header extensions for Non-ASCII text from IETF](https://datatracker.ietf.org/doc/html/rfc2047).
- [Syntax of encoded-words from IETF](https://datatracker.ietf.org/doc/html/rfc2047#section-2).
- [Anatomy of an email address from Jochen Topf](https://www.jochentopf.com/email/address.html).
- [Email address from Wikipedia](https://en.wikipedia.org/wiki/Email_address).
- [RFC 5321 - Simple Mail Transfer Protocol (size limits) from IETF](https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.3).