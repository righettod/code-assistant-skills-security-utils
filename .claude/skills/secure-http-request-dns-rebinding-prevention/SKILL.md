---
name: secure-http-request-dns-rebinding-prevention
description: Generate secure code for HTTP request preventing exposure to DNS rebinding attack. Enforces HTTP request not exposed to DNS rebinding attack. Invoke when writing HTTP request code that must only target public IP addresses.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure HTTP Request Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to performing an HTTP request.

## 1. DNS rebinding prevention (CRITICAL)

- ALWAYS reject any URL whose scheme is not http or https.
- ALWAYS ensure that the resolved IP address of the domain is not a private or site-local one (covers RFC 1918 for IPv4 and fec0::/10 / fc00::/7 for IPv6).
- ALWAYS ensure that the resolved IP address of the domain is not a multicast one.
- ALWAYS ensure that the resolved IP address of the domain is not a link-local one.
- ALWAYS ensure that the resolved IP address of the domain is not a loopback one.
- ALWAYS ensure that the resolved IP address of the domain is not a wildcard/any-local one (0.0.0.0 for IPv4 or :: for IPv6).
- ALWAYS use the validated IP V4 or V6 address for the HTTP request.
- ALWAYS disable automatic redirect following so that a redirect response cannot bypass the resolved-IP validation.
- ALWAYS specify a request timeout; default to 10 seconds.

```java
// BAD: No validation is performed for any points
public static String badCall(String targetUrl) throws Exception {
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest request = HttpRequest.newBuilder().uri(URI.create(targetUrl)).GET().build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    return response.body();
}

// GOOD: All the points are validated
public static String goodCall(String targetUrl) throws Exception {
    URI uri = URI.create(targetUrl);

    // Rule 1: Reject any scheme that is not http or https
    String scheme = uri.getScheme();
    if (scheme == null || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
        throw new SecurityException("Blocked scheme: " + scheme);
    }

    String host = uri.getHost();
    if (host == null || host.isBlank()) {
        throw new SecurityException("Missing or blank hostname.");
    }

    InetAddress chosen = null;
    for (InetAddress address : InetAddress.getAllByName(host)) {
        // Rules 2–6: Reject private/site-local, multicast, link-local, loopback, and any-local addresses
        if (address.isLoopbackAddress() || address.isSiteLocalAddress() || address.isLinkLocalAddress() || address.isAnyLocalAddress() || address.isMulticastAddress()) {
            throw new SecurityException("Blocked non-public address: " + address.getHostAddress());
        }
        // Rule 2 (cont.): isSiteLocalAddress() covers fec0::/10 for IPv6 but not fc00::/7; check the unique-local range explicitly
        if (address instanceof Inet6Address) {
            byte[] bytes = address.getAddress();
            if ((bytes[0] & 0xFE) == 0xFC) {
                throw new SecurityException("Blocked IPv6 unique-local address: " + address.getHostAddress());
            }
        }
        if (chosen == null || (!(chosen instanceof Inet4Address) && address instanceof Inet4Address)) {
            chosen = address;
        }
    }

    if (chosen == null) {
        throw new SecurityException("Could not resolve hostname: " + host);
    }

    // Rule 7: Build the request URI from the validated IP address, not the hostname
    int port = uri.getPort();
    String ipLiteral = chosen instanceof Inet6Address ? "[" + chosen.getHostAddress() + "]" : chosen.getHostAddress();

    URI resolvedUri = new URI(scheme, null, ipLiteral, port, uri.getPath(), uri.getQuery(), uri.getFragment());

    // Rule 8: Disable automatic redirects to prevent bypass via redirect to a private address
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER).build();

    // Rule 9: Set a request timeout to prevent indefinite blocking (default: 10 seconds)
    HttpRequest request = HttpRequest.newBuilder().uri(resolvedUri).timeout(Duration.ofSeconds(10)).header("Host", port != -1 ? host + ":" + port : host).GET().build();

    return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] The URL scheme is http or https; any other scheme is rejected.
- [ ] The resolved IP address is not a private, site-local, or IPv6 unique-local address (RFC 1918 for IPv4; fec0::/10 and fc00::/7 for IPv6).
- [ ] The resolved IP address is not a multicast address.
- [ ] The resolved IP address is not a link-local address.
- [ ] The resolved IP address is not a loopback address.
- [ ] The resolved IP address is not a wildcard/any-local address (0.0.0.0 for IPv4 or :: for IPv6).
- [ ] The validated IP V4 or V6 address is used directly when performing the HTTP request.
- [ ] Automatic redirect following is disabled so that a redirect response cannot bypass the resolved-IP validation.
- [ ] A request timeout is set; default is 10 seconds.

## References

- [Server-Side Request Forgery Prevention Cheat Sheet from OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Server-side request forgery (SSRF) from PortSwigger](https://portswigger.net/web-security/ssrf)
- [DNS Rebinding (CAPEC-275) from MITRE](https://capec.mitre.org/data/definitions/275.html)
- [DNS Rebinding from Wikipedia](https://en.wikipedia.org/wiki/DNS_rebinding).
- [DNS rebinding attacks explained from GitHub Security Blog](https://github.blog/security/application-security/dns-rebinding-attacks-explained-the-lookup-is-coming-from-in-side-the-house/)
- [DNS Rebinding explanation from Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/what-is-dns-rebinding)
- [RFC 1918 - Address Allocation for Private Internets from IETF](https://datatracker.ietf.org/doc/html/rfc1918)