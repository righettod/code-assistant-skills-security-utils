---
name: secure-xml-parsing
description: Generate secure XML parsing code. Enforces secure parsing of XML content. Invoke when writing any XML parsing related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure XML parsing Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to xml content parsing.

## 1. XXE / DTD / XInclude / Internal Entity Prevention (CRITICAL)

- ALWAYS disable resolution of Document Type Definition (DTD).
- ALWAYS disable resolution of XML External Entity.
- ALWAYS disable expansion/replacement of XML Internal Entity.
- ALWAYS disable XInclude support.

```java
// BAD: DTD and External Entities are resolved / Internal Entities are replaced / XInclude support is left to default configuration
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new File("data.xml"));

// GOOD: DTD and External Entities are not resolved / Internal Entities are not replaced / XInclude support is explicitly disabled
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
// Disable DTD resolution entirely
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
//Disable XML External Entity (XXE) resolution
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
//Disable replacement of XML Internal Entities
factory.setExpandEntityReferences(false);
// Process namespaces safely
factory.setXIncludeAware(false);
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new File("data.xml"));
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] DTD resolution is NOT enabled.
- [ ] External Entities (general and parameter) are NOT resolved.
- [ ] Internal Entities are NOT replaced.
- [ ] XInclude support is explicitly disabled.

## References

- [XXE Prevention Cheat Sheet from OWASP](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html).
- [XML external entity (XXE) injection from PortSwigger](https://portswigger.net/web-security/xxe).