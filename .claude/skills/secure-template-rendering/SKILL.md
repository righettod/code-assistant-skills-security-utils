---
name: secure-template-rendering
description: Generate secure template rendering code. Enforces secure usage of template engines to create content. Invoke when writing any code that uses a template engine to generate content.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure Template Rendering Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to usage of templating to create content.

## 1. Server-side Template Injection Prevention (CRITICAL)

- ALWAYS load template content from a trusted, static source — NEVER use user-controlled data as the template source or structure.
- NEVER derive the template filename or path from user-controlled data.
- ALWAYS use the most safe configuration available for the template engine.
- ALWAYS enable output auto-escaping in the template engine to prevent XSS from rendered variables.

```java
// BAD #1a: The entire template is loaded from user-controlled input (SSTI — complete injection); default (unsafe) engine configuration is used; auto-escaping is not explicitly enabled
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
public String unsafeGenerateEmailContentSstiComplete(String userInput, Map<String, Object> templateData) throws IOException, TemplateException {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
    cfg.setDefaultEncoding("UTF-8");
    Template template = new Template("dynamic", new StringReader(userInput), cfg);
    StringWriter writer = new StringWriter();
    template.process(templateData, writer);
    return writer.toString();
}

// BAD #1b: User-controlled input is concatenated into the template string before rendering (SSTI — partial injection); a payload such as "${7*7}" in userInput is evaluated by the engine
public String unsafeGenerateEmailContentSstiPartial(String userInput, Map<String, Object> templateData) throws IOException, TemplateException {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
    cfg.setDefaultEncoding("UTF-8");
    // BAD: concatenating user input into the template string allows partial SSTI even when the rest of the template is static
    String templateStr = "Dear " + userInput + ", your order is ${orderId}.";
    Template template = new Template("dynamic", new StringReader(templateStr), cfg);
    StringWriter writer = new StringWriter();
    template.process(templateData, writer);
    return writer.toString();
}

// BAD #2: Templates are loaded from the filesystem and the template filename comes from user input — a path traversal payload such as "../../etc/passwd" can load arbitrary files outside the template directory
public String unsafeGenerateEmailContentTraversal(String templateName, Map<String, Object> templateData) throws IOException, TemplateException {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
    cfg.setDefaultEncoding("UTF-8");
    // BAD: filesystem loader combined with a user-controlled name enables path traversal
    cfg.setDirectoryForTemplateLoading(new File("/app/templates"));
    Template template = cfg.getTemplate(templateName);
    StringWriter writer = new StringWriter();
    template.process(templateData, writer);
    return writer.toString();
}

// BAD #3: Safe engine configuration is used and the template is loaded from a trusted source, but auto-escaping is explicitly disabled — user-controlled data rendered into the template is not HTML-encoded, enabling XSS
public String unsafeGenerateEmailContentXss(Map<String, Object> templateData) throws IOException, TemplateException {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
    cfg.setDefaultEncoding("UTF-8");
    cfg.setClassForTemplateLoading(this.getClass(), "/templates");
    cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
    cfg.setAPIBuiltinEnabled(false);
    // BAD: auto-escaping is explicitly disabled — any user-controlled variable rendered in the template becomes an XSS vector
    cfg.setAutoEscapingPolicy(Configuration.DISABLE_AUTO_ESCAPING_POLICY);
    // BAD: .ftl extension does not enable auto-escaping by default
    Template template = cfg.getTemplate("email-content.ftl");
    StringWriter writer = new StringWriter();
    template.process(templateData, writer);
    return writer.toString();
}

// GOOD: Template content is loaded from a trusted classpath location using a hardcoded name; user input is only passed as data variables; auto-escaping is enabled; the engine is configured with the most restrictive (safe) settings
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.core.TemplateClassResolver;
public String safeGenerateEmailContent(Map<String, Object> templateData) throws IOException, TemplateException {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
    cfg.setDefaultEncoding("UTF-8");
    // Load templates from a trusted classpath location — path is never derived from user input
    cfg.setClassForTemplateLoading(this.getClass(), "/templates");
    // Prevent access to arbitrary Java classes from within templates (safe configuration)
    cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
    // Disable API access from templates
    cfg.setAPIBuiltinEnabled(false);
    // Explicitly enable HTML auto-escaping for all templates to prevent XSS from rendered variables
    cfg.setAutoEscapingPolicy(Configuration.ENABLE_IF_SUPPORTED_AUTO_ESCAPING_POLICY);
    // Template filename is hardcoded — never derived from user input
    // The .ftlh extension marks the template as HTML, activating the auto-escaping policy set above
    Template template = cfg.getTemplate("email-content.ftlh");
    StringWriter writer = new StringWriter();
    // User-controlled data is passed only as data variables — the template source is always a trusted static resource
    template.process(templateData, writer);
    return writer.toString();
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] Template content is loaded from a trusted, static source and user-controlled data is NOT used as the template source or structure.
- [ ] The template filename or path is NOT derived from user-controlled data.
- [ ] The most safe configuration available is used for the template engine.
- [ ] Output auto-escaping is enabled in the template engine to prevent XSS.

## References

- [Server-side template injection from PortSwigger](https://portswigger.net/web-security/server-side-template-injection).
- [Improper Neutralization of Special Elements Used in a Template Engine (CWE-1336) from MITRE](https://cwe.mitre.org/data/definitions/1336.html).
- [Cross-site scripting (XSS) prevention cheat sheet from OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- [Path traversal from PortSwigger](https://portswigger.net/web-security/file-path-traversal).
- [Improper Limitation of a Pathname to a Restricted Directory (CWE-22) from MITRE](https://cwe.mitre.org/data/definitions/22.html).