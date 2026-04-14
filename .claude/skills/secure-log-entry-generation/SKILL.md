---
name: secure-log-entry-generation
description: Generate secure log entry generation code. Enforces secure generation of code generating a log entry. Invoke when writing any log entry generation related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure Log Entry Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to generation of a log entry.

## 1. Log entry generation (CRITICAL)

- ALWAYS ensure when the user-controlled information is used to create the log entry then any HTML tag in the value is entities encoded.
- ALWAYS ensure when the user-controlled information is used to create the log entry then any `\r`, `\n`, `\u2028` (Unicode LINE SEPARATOR) or `\u2029` (Unicode PARAGRAPH SEPARATOR) character in the value is removed.
- ALWAYS ensure when the user-controlled information is used to create the log entry then any ANSI escape sequence in the value is removed.
- ALWAYS ensure when the user-controlled information is used to create the log entry then limit the maximum length of the user-controlled information to 100 characters.

```java
// BAD: No validation is applied
String userControlledContent = request.getParameter("input");
Logger logger                = Logger.getLogger(Main.class.getName());
logger.info(userControlledContent);

// GOOD: All points are applied
public class LogHelper {

    private static final int MAX_USER_INPUT_LENGTH = 100;

    private static String sanitize(String value) {
        if (value == null) return "null";

        // Rule 1: HTML-encode special characters (prevent markup injection)
        value = value.replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;")
                     .replace("\"", "&quot;")
                     .replace("'", "&#x27;");

        // Rule 2: Remove line-break characters (prevent log forging)
        value = value.replace("\r", "")
                     .replace("\n", "")
                     .replace("\u2028", "")  // Unicode LINE SEPARATOR
                     .replace("\u2029", ""); // Unicode PARAGRAPH SEPARATOR

        // Rule 3: Remove ANSI escape sequences (prevent terminal escape injection)
        value = value.replaceAll("\u001B\\[[\\d;]*[a-zA-Z]", "") // strip CSI sequences
                     .replace("\u001B", "");                      // strip bare ESC

        // Rule 4: Truncate to maximum allowed length (prevent log flooding)
        if (value.length() > MAX_USER_INPUT_LENGTH) {
            value = value.substring(0, MAX_USER_INPUT_LENGTH) + "[TRUNCATED]";
        }

        return value;
    }

    public static void logUserInput(String userControlledContent) {
        Logger logger = Logger.getLogger(LogHelper.class.getName());
        logger.info(sanitize(userControlledContent));
    }
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] Any HTML tags are entities encoded.
- [ ] Any `\r`, `\n`, `\u2028` or `\u2029` character is removed.
- [ ] Any ANSI escape sequence is removed.
- [ ] User-controlled information is constrained to 100 characters maximum.

## References

- [Log forging explanation by Fortify](https://vulncat.fortify.com/en/weakness?q=log%20forging).
- [Log forging explanation by Snyk](https://learn.snyk.io/lesson/logging-vulnerabilities/?ecosystem=java).
- [Logging Cheat Sheet by OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).