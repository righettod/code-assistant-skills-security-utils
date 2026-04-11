---
name: secure-csv-generation
description: Generate secure Comma Separated Values (CSV) generation code. Enforces secure generation of Comma Separated Values (CSV) content. Invoke when writing any Comma Separated Values (CSV) generation related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure Comma Separated Values (CSV) Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to Comma Separated Values (CSV) content generation.

## 1. CSV injection Prevention (CRITICAL)

- ALWAYS ensure that if any field value start with one of the following character `=`, `+`, `-`, `@`, `\t`, `\r` then a single quote is added at the beginning of the value to disable the CSV injection.

```java
// BAD: Content of fields are not validated to detect and disable any CSV injection
  try (PrintWriter writer = new PrintWriter(new FileWriter(filePath))) {
          for (String[] row : rows) {
              StringBuilder sb = new StringBuilder();
              for (int i = 0; i < row.length; i++) {
                  String field = row[i] == null ? "" : row[i];
                  if (field.contains(",") || field.contains("\"") || field.contains("\n"))
                      field = "\"" + field.replace("\"", "\"\"") + "\"";
                  if (i > 0) sb.append(",");
                  sb.append(field);
              }
              writer.println(sb);
          }
      }

// GOOD: Dangerous characters used in CSV injection are prefixed to disable the injection
  try (PrintWriter writer = new PrintWriter(new FileWriter(filePath))) {
            for (String[] row : rows) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < row.length; i++) {
                    String field = row[i] == null ? "" : row[i];

                    // Prepend single quote to disable CSV injection
                    if (!field.isEmpty() && "=+-@\t\r".indexOf(field.charAt(0)) >= 0)
                        field = "'" + field;

                    if (field.contains(",") || field.contains("\"") || field.contains("\n"))
                        field = "\"" + field.replace("\"", "\"\"") + "\"";

                    if (i > 0) sb.append(",");
                    sb.append(field);
                }
                writer.println(sb);
            }
        }
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] Dangerous characters used in CSV injection are detected and then prefixed to disable the injection.

## References

- [CSV injection information from WE45](https://www.we45.com/post/your-excel-sheets-are-not-safe-heres-how-to-beat-csv-injection).
- [CSV injection information from OWASP](https://owasp.org/www-community/attacks/CSV_Injection).