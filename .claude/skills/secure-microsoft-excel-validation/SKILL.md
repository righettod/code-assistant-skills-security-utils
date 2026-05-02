---
name: secure-microsoft-excel-validation
description: Generate secure microsoft excel file validation code. Enforces secure generation of code validating a microsoft excel file. Invoke when writing any microsoft excel file validation related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure Microsoft Excel File Validation Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to validation of a Microsoft Excel file.

## 1. Microsoft Excel file validation (CRITICAL)

- ALWAYS ensure that the file is a real Microsoft Excel file.
- ALWAYS ensure that the file use the standard named `Office Open XML`.
- ALWAYS ensure that the file use the file type named `XLSX`.
- ALWAYS ensure that the file has a single extension and is `xlsx`.
- ALWAYS ensure that the file size does not exceed 5 megabytes before opening or parsing it.
- ALWAYS ensure that the total uncompressed size of all ZIP entries does not exceed 50 megabytes before opening or parsing it.
- ALWAYS ensure that the file has no Visual Basic for Application (VBA) macros.
- ALWAYS ensure that the file has no Object Linking and Embedding (OLE) package.
- ALWAYS ensure that the file has no external data connections.
- ALWAYS ensure that the file has no external links.

```java
// BAD: No validation is applied
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.*;
import java.io.*;

public class UnsafeReadExcelFile {
    public static void main(String[] args) {
        try (FileInputStream fis = new FileInputStream("spreadsheet.xlsx");
             XSSFWorkbook workbook = new XSSFWorkbook(fis)) {
            XSSFSheet sheet = workbook.getSheetAt(0);
            for (Row row : sheet) {
                for (Cell cell : row) {
                    System.out.print(cell + "\t");
                }
                System.out.println();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// GOOD: All points are validated
import org.apache.poi.openxml4j.opc.*;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.*;
import java.io.*;

public class SafeExcelFileReader {

    public static void main(String[] args) {
        try {
            File file = new File("spreadsheet.xlsx");

            // ── CHECK 1: Single extension and must be "xlsx" ──────────────────
            String name = file.getName();
            int dotCount = name.length() - name.replace(".", "").length();
            if (dotCount != 1) {
                throw new SecurityException("File must have exactly one extension. Found: " + name);
            }
            if (!name.toLowerCase().endsWith(".xlsx")) {
                throw new SecurityException("File extension must be '.xlsx'. Found: " + name);
            }

            // ── CHECK 2: File size must not exceed 5 MB ───────────────────────
            long maxSizeBytes = 5L * 1024 * 1024;
            if (file.length() > maxSizeBytes) {
                throw new SecurityException("File size exceeds the maximum allowed size of 5 MB. Found: " + file.length() + " bytes.");
            }

            // ── CHECK 3: Office Open XML magic bytes (PK\x03\x04) ─────────────
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] header = new byte[4];
                int bytesRead = fis.read(header);
                if (bytesRead < 4 || header[0] != 0x50 || header[1] != 0x4B || header[2] != 0x03 || header[3] != 0x04) {
                    throw new SecurityException("File is not a valid Office Open XML (OOXML/ZIP) file. Magic bytes do not match PK\\x03\\x04.");
                }
            }

            // ── CHECK 4: ZIP bomb — total uncompressed size must not exceed 50 MB ──
            long maxUncompressedBytes = 50L * 1024 * 1024;
            long totalUncompressedSize = 0;
            try (java.util.zip.ZipFile zip = new java.util.zip.ZipFile(file)) {
                java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zip.entries();
                while (entries.hasMoreElements()) {
                    java.util.zip.ZipEntry entry = entries.nextElement();
                    long entrySize = entry.getSize();
                    if (entrySize > 0) {
                        totalUncompressedSize += entrySize;
                    }
                    if (totalUncompressedSize > maxUncompressedBytes) {
                        throw new SecurityException("File total uncompressed size exceeds the maximum allowed size of 50 MB. Possible ZIP bomb detected.");
                    }
                }
            }

            // ── CHECK 5: Real XLSX (contains xl/workbook.xml) ─────────────────
            // ── CHECK 6: No VBA macros (no xl/vbaProject.bin) ─────────────────
            // ── CHECK 7: No embedded OLE/ActiveX objects ──────────────────────
            // ── CHECK 8: No external data connections ─────────────────────────
            // ── CHECK 9: No external links ────────────────────────────────────
            String oleObjectUri = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject";
            String activeXUri = "http://schemas.microsoft.com/office/2006/relationships/activeX";

            try (OPCPackage pkg = OPCPackage.open(file)) {
                if (pkg.getPartsByName(java.util.regex.Pattern.compile("/xl/workbook\\.xml")).isEmpty()) {
                    throw new SecurityException("File does not contain 'xl/workbook.xml'. It is not a valid XLSX file.");
                }

                if (!pkg.getPartsByName(java.util.regex.Pattern.compile("(?i)/xl/vbaProject\\.bin")).isEmpty()) {
                    throw new SecurityException("File contains a VBA macro project (vbaProject.bin). Macro-enabled workbooks (XLSM) are not allowed.");
                }

                if (!pkg.getPartsByName(java.util.regex.Pattern.compile("(?i)/xl/connections\\.xml")).isEmpty()) {
                    throw new SecurityException("File contains external data connections (connections.xml). External data connections are not allowed.");
                }

                if (!pkg.getPartsByName(java.util.regex.Pattern.compile("(?i)/xl/externalLinks/.*")).isEmpty()) {
                    throw new SecurityException("File contains external links (externalLinks/). External links are not allowed.");
                }

                for (PackagePart part : pkg.getParts()) {
                    for (PackageRelationship rel : part.getRelationships()) {
                        String relType = rel.getRelationshipType();
                        if (relType != null) {
                            String lower = relType.toLowerCase();
                            if (lower.startsWith(oleObjectUri.toLowerCase()) || lower.startsWith(activeXUri.toLowerCase())) {
                                throw new SecurityException("File contains an embedded OLE object in part: " + part.getPartName() + ". OLE packages are not allowed.");
                            }
                        }
                    }
                }
            }

            // ── READ: Sheet data ───────────────────────────────────────────────
            try (FileInputStream fis = new FileInputStream(file);
                 XSSFWorkbook workbook = new XSSFWorkbook(fis)) {

                for (int i = 0; i < workbook.getNumberOfSheets(); i++) {
                    XSSFSheet sheet = workbook.getSheetAt(i);
                    System.out.println("=== Sheet: " + sheet.getSheetName() + " ===");
                    for (Row row : sheet) {
                        for (Cell cell : row) {
                            System.out.print(cell + "\t");
                        }
                        System.out.println();
                    }
                }
            }

        } catch (SecurityException e) {
            System.err.println("Security validation failed: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] The file is a real Microsoft Excel file.
- [ ] The file use the standard named `Office Open XML`.
- [ ] The file use the file type named `XLSX`.
- [ ] The file has a single extension and is `xlsx`.
- [ ] The file size does not exceed 5 megabytes.
- [ ] The total uncompressed size of all ZIP entries does not exceed 50 megabytes.
- [ ] The file has no Visual Basic for Application (VBA) macros.
- [ ] The file has no Object Linking and Embedding (OLE) package.
- [ ] The file has no external data connections.
- [ ] The file has no external links.

## References

- [ECMA-376 - Office Open XML file formats](https://ecma-international.org/publications-and-standards/standards/ecma-376/).
- [Learn about file formats](https://support.microsoft.com/en-us/office/learn-about-file-formats-56dc3b55-7681-402e-a727-c59fa0884b30).
- [Open XML Formats and file name extensions](https://support.microsoft.com/en-us/office/open-xml-formats-and-file-name-extensions-5200d93c-3449-4380-8e11-31ef14555b18).
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
- [MITRE ATT&CK T1059.005 - Visual Basic](https://attack.mitre.org/techniques/T1059/005/).
- [MITRE ATT&CK T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/).
- [MITRE ATT&CK T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/).
- [Microsoft: Macros from the internet are blocked by default](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked).
