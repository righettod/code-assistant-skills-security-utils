---
name: secure-microsoft-word-validation
description: Generate secure microsoft word file validation code. Enforces secure generation of code validating a microsoft word file. Invoke when writing any microsoft word file validation related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure Microsoft Word File Validation Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to validation of a Microsoft Word file.

## 1. Microsoft Word file validation (CRITICAL)

- ALWAYS ensure that the file is a real Microsoft Word file.
- ALWAYS ensure that the file use the standard named `Office Open XML`.
- ALWAYS ensure that the file use the file type named `DOCX`.
- ALWAYS ensure that the file has a single extension and is `docx`.
- ALWAYS ensure that the file size does not exceed 5 megabytes before opening or parsing it.
- ALWAYS ensure that the file has no Visual Basic for Application (VBA) macros.
- ALWAYS ensure that the file has no Object Linking and Embedding (OLE) package.

```java
// BAD: No validation is applied
import org.apache.poi.xwpf.usermodel.*;
import java.io.*;
import java.util.List;

public class UnsafeReadWordFile {
    public static void main(String[] args) {
        String filePath = "document.docx";
        try (FileInputStream fis = new FileInputStream(filePath);
             XWPFDocument document = new XWPFDocument(fis)) {
            // Read all paragraphs
            List<XWPFParagraph> paragraphs = document.getParagraphs();
            for (XWPFParagraph paragraph : paragraphs) {
                System.out.println(paragraph.getText());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// GOOD: All points are validated
import org.apache.poi.openxml4j.opc.*;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.xwpf.usermodel.*;
import java.io.*;

public class SafeWordFileReader {

    public static void main(String[] args) {
        try {
            File file = new File("document.docx");

            // ── CHECK 1: Single extension and must be "docx" ──────────────────
            String name = file.getName();
            int dotCount = name.length() - name.replace(".", "").length();
            if (dotCount != 1) {
                throw new SecurityException(
                    "File must have exactly one extension. Found: " + name);
            }
            if (!name.toLowerCase().endsWith(".docx")) {
                throw new SecurityException(
                    "File extension must be '.docx'. Found: " + name);
            }

            // ── CHECK 2: File size must not exceed 5 MB ───────────────────────
            long maxSizeBytes = 5L * 1024 * 1024;
            if (file.length() > maxSizeBytes) {
                throw new SecurityException(
                    "File size exceeds the maximum allowed size of 5 MB. " +
                    "Found: " + file.length() + " bytes.");
            }

            // ── CHECK 3: Office Open XML magic bytes (PK\x03\x04) ─────────────
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] header = new byte[4];
                int bytesRead = fis.read(header);
                if (bytesRead < 4
                        || header[0] != 0x50
                        || header[1] != 0x4B
                        || header[2] != 0x03
                        || header[3] != 0x04) {
                    throw new SecurityException(
                        "File is not a valid Office Open XML (OOXML/ZIP) file. " +
                        "Magic bytes do not match PK\\x03\\x04.");
                }
            }

            // ── CHECK 4: Real DOCX (contains word/document.xml) ───────────────
            // ── CHECK 5: No VBA macros (no word/vbaProject.bin) ───────────────
            // ── CHECK 6: No embedded OLE/ActiveX objects ──────────────────────
            String oleObjectUri = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject";
            String activeXUri = "http://schemas.microsoft.com/office/2006/relationships/activeX";

            try (OPCPackage pkg = OPCPackage.open(file)) {
                if (pkg.getPartsByName(
                        java.util.regex.Pattern.compile("/word/document\\.xml"))
                    .isEmpty()) {
                    throw new SecurityException(
                        "File does not contain 'word/document.xml'. " +
                        "It is not a valid DOCX file.");
                }

                if (!pkg.getPartsByName(
                        java.util.regex.Pattern.compile("(?i)/word/vbaProject\\.bin"))
                    .isEmpty()) {
                    throw new SecurityException(
                        "File contains a VBA macro project (vbaProject.bin). " +
                        "Macro-enabled documents (DOCM) are not allowed.");
                }

                for (PackagePart part : pkg.getParts()) {
                    for (PackageRelationship rel : part.getRelationships()) {
                        String relType = rel.getRelationshipType();
                        if (relType != null) {
                            String lower = relType.toLowerCase();
                            if (lower.startsWith(oleObjectUri.toLowerCase())
                                    || lower.startsWith(activeXUri.toLowerCase())) {
                                throw new SecurityException(
                                    "File contains an embedded OLE object in part: " +
                                    part.getPartName() + ". OLE packages are not allowed.");
                            }
                        }
                    }
                }
            }

            // ── CHECK 7: No raw OLE2 compound file (old .doc binary) ──────────
            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] header = new byte[8];
                if (fis.read(header) >= 4 && POIFSFileSystem.hasPOIFSHeader(header)) {
                    throw new SecurityException(
                        "File appears to be an OLE2 compound document (old .doc binary format). " +
                        "Only OOXML DOCX files are accepted.");
                }
            }

            // ── READ: Paragraphs and tables ────────────────────────────────────
            try (FileInputStream fis = new FileInputStream(file);
                 XWPFDocument document = new XWPFDocument(fis)) {

                System.out.println("=== Paragraphs ===");
                for (XWPFParagraph para : document.getParagraphs()) {
                    if (!para.getText().isBlank()) {
                        System.out.println(para.getText());
                    }
                }

                System.out.println("\n=== Tables ===");
                for (XWPFTable table : document.getTables()) {
                    for (XWPFTableRow row : table.getRows()) {
                        for (XWPFTableCell cell : row.getTableCells()) {
                            System.out.print(cell.getText() + "\t");
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

- [ ] The file is a real Microsoft Word file.
- [ ] The file use the standard named `Office Open XML`.
- [ ] The file use the file type named `DOCX`.
- [ ] The file has a single extension and is `docx`.
- [ ] The file size does not exceed 5 megabytes.
- [ ] The file has no Visual Basic for Application (VBA) macros.
- [ ] The file has no Object Linking and Embedding (OLE) package.

## References

- [ECMA-376 - Office Open XML file formats](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [Learn about file formats](https://support.microsoft.com/en-us/office/learn-about-file-formats-56dc3b55-7681-402e-a727-c59fa0884b30).
- [Linked objects and embedded objects](https://support.microsoft.com/en-au/office/linked-objects-and-embedded-objects-0bf81db2-8aa3-4148-be4a-c8b6e55e0d7c).
- [Open XML Formats and file name extensions](https://support.microsoft.com/en-us/office/open-xml-formats-and-file-name-extensions-5200d93c-3449-4380-8e11-31ef14555b18).
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
- [MITRE ATT&CK T1059.005 - Visual Basic](https://attack.mitre.org/techniques/T1059/005/).
- [MITRE ATT&CK T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/).
- [Microsoft: Macros from the internet are blocked by default](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked).