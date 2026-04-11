---
name: safe-pdf-validation
description: Generate secure pdf file validation code. Enforces secure generation of code validating a pdf file. Invoke when writing any pdf file validation related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure PDF File Validation Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to validation of a PDF file.

## 1. PDF file validation (CRITICAL)

- ALWAYS ensure that the file is a real PDF file.
- ALWAYS ensure that the PDF file has no file attached.
- ALWAYS ensure that the PDF file has no XML Forms Architecture (XFA) form embedded.
- ALWAYS ensure that the PDF file has no JavaScript embedded.
- ALWAYS ensure that the PDF file has no links of type `Launch`, `GoToR` or `ImportData`.
- ALWAYS ensure that the PDF file has no content appended at the end of the PDF structure (concatenated file).

```java
// BAD: No validation is applied
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
try (PDDocument document = Loader.loadPDF(file)) {
    PDFTextStripper stripper = new PDFTextStripper();
    String text = stripper.getText(document);
    System.out.println(text);
}

// GOOD: All points are validated
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.interactive.action.*;
import org.apache.pdfbox.pdmodel.interactive.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class PdfSecurityValidator {

    public static void main(String[] args) throws IOException {
        File file = new File("document.pdf");
        List<String> violations = validate(file);

        if (violations.isEmpty()) {
            System.out.println("✅ PDF passed all security checks.");
        } else {
            System.out.println("❌ PDF failed security checks:");
            violations.forEach(v -> System.out.println("  - " + v));
        }
    }

    public static List<String> validate(File file) throws IOException {
        List<String> violations = new ArrayList<>();

        // ── Rule 1: Real PDF ──────────────────────────────────────────────────
        byte[] header = new byte[5];
        try (InputStream is = new FileInputStream(file)) {
            if (is.read(header) < 5 || !new String(header).startsWith("%PDF-")) {
                violations.add("File is not a valid PDF (missing %PDF- header).");
                return violations; // Can't parse further
            }
        }

        try (PDDocument document = Loader.loadPDF(file)) {
            PDDocumentCatalog catalog = document.getDocumentCatalog();

            // ── Rule 2: No embedded file attachments ──────────────────────────
            PDDocumentNameDictionary names = catalog.getNames();
            if (names != null) {
                PDEmbeddedFilesNameTreeNode embeddedFiles = names.getEmbeddedFiles();
                if (embeddedFiles != null) {
                    try {
                        Map<String, ?> files = embeddedFiles.getNames();
                        if (files != null && !files.isEmpty())
                            violations.add("PDF contains " + files.size() + " embedded file attachment(s): " + files.keySet());
                    } catch (IOException ignored) {}
                    try {
                        if (embeddedFiles.getKids() != null && !embeddedFiles.getKids().isEmpty())
                            violations.add("PDF contains embedded file attachments (in name tree subtree).");
                    } catch (Exception ignored) {}
                }
            }

            // ── Rule 3: No XFA form ───────────────────────────────────────────
            PDAcroForm acroForm = catalog.getAcroForm();
            if (acroForm != null) {
                COSBase xfa = acroForm.getCOSObject().getDictionaryObject(COSName.getPDFName("XFA"));
                if (xfa != null)
                    violations.add("PDF contains an embedded XFA (XML Forms Architecture) form.");
            }

            // ── Rule 4 & 5: No JavaScript / No forbidden link actions ─────────
            Set<String> forbiddenActions = Set.of("Launch", "GoToR", "ImportData");

            // Document-level: Names/JavaScript tree
            if (names != null && names.getJavaScript() != null) {
                PDJavascriptNameTreeNode jsTree = names.getJavaScript();
                try {
                    Map<String, ?> scripts = jsTree.getNames();
                    if (scripts != null && !scripts.isEmpty())
                        violations.add("PDF contains " + scripts.size() + " document-level JavaScript action(s).");
                    else
                        violations.add("PDF contains document-level JavaScript (in name tree).");
                } catch (IOException ignored) {
                    violations.add("PDF contains document-level JavaScript (in name tree).");
                }
            }

            // Document-level: OpenAction
            COSBase openAction = catalog.getCOSObject().getDictionaryObject(COSName.OPEN_ACTION);
            String jsInOpenAction = findAction(openAction, Set.of("JavaScript"), forbiddenActions);
            if (jsInOpenAction != null)
                violations.add("PDF contains a forbidden action in OpenAction: " + jsInOpenAction);

            // Page-level: AA, annotations
            for (PDPage page : document.getPages()) {
                COSDictionary pageDict = page.getCOSObject();

                String jsInAA = findAction(pageDict.getDictionaryObject(COSName.getPDFName("AA")), Set.of("JavaScript"), forbiddenActions);
                if (jsInAA != null)
                    violations.add("PDF contains a forbidden action in page AA entry: " + jsInAA);

                try {
                    for (PDAnnotation annotation : page.getAnnotations()) {
                        COSDictionary annot = annotation.getCOSObject();

                        // Page-level file attachment annotations (Rule 2)
                        if (annotation instanceof PDAnnotationFileAttachment)
                            violations.add("PDF contains a page-level file attachment annotation.");

                        // Check annotation actions (Rules 4 & 5)
                        for (COSName key : List.of(COSName.A, COSName.getPDFName("AA"))) {
                            String found = findAction(annot.getDictionaryObject(key), Set.of("JavaScript"), forbiddenActions);
                            if (found != null)
                                violations.add("PDF contains a forbidden action (" + found + ") in annotation on page.");
                        }
                    }
                } catch (IOException ignored) {}
            }
        }

        // ── Rule 6: No content appended after %%EOF ───────────────────────────
        byte[] content = Files.readAllBytes(file.toPath());
        String raw = new String(content, java.nio.charset.StandardCharsets.ISO_8859_1);
        int lastEof = raw.lastIndexOf("%%EOF");
        if (lastEof == -1) {
            violations.add("PDF has no %%EOF marker — file may be corrupt or truncated.");
        } else {
            String tail = raw.substring(lastEof + 5).stripTrailing();
            if (!tail.isEmpty())
                violations.add("PDF has " + tail.length() + " unexpected byte(s) after %%EOF — possible concatenated/appended content.");
        }

        return violations;
    }

    /**
     * Recursively walks a COSBase action (or AA dictionary / COSArray of actions)
     * and returns the action subtype name if it matches any of the provided sets,
     * or null if no match is found.
     *
     * @param base            the action or AA entry to inspect
     * @param jsTypes         action S values considered JavaScript (e.g. "JavaScript")
     * @param forbiddenTypes  action S values that are forbidden links
     */
    private static String findAction(COSBase base, Set<String> jsTypes, Set<String> forbiddenTypes) {
        if (base instanceof COSDictionary dict) {
            COSBase s = dict.getDictionaryObject(COSName.S);
            if (s instanceof COSName name) {
                if (jsTypes.contains(name.getName()) || forbiddenTypes.contains(name.getName()))
                    return name.getName();
            }
            // Recurse into AA sub-entries (e.g. /O, /C, /F, /Bl, /D, /U, /Fo, /Bl, /PC, /PO, /PV)
            for (COSName key : dict.keySet()) {
                if (!key.equals(COSName.S) && !key.equals(COSName.TYPE)) {
                    String found = findAction(dict.getDictionaryObject(key), jsTypes, forbiddenTypes);
                    if (found != null) return found;
                }
            }
            // Recurse into chained Next action
            String next = findAction(dict.getDictionaryObject(COSName.NEXT), jsTypes, forbiddenTypes);
            if (next != null) return next;
        }
        if (base instanceof COSArray array) {
            for (COSBase item : array) {
                String found = findAction(item, jsTypes, forbiddenTypes);
                if (found != null) return found;
            }
        }
        return null;
    }
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] The file is a real PDF file.
- [ ] The PDF file has no file attached.
- [ ] The PDF file has no XML Forms Architecture (XFA) form embedded.
- [ ] The PDF file has no JavaScript embedded.
- [ ] The PDF file has no links of type `Launch`, `GoToR` or `ImportData`.
- [ ] The PDF file has no content appended at the end of the PDF structure (concatenated file).

## References

- [XML Forms Architecture information from Wikipedia](https://en.wikipedia.org/wiki/XFA).
- [Malicious PDF generator project on GitHub](https://github.com/jonaslejon/malicious-pdf).
- [Example of CVE affecting a pdf parser](https://nvd.nist.gov/vuln/detail/CVE-2025-54988).