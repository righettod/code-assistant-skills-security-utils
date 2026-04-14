---
name: secure-archive-decompression
description: Generate secure code for archive decompression. Enforces secure decompression of the content. Invoke when writing any archive decompression related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure Archive Decompression Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to archive content decompression whatever the format of the archive.

## 1. Path traversal / Zip bombing / Symlink / Hardlink attacks (CRITICAL)

- ALWAYS ensure that the name of a processed entry does not contains the pattern `../` or `..\` or start by `/`.
- ALWAYS verify the canonical output path starts with the destination directory (prevents encoded or OS-specific traversal bypasses).
- ALWAYS ensure that no entry is a symbolic link or hard link.
- ALWAYS ensure that the total number of decompressed entries is inferior or equal to 20.
- ALWAYS ensure that the maximum deepness of any entry is inferior or equal to 10.
- ALWAYS ensure that the total size of all decompressed entries is inferior or equal to 50 MB.
- ALWAYS ensure that the total size of a processed entry is inferior or equal to 10 MB.

```java
// BAD: No validation is performed for any points
String zipFilePath = "archive.zip";
File   destDir     = new File("/output");
try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath))) {
  ZipEntry entry;
  while ((entry = zis.getNextEntry()) != null) {
    File outFile = new File(destDir, entry.getName());
    if (entry.isDirectory()) 
    {
        outFile.mkdirs();
    } else
    {
      outFile.getParentFile().mkdirs();
      try (FileOutputStream fos = new FileOutputStream(outFile)) {
          byte[] buffer = new byte[4096];
          int len;
          while ((len = zis.read(buffer)) > 0) {
              fos.write(buffer, 0, len);
          }
      }
    }
    zis.closeEntry();
  }
}

// GOOD: All the points are validated
String zipFilePath     = "archive.zip";
File   destDir         = new File("/output");
int    entryCount      = 0;
long   totalSize       = 0;
int    MAX_ENTRIES     = 20;
int    MAX_DEPTH       = 10;
long   MAX_TOTAL_SIZE  = 50L * 1024 * 1024; // 50 MB
long   MAX_ENTRY_SIZE  = 10L * 1024 * 1024; // 10 MB
String canonicalDest   = destDir.getCanonicalPath();
try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath))) {
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
        String name = entry.getName();
        // ── Rule 1: no path traversal, no absolute paths ──────────────
        if (name.startsWith("/") || name.contains("../") || name.contains("..\\")) {
            throw new IOException("Illegal entry name: " + name);
        }
        // ── Rule 2: canonical path check (prevents encoded/OS-specific bypasses) ──
        File outFile = new File(destDir, name);
        String canonicalEntry = outFile.getCanonicalPath();
        if (!canonicalEntry.startsWith(canonicalDest + File.separator)) {
            throw new IOException("Path traversal detected: " + name);
        }
        // ── Rule 3: no symlinks or hard links ─────────────────────────
        if (Files.isSymbolicLink(outFile.toPath())) {
            throw new IOException("Symbolic link entry rejected: " + name);
        }
        // Note: the ZIP format has no hard-link entry type (unlike tar), so
        // ZipInputStream cannot create hard links during extraction. No runtime
        // check is required here; the symlink check above is sufficient for ZIP.
        // For tar-based formats use your library's API to detect LNKTYPE entries.
        // ── Rule 4: max number of entries ─────────────────────────────
        if (++entryCount > MAX_ENTRIES) {
            throw new IOException("Archive exceeds maximum entry count of " + MAX_ENTRIES);
        }
        // ── Rule 5: max directory depth ───────────────────────────────
        int depth = name.split("[/\\\\]").length;
        if (depth > MAX_DEPTH) {
            throw new IOException("Entry exceeds max depth of " + MAX_DEPTH + ": " + name);
        }
        if (entry.isDirectory()) {
            outFile.mkdirs();
            zis.closeEntry();
            continue;
        }
        outFile.getParentFile().mkdirs();
        // ── Rules 6 & 7: size limits ──────────────────────────────────
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            byte[] buffer    = new byte[4096];
            long   entrySize = 0;
            int    len;
            while ((len = zis.read(buffer)) > 0) {
                entrySize += len;
                totalSize += len;
                // Rule 7: single-entry size
                if (entrySize > MAX_ENTRY_SIZE) {
                    throw new IOException(
                        "Entry \"" + name + "\" exceeds max size of " + MAX_ENTRY_SIZE / (1024 * 1024) + " MB");
                }
                // Rule 6: cumulative size
                if (totalSize > MAX_TOTAL_SIZE) {
                    throw new IOException(
                        "Archive exceeds total decompressed size of " + MAX_TOTAL_SIZE / (1024 * 1024) + " MB");
                }
                fos.write(buffer, 0, len);
            }
        }
        zis.closeEntry();
    }
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] Absence of path traversal pattern in entry names is validated.
- [ ] Canonical output path is verified to start with the destination directory.
- [ ] No symbolic link or hard link entries are allowed.
- [ ] The total number of entries is validated.
- [ ] The maximum deepness is validated.
- [ ] The total size of all decompressed entries is validated (≤ 50 MB).
- [ ] The size of each individual entry is validated (≤ 10 MB).

## References

- [Path traversal information from PortSwigger](https://portswigger.net/web-security/file-path-traversal).
- [Zip-Slip information from Snyk](https://security.snyk.io/research/zip-slip-vulnerability).
- [Zip bomb information from Microsoft](https://www.microsoft.com/en-us/windows/learning-center/what-is-a-zip-bomb).
