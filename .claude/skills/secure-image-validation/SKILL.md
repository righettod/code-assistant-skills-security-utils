---
name: secure-image-validation
description: Generate secure image file validation code. Enforces secure generation of code validating an image file. Invoke when writing any image file validation related code.
allowed-tools: Read Grep Glob
metadata:
  category: security
---

# Secure Image File Validation Code Generation Rules

Apply **all** rules below when generating or reviewing any code related to validation of an image file.

## 1. Image file validation (CRITICAL)

- ALWAYS ensure that the file is a real image file of type `PNG`, `JPEG`, `GIF`, `BMP`.
- ALWAYS ensure that the image file has no content appended at the end of the image structure (concatenated file).
- ALWAYS resize the image by removing 1px in width and 1px in height to remove any embedded code.

```java
// BAD: No validation is applied
BufferedImage image = ImageIO.read(file);
if (image != null) {
    System.out.println("Image loaded successfully!");
    System.out.println("Width:  " + image.getWidth() + "px");
    System.out.println("Height: " + image.getHeight() + "px");
}

// GOOD: All points are applied
public class ImageReader {

    public static BufferedImage readImage(String filePath) throws IOException {
        byte[] b = Files.readAllBytes(Path.of(filePath));

        long end;
        if (match(b, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))
            end = pngEnd(b);
        else if (match(b, 0xFF, 0xD8, 0xFF))
            end = jpegEnd(b);
        else if (match(b, 0x47, 0x49, 0x46, 0x38))
            end = gifEnd(b);
        else if (match(b, 0x42, 0x4D))
            end = bmpEnd(b);
        else
            throw new IOException("Not a supported image (PNG/JPEG/GIF/BMP).");

        if (end < 0)
            throw new IOException("Could not parse image structure.");
        if (end != b.length)
            throw new IOException("Extra " + (b.length - end) + " byte(s) appended after image.");

        BufferedImage img = ImageIO.read(new ByteArrayInputStream(b));
        if (img == null)
            throw new IOException("ImageIO failed to decode the image.");

        // Rule 3: strip 1px from width and height to remove any embedded code
        return img.getSubimage(0, 0, img.getWidth() - 1, img.getHeight() - 1);
    }

    private static boolean match(byte[] b, int... magic) {
        if (b.length < magic.length) return false;
        for (int i = 0; i < magic.length; i++)
            if ((b[i] & 0xFF) != magic[i]) return false;
        return true;
    }

    private static long pngEnd(byte[] b) {
        int o = 8;
        while (o + 12 <= b.length) {
            int len = ((b[o] & 0xFF) << 24) | ((b[o+1] & 0xFF) << 16) | ((b[o+2] & 0xFF) << 8) | (b[o+3] & 0xFF);
            boolean iend = match(Arrays.copyOfRange(b, o+4, o+8), 0x49, 0x45, 0x4E, 0x44);
            o += 12 + len;
            if (iend) return o;
        }
        return -1;
    }

    private static long jpegEnd(byte[] b) {
        int o = 0;
        while (o + 1 < b.length) {
            if ((b[o] & 0xFF) != 0xFF) return -1;
            int m = b[o+1] & 0xFF;
            if (m == 0xD9) return o + 2;
            if (m == 0xD8 || m == 0x01 || (m >= 0xD0 && m <= 0xD7)) { o += 2; continue; }
            if (o + 3 >= b.length) return -1;
            o += 2 + (((b[o+2] & 0xFF) << 8) | (b[o+3] & 0xFF));
        }
        return -1;
    }

    private static long gifEnd(byte[] b) {
        int f = b[10] & 0xFF;
        int o = 13 + (((f & 0x80) != 0) ? 3 * (1 << ((f & 0x07) + 1)) : 0);
        while (o < b.length) {
            int block = b[o] & 0xFF;
            if (block == 0x3B) return o + 1;
            if (block == 0x2C) {
                int lf = b[o+9] & 0xFF;
                o += 10 + (((lf & 0x80) != 0) ? 3 * (1 << ((lf & 0x07) + 1)) : 0) + 1;
            } else if (block == 0x21) {
                o += 2;
            } else {
                return -1;
            }
            while (o < b.length) {
                int s = b[o++] & 0xFF;
                o += s;
                if (s == 0) break;
            }
        }
        return -1;
    }

    private static long bmpEnd(byte[] b) {
        return (b.length < 6) ? -1
            : (b[2] & 0xFFL) | ((b[3] & 0xFFL) << 8) | ((b[4] & 0xFFL) << 16) | ((b[5] & 0xFFL) << 24);
    }
}
```

## 2. Output Checklist

Before finalizing generated code, verify:

- [ ] The file is a real image file.
- [ ] The image file has no content appended at the end of the image structure (concatenated file).
- [ ] The image file was resized.

## References

- [Example of a Payload Delivered Through Steganography from SANS](https://isc.sans.edu/diary/31892).
- [Example of attack from Synacktiv](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there).
- [A generator of weird files (binary polyglots, near polyglots, polymocks...) by Ange Albertini on GitHub](https://github.com/corkami/mitra).
- [Image Payload Creating/Injecting tools on GitHub](https://github.com/sighook/pixload).
- [Embed a payload inside a PNG file tools on GitHub](https://github.com/Maldev-Academy/EmbedPayloadInPng).