// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
package rx62t;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Prints RX62TBEClassifier blocks as "start end kind" lines (hex offsets) for parity checks. */
public final class ClassifyDump {
    private ClassifyDump() {}

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("usage: ClassifyDump <image> <baseHex>");
            System.exit(2);
        }
        byte[] img = Files.readAllBytes(Path.of(args[0]));
        long base = Long.parseUnsignedLong(args[1].replaceFirst("^0[xX]", ""), 16);
        for (RX62TBEClassifier.Block b : RX62TBEClassifier.classify(img, base))
            System.out.printf("%x %x %s%n", b.start(), b.end(), b.kind().name().toLowerCase(java.util.Locale.ROOT));
    }
}
