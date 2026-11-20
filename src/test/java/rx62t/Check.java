// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
package rx62t;

import java.util.Objects;

/** Minimal assertion helper; output format matches RxVectorTest. */
final class Check {
    private static int pass, fail;
    private static String suite = "";

    private Check() {}

    static void eq(String name, Object want, Object got) {
        ok(name, Objects.deepEquals(want, got), "want=" + show(want) + " got=" + show(got));
    }

    static void ok(String name, boolean cond, String detail) {
        if (cond) {
            pass++;
            System.out.println("RXTEST PASS " + suite + ":" + name);
        } else {
            fail++;
            System.out.println("RXTEST FAIL " + suite + ":" + name + " " + detail);
        }
    }

    /** Prints the summary and returns the process exit code (0 when nothing failed). */
    static int summary(String suiteName) {
        System.out.println("RXTEST SUMMARY " + suiteName + " pass=" + pass + " fail=" + fail);
        return fail == 0 ? 0 : 1;
    }

    /** Sets the suite name used in PASS/FAIL lines. */
    static void suite(String name) {
        suite = name;
    }

    private static String show(Object o) {
        if (o instanceof byte[] b) return java.util.Arrays.toString(b);
        return String.valueOf(o);
    }
}
