// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Aaron Brown
package rx62t;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Splits a big-endian RX image into code, data and fill, and un-swaps the code, with a statistical
 * code/data model. RX code reads as code only when word-swapped, while data looks the same either
 * way: a byte-pair model of code is trained on the swapped image, each window is scored by how much
 * more code-like it is swapped than raw (counting only byte pairs the swap changes), and a two-state
 * Viterbi pass keeps the long contiguous sections a linker produces. The model is retrained on the
 * code it found and boundaries are refined to single words; pointer tables, vector tables and the
 * reset stub are fixed structurally. The exact block output is pinned by a test against a reference
 * implementation of this model, so keep the evaluation order of floating-point expressions and the
 * compensated {@code sum()}.
 */
public final class RX62TBEClassifier {
    public enum Kind { CODE, DATA, FILL }

    /** Classified byte range of the image; end is exclusive. */
    public record Block(int start, int end, Kind kind) {}

    public static final int WINDOW = 32;
    public static final double THRESHOLD = 1.0, SWITCH_COST = 60.0;

    private static final char C = 'C', D = 'D', F = 'F';
    private static final Pattern PRINTABLE = Pattern.compile("[ -~]{6,}");
    private static final Pattern WORDY = Pattern.compile("[A-Za-z]{4}");

    private RX62TBEClassifier() {}

    public static List<Block> classify(byte[] img, long base) {
        return classify(img, base, WINDOW, THRESHOLD, SWITCH_COST);
    }

    public static List<Block> classify(byte[] img, long base, int window, double threshold, double switchCost) {
        byte[] sw = RX62TBEUtils.swapWords(img);
        int n = img.length;
        boolean[] forcedData = new boolean[n], forcedCode = new boolean[n];
        for (RX62TBEUtils.Range t : RX62TBEUtils.findPointerTables(img, base, 4, true))
            Arrays.fill(forcedData, t.start(), t.end(), true);
        forceVectorTables(img, base, forcedData, forcedCode);

        double[] bias = new double[n];
        boolean[] strRaw = textMask(img), strSw = textMask(sw);
        for (int i = 0; i < n; i++) if (strRaw[i] && !strSw[i]) bias[i] -= 2.0;
        numericLanes(img, forcedData, bias);
        double[] stringBias = bias;

        int nOffs = (n + window - 1) / window;
        boolean[] fill = new boolean[nOffs];
        int nLive = 0;
        for (int k = 0; k < nOffs; k++) {
            int o = k * window, e = Math.min(n, o + window), ffs = 0;
            for (int i = o; i < e; i++) if ((img[i] & 0xFF) == 0xFF) ffs++;
            fill[k] = ffs >= (e - o) - 2;
            if (!fill[k]) nLive++;
        }
        int[] live = new int[nLive];
        for (int k = 0, j = 0; k < nOffs; k++) if (!fill[k]) live[j++] = k * window;
        char[] labels = new char[nLive];
        Arrays.fill(labels, C);

        double[] gain = null;
        for (int iter = 0; iter < 6; iter++) {
            double[][] model = bigramModel(sw, live, labels, forcedData, window);
            gain = stringBias.clone();
            for (int i = 0; i < n - 1; i++) {
                int s0 = sw[i] & 0xFF, s1 = sw[i + 1] & 0xFF, r0 = img[i] & 0xFF, r1 = img[i + 1] & 0xFF;
                if (s0 != r0 || s1 != r1) gain[i] += model[s0][s1] - model[r0][r1] - threshold;
            }
            double[] emit = emissions(live, gain, forcedData, forcedCode, window);
            char[] newLabels = viterbi(emit, switchCost);
            if (Arrays.equals(newLabels, labels)) break;
            labels = newLabels;
        }

        // word-level labels
        int perWin = window / 4;
        char[] word = new char[Math.min(nOffs * perWin, n / 4)];
        for (int k = 0, j = 0; k < nOffs; k++) {
            char lab = fill[k] ? F : labels[Arrays.binarySearch(live, k * window)];
            for (int r = 0; r < perWin && j < word.length; r++) word[j++] = lab;
        }

        refineBoundaries(word, gain, window);
        structuralOverrides(word, img, forcedData, forcedCode);
        absorbSlivers(word, forcedData, stringBias, window);
        return blocks(word, window);
    }

    /** Vector tables are data; every handler they point at (outside data) is code. */
    private static void forceVectorTables(byte[] img, long base, boolean[] forcedData, boolean[] forcedCode) {
        int n = img.length;
        for (Map.Entry<String, Integer> v : RX62TBEUtils.findVectorTables(img, base, true).entrySet()) {
            int s = v.getValue();
            int len = v.getKey().equals("INTB") ? RX62TBEUtils.INTB_LEN : RX62TBEUtils.EXTB_LEN;
            int e = (int) Math.min(n, (long) s + len);
            Arrays.fill(forcedData, s, e, true);
            for (int o = s; o < e && o + 4 <= n; o += 4) {
                long t = be32(img, o) - base;
                if (0 <= t && t < n && !forcedData[(int) t]) {
                    int w = (int) (t - t % 4);
                    Arrays.fill(forcedCode, w, Math.min(n, w + 4), true);
                }
            }
        }
    }

    /** Text that reads as a word: maximal printable runs of 6+ containing 4 letters in a row. */
    private static boolean[] textMask(byte[] buf) {
        boolean[] mask = new boolean[buf.length];
        Matcher m = PRINTABLE.matcher(new String(buf, StandardCharsets.ISO_8859_1));
        while (m.find())
            if (WORDY.matcher(m.group()).find()) Arrays.fill(mask, m.start(), m.end(), true);
        return mask;
    }

    /** Numeric tables: one byte lane only 00/FF for 8 words -> data bias. */
    private static void numericLanes(byte[] img, boolean[] forcedData, double[] bias) {
        int n = img.length, span = 32;
        for (int o = 0; o < n - span; o += 4) {
            if (anyTrue(forcedData, o, o + span)) continue;
            boolean[] seen = new boolean[256];
            int distinct = 0;
            for (int i = o; i < o + span; i++) if (!seen[img[i] & 0xFF]) { seen[img[i] & 0xFF] = true; distinct++; }
            boolean signLane = false;
            for (int c = 0; c < 4 && !signLane; c++) {
                boolean all = true;
                for (int i = o + c; i < o + span; i += 4) {
                    int b = img[i] & 0xFF;
                    if (b != 0x00 && b != 0xFF) all = false;
                }
                signLane = all;
            }
            if (distinct > 2 && signLane)
                for (int i = o; i < o + span; i++) bias[i] = bias[i] > -2.0 ? Math.min(bias[i], -1.0) : bias[i];
        }
    }

    private static double[][] bigramModel(byte[] sw, int[] live, char[] labels, boolean[] forcedData, int window) {
        double[][] counts = new double[256][256];
        for (double[] row : counts) Arrays.fill(row, 0.5);
        for (int j = 0; j < live.length; j++) {
            int o = live[j];
            if (labels[j] != C || forcedData[o]) continue;
            int e = Math.min(sw.length, o + window);
            for (int i = o; i + 1 < e; i++) counts[sw[i] & 0xFF][sw[i + 1] & 0xFF] += 1;
        }
        double[][] model = new double[256][256];
        for (int a = 0; a < 256; a++) {
            double total = pySum(counts[a], 0, 256);
            for (int b = 0; b < 256; b++) model[a][b] = StrictMath.log(counts[a][b] / total);
        }
        return model;
    }

    private static double[] emissions(int[] live, double[] gain, boolean[] forcedData, boolean[] forcedCode, int window) {
        int n = gain.length;
        double[] emit = new double[live.length];
        for (int j = 0; j < live.length; j++) {
            int o = live[j], e = Math.min(n, o + window), fd = 0;
            for (int i = o; i < e; i++) if (forcedData[i]) fd++;
            if (fd * 2 >= window) emit[j] = -1e6;
            else if (anyTrue(forcedCode, o, e)) emit[j] = 1e6;
            else emit[j] = pySum(gain, o, e);
        }
        return emit;
    }

    /** Two-state (C/D) Viterbi; ties stay, and a final tie picks C. */
    private static char[] viterbi(double[] emit, double switchCost) {
        int m = emit.length;
        double costC = 0.0, costD = 0.0;
        boolean[] backC = new boolean[m], backD = new boolean[m]; // true: came from the other state
        for (int j = 0; j < m; j++) {
            double eC = -emit[j], eD = emit[j];
            double stayC = costC, switchC = costD + switchCost;
            double stayD = costD, switchD = costC + switchCost;
            double newC, newD;
            if (stayC <= switchC) newC = stayC + eC; else { newC = switchC + eC; backC[j] = true; }
            if (stayD <= switchD) newD = stayD + eD; else { newD = switchD + eD; backD[j] = true; }
            costC = newC;
            costD = newD;
        }
        char state = costC <= costD ? C : D;
        char[] path = new char[m];
        for (int j = m - 1; j >= 0; j--) {
            path[j] = state;
            boolean cross = state == C ? backC[j] : backD[j];
            if (cross) state = state == C ? D : C;
        }
        return path;
    }

    /** Moves each C/D boundary to the best word split within +-window/2 words. */
    private static void refineBoundaries(char[] word, double[] gain, int window) {
        double[] prefix = new double[gain.length + 1];
        for (int i = 0; i < gain.length; i++) prefix[i + 1] = prefix[i] + gain[i];
        List<int[]> runs = new ArrayList<>(); // {start, end, kind}
        for (int i = 0; i < word.length; i++) {
            if (!runs.isEmpty() && runs.get(runs.size() - 1)[2] == word[i]) runs.get(runs.size() - 1)[1] = i + 1;
            else runs.add(new int[] {i, i + 1, word[i]});
        }
        for (int r = 0; r + 1 < runs.size(); r++) {
            int[] a = runs.get(r), b = runs.get(r + 1);
            if (!((a[2] == C && b[2] == D) || (a[2] == D && b[2] == C))) continue;
            int lo = Math.max(a[0] + 1, a[1] - window / 2);
            int hi = Math.min(b[1] - 1, a[1] + window / 2);
            int signA = a[2] == C ? 1 : -1;
            if (lo < hi) {
                int cut = lo;
                double best = splitScore(prefix, lo, lo, hi, signA);
                for (int k = lo + 1; k <= hi; k++) {
                    double s = splitScore(prefix, k, lo, hi, signA);
                    if (s > best) { best = s; cut = k; }
                }
                for (int w = Math.min(cut, a[1]); w < Math.max(cut, a[1]); w++)
                    word[w] = (char) (w < cut ? a[2] : b[2]);
            }
        }
    }

    private static double splitScore(double[] prefix, int k, int lo, int hi, int signA) {
        return signA * (prefix[4 * k] - prefix[4 * lo]) - signA * (prefix[4 * hi] - prefix[4 * k]);
    }

    /** Pointer tables are data, their targets and the reset stub (up to the first FFFFFFFF) code. */
    private static void structuralOverrides(char[] word, byte[] img, boolean[] forcedData, boolean[] forcedCode) {
        for (int w = 0; w < word.length; w++) {
            if (forcedData[4 * w]) word[w] = D;
            else if (forcedCode[4 * w]) word[w] = C;
        }
        for (int w = 0; w < word.length && be32(img, 4 * w) != 0xFFFFFFFFL; w++) word[w] = C;
    }

    /** A short evidence-free data sliver between a structural table and code is code. */
    private static void absorbSlivers(char[] word, boolean[] forcedData, double[] stringBias, int window) {
        int limit = 2 * window / 4;
        for (int w = 1; w < word.length; w++) {
            if (word[w] != D || forcedData[4 * w] || !forcedData[4 * (w - 1)]) continue;
            int e = w;
            while (e < word.length && word[e] == D && !forcedData[4 * e]) e++;
            if (e - w <= limit && e < word.length && word[e] == C && allZero(stringBias, 4 * w, 4 * e))
                Arrays.fill(word, w, e, C);
        }
    }

    /** Word labels to blocks, absorbing fill runs shorter than a window into the previous kind. */
    private static List<Block> blocks(char[] word, int window) {
        List<Block> blocks = new ArrayList<>();
        for (int i = 0; i < word.length; i++) {
            Kind k = word[i] == C ? Kind.CODE : word[i] == D ? Kind.DATA : Kind.FILL;
            int last = blocks.size() - 1;
            if (last >= 0 && blocks.get(last).kind() == k) blocks.set(last, new Block(blocks.get(last).start(), 4 * (i + 1), k));
            else blocks.add(new Block(4 * i, 4 * (i + 1), k));
        }
        List<Block> merged = new ArrayList<>();
        for (Block b : blocks) {
            int last = merged.size() - 1;
            if (last >= 0 && b.kind() == Kind.FILL && b.end() - b.start() < window)
                b = new Block(b.start(), b.end(), merged.get(last).kind());
            if (last >= 0 && merged.get(last).kind() == b.kind())
                merged.set(last, new Block(merged.get(last).start(), b.end(), b.kind()));
            else merged.add(b);
        }
        return merged;
    }

    /**
     * The image in instruction-fetch order: CODE blocks word-swapped, everything else verbatim.
     *
     * @throws IllegalArgumentException if base is not 4-byte aligned
     */
    public static byte[] buildFetchOrderImage(byte[] img, List<Block> blocks, long base) {
        if (base % 4 != 0)
            throw new IllegalArgumentException(
                    String.format("image base 0x%08X is not word aligned; cannot un-swap code words", base));
        byte[] out = img.clone();
        for (Block b : blocks) {
            if (b.kind() != Kind.CODE) continue;
            byte[] sw = RX62TBEUtils.swapWords(Arrays.copyOfRange(img, b.start(), b.end()));
            System.arraycopy(sw, 0, out, b.start(), sw.length);
        }
        return out;
    }

    /** CPython (>= 3.12) float sum(): Neumaier-compensated. */
    private static double pySum(double[] xs, int from, int to) {
        double hi = 0.0, lo = 0.0;
        for (int i = from; i < to; i++) {
            double x = xs[i], t = hi + x;
            if (Math.abs(hi) >= Math.abs(x)) lo += (hi - t) + x;
            else lo += (x - t) + hi;
            hi = t;
        }
        return lo != 0.0 && Double.isFinite(lo) ? hi + lo : hi;
    }

    private static boolean anyTrue(boolean[] a, int from, int to) {
        for (int i = from; i < Math.min(to, a.length); i++) if (a[i]) return true;
        return false;
    }

    private static boolean allZero(double[] a, int from, int to) {
        for (int i = from; i < to; i++) if (a[i] != 0.0) return false;
        return true;
    }

    private static long be32(byte[] b, int o) {
        return (b[o] & 0xFFL) << 24 | (b[o + 1] & 0xFFL) << 16 | (b[o + 2] & 0xFFL) << 8 | (b[o + 3] & 0xFFL);
    }
}
