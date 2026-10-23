package org.wonad.probe;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** The same checks run on the host JVM and in Android instrumentation. */
public final class ProbeChecks {
    private ProbeChecks() {}

    public static void run() throws Exception {
        if (!Arrays.asList("x86_64", "arm64-v8a").contains(NativeProbe.nativeAbi())) {
            throw new AssertionError("Unsupported native probe ABI");
        }
        equal(new int[] {0, 0, 960, 1080, 960, 0, 960, 1080},
                NativeProbe.layout(1920, 1080));
        equal(new int[] {0, 0, 1, 1, 1, 0, 2, 1}, NativeProbe.layout(3, 1));
        equal(new int[] {0, 0, 1073741823, 1, 1073741823, 0, 1073741824, 1},
                NativeProbe.layout(Integer.MAX_VALUE, 1));
        for (int[] size : new int[][] {{0, 1}, {1, 1}, {2, 0}, {-1, 1}}) {
            try {
                NativeProbe.layout(size[0], size[1]);
                throw new AssertionError("Invalid dimensions accepted");
            } catch (IllegalArgumentException expected) {
                // An exception must reach Java, not unwind through C.
            }
        }
        if (NativeProbe.stress(-1) != -1 || NativeProbe.stress(4097) != -1) {
            throw new AssertionError("Stress bounds not enforced");
        }
        ExecutorService workers = Executors.newFixedThreadPool(4);
        try {
            List<Future<Integer>> results = new ArrayList<>();
            for (int i = 0; i < 8; ++i) {
                results.add(workers.submit(() -> NativeProbe.stress(256)));
            }
            for (Future<Integer> result : results) {
                if (result.get(30, TimeUnit.SECONDS) != 32896) {
                    throw new AssertionError("Haskell runtime result mismatch");
                }
            }
        } finally {
            workers.shutdownNow();
        }
    }

    private static void equal(int[] expected, int[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError("Geometry mismatch: " + Arrays.toString(actual));
        }
    }

    public static void main(String[] args) throws Exception {
        run();
        System.out.println("PASS: host JNI probe (NOT the Android runtime gate)");
    }
}
