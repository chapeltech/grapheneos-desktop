package org.wonad.probe;

public final class NativeProbe {
    static { System.loadLibrary("wonad_probe"); }
    private NativeProbe() {}
    public static native int[] layout(int width, int height);
    public static native int stress(int count);
    public static native String nativeAbi();
}
