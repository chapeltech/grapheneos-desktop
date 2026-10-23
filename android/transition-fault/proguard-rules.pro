# Keep Android's instrumentation entry point, but relocate all surviving bundled
# Kotlin runtime helpers away from SystemUI's already-loaded kotlin.* classes.
-repackageclasses org.wonad.desktop.transitionfault.internal
-keep,allowoptimization class org.wonad.desktop.transitionfault.TransitionDelayInstrumentation {
    public <init>();
    public void onCreate(android.os.Bundle);
    public void onStart();
}
-keep,allowoptimization class org.wonad.desktop.transitionfault.NativeCompletionProofInstrumentation {
    public <init>();
    public void onCreate(android.os.Bundle);
    public void onStart();
}
