package org.wonad.probe;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;

/** A zero-library instrumentation runner; checks do not run on the UI thread. */
public final class ProbeInstrumentation extends Instrumentation {
    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    @Override public void onStart() {
        Bundle result = new Bundle();
        try {
            ProbeChecks.run();
            checkActivityRecreation();
            result.putString("wonad_runtime_probe", "passed");
            result.putString("activity_recreations", "3");
            result.putString("fingerprint", Build.FINGERPRINT);
            result.putString("device", Build.DEVICE);
            result.putString("abi", android.os.Process.is64Bit() ? "64" : "32");
            result.putString("native_abi", NativeProbe.nativeAbi());
            result.putString("app_debuggable", Boolean.toString(
                    (getTargetContext().getApplicationInfo().flags
                     & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0));
            result.putString("stream", "\nWonad Haskell JNI checks passed\n");
            finish(Activity.RESULT_OK, result);
        } catch (Throwable failure) {
            result.putString("wonad_runtime_probe", "failed");
            result.putString("stream", "\n" + failure + "\n");
            finish(Activity.RESULT_CANCELED, result);
        }
    }

    private void checkActivityRecreation() throws Exception {
        Intent intent = new Intent(getTargetContext(), ProbeActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        Activity activity = startActivitySync(intent);
        try {
            for (int i = 0; i < 3; i++) {
                ActivityMonitor monitor = addMonitor(ProbeActivity.class.getName(), null, false);
                try {
                    Activity previous = activity;
                    runOnMainSync(previous::recreate);
                    Activity recreated = monitor.waitForActivityWithTimeout(30_000);
                    if (recreated == null || recreated == previous) {
                        throw new AssertionError("Activity was not recreated");
                    }
                    activity = recreated;
                    waitForIdleSync();
                    // The process-wide RTS must remain alive across Activity destruction.
                    ProbeChecks.run();
                } finally {
                    removeMonitor(monitor);
                }
            }
        } finally {
            Activity last = activity;
            runOnMainSync(last::finish);
        }
    }
}
