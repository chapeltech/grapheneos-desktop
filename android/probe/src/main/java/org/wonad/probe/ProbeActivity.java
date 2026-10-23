package org.wonad.probe;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/** Deliberately permissionless: this APK does not control any Android tasks. */
public final class ProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView status = new TextView(this);
        status.setText("Running Haskell JNI runtime probe…");
        setContentView(status);
        new Thread(() -> {
            String result;
            try {
                ProbeChecks.run();
                result = "PASS: Haskell JNI checks. This is not a window manager. " +
                        "Run instrumentation to collect device gate evidence.";
            } catch (Throwable failure) {
                result = "FAIL: " + failure;
            }
            final String message = result;
            runOnUiThread(() -> { if (!isDestroyed()) status.setText(message); });
        }, "wonad-probe").start();
    }
}
