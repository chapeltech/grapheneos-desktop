package org.wonad.desktop.broker

import android.app.Instrumentation
import android.os.Build
import android.os.Bundle
import org.junit.runner.JUnitCore

/** Runs the same Rust/JNI and OS-token-registry tests in an unprivileged APK.
 * This proves Android execution, not Binder authentication or WM integration.
 */
class NativeBrokerInstrumentation : Instrumentation() {
    private var boundary = false
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        val mode = arguments?.getString("mode")
        require(mode == null || mode == "broker-boundary") { "Unknown test mode" }
        boundary = mode == "broker-boundary"
        start()
    }

    override fun onStart() {
        val result = Bundle()
        try {
            if (boundary) {
                result.putInt("denied_calls", BrokerBoundaryChecks.run(targetContext))
                result.putString("broker_boundary", "passed")
                result.putString("scope", "wrong_uid_broker_authentication")
                result.putString("fingerprint", Build.FINGERPRINT)
                result.putString("native_abi", Build.SUPPORTED_ABIS.first())
                finish(-1, result)
                return
            }
            val tests = JUnitCore.runClasses(NativeDesktopWireTest::class.java,
                NativeFrameCompletionTest::class.java, InputNativeTest::class.java,
                BrokerDispatchTest::class.java)
            result.putString("wonad_broker_core", if (tests.wasSuccessful()) "passed" else "failed")
            result.putInt("tests", tests.runCount)
            result.putInt("failures", tests.failureCount)
            result.putString("fingerprint", Build.FINGERPRINT)
            result.putString("native_abi", Build.SUPPORTED_ABIS.first())
            result.putString("scope", "unprivileged_rust_jni_probe")
            result.putString("wm_broker", "not_tested")
            if (!tests.wasSuccessful()) result.putString("failure_details", tests.failures.joinToString("\n"))
            finish(if (tests.wasSuccessful()) -1 else 0, result)
        } catch (error: Throwable) {
            result.putString(if (boundary) "broker_boundary" else "wonad_broker_core", "failed")
            result.putString("failure_details", error.toString())
            finish(0, result)
        }
    }
}
