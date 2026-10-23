package org.wonad.desktop.broker

import android.app.Activity
import android.app.ActivityManager
import android.app.KeyguardManager
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.UserHandle
import android.provider.Settings
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Explicit system-owned consent. The real component requires DUMP; the client alias requires
 * an install-time known-signer permission pinned to the same public certificate as the broker.
 * No Intent extra or client RPC can enable the broker.
 */
class WonadSettingsActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val launchedUid = launchedFromUid
        val trustedLauncher = launchedUid == applicationInfo.uid ||
            launchedUid == Process.SYSTEM_UID ||
            (Build.IS_DEBUGGABLE &&
                (launchedUid == Process.SHELL_UID || launchedUid == Process.ROOT_UID)) ||
            (launchedFromPackage == WonadController.PACKAGE &&
                WonadController.instance?.isAuthorizedClient(launchedUid) == true)
        if (!trustedLauncher) {
            finishAndRemoveTask()
            return
        }
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.setHideOverlayWindows(true)
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        content.addView(TextView(this).apply {
            text = "Wonad external desktop\n\nAllow the separately installed Wonad app to arrange eligible windows on one external screen. " +
                "The phone keeps Android's normal interface. Disconnecting, locking, disabling or a failed client revokes control.\n\n" +
                "Allowed package: ${WonadController.PACKAGE}\nSigning certificate SHA-256:\n${WonadSigning.SHA256}"
            textSize = 18f
        })
        val toggle = Button(this)
        fun enabled() = Settings.Secure.getIntForUser(contentResolver, WonadController.ENABLED_SETTING, 0, UserHandle.myUserId()) == 1
        fun label() { toggle.text = if (enabled()) "Disable Wonad desktop" else "Enable Wonad desktop" }
        label()
        toggle.filterTouchesWhenObscured = true
        toggle.setOnClickListener {
            if (ActivityManager.getCurrentUser() != UserHandle.myUserId() ||
                getSystemService(KeyguardManager::class.java).isKeyguardLocked) return@setOnClickListener
            Settings.Secure.putIntForUser(contentResolver, WonadController.ENABLED_SETTING,
                if (enabled()) 0 else 1, UserHandle.myUserId())
            label()
        }
        content.addView(toggle)
        setContentView(content)
    }
}
