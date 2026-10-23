package org.wonad.desktop.api;
import org.wonad.desktop.api.DesktopFrame;
import org.wonad.desktop.api.DesktopLaunchPage;
import org.wonad.desktop.api.DesktopShortcutProfile;

/** Binder identity and a fresh OS session/environment are checked on every call. */
interface IDesktopSession {
    oneway void applyFrame(long generation, long requestId, long baseRevision,
                          in DesktopFrame frame);
    oneway void focusTask(long generation, long requestId, long baseRevision, long taskToken);
    oneway void closeTask(long generation, long requestId, long baseRevision, long taskToken);
    oneway void enableShortcuts(long generation, boolean enabled);
    oneway void heartbeat(long generation, long sequence);
    oneway void release(long generation);
    oneway void enableExternalUi(long generation);
    // Start only the authenticated APK's fixed external shell on the exact
    // claimed display. No window, surface or input handle crosses this API.
    oneway void showShell(long generation, long displayToken);
    @nullable DesktopLaunchPage launcherPage(long generation, long catalogId,
                                             long displayToken, int offset);
    oneway void showLauncher(long generation, long catalogId);
    oneway void selectLauncher(long generation, long catalogId, int index);
    // Trusted phone-side exact-task selection and confirmation.
    oneway void showTransferPicker(long generation, long displayToken);
    // Capability-gated signed/off-screen task placement. applyFrame remains
    // monitor-contained; shell regions are contained for both operations.
    oneway void applySignedFrame(long generation, long requestId, long baseRevision,
                                in DesktopFrame frame);
    // SDK 3.1.0 additions. Never reorder the preceding transactions.
    @nullable DesktopShortcutProfile getShortcutProfile(long generation);
    oneway void enableShortcutKeys(long generation, boolean enabled);
    // Fixed ordinary APK UI only; no prompt text or desktop policy enters OS.
    oneway void showClientPrompt(long generation, long requestId, long displayToken);
}
