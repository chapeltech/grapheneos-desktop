package org.wonad.desktop.api;
import org.wonad.desktop.api.DesktopSnapshot;

oneway interface IDesktopCallback {
    void onSnapshot(in DesktopSnapshot snapshot);
    // Only registered desktop commands, not a general input-event stream.
    void onCommand(long generation, int command, int argument, long taskToken, long displayToken);
    // Transition completion plus an actual observation, never an ACK alone.
    void onResult(long generation, long requestId, int result, long revision);
    void onRevoked(long generation, int reason);
}
