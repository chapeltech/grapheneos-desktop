package org.wonad.desktop.api;
import org.wonad.desktop.api.DesktopTask;
import org.wonad.desktop.api.DesktopDisplay;

/** Fresh bounded observations; contains no desktop policy authority. */
parcelable DesktopSnapshot {
    long generation;
    long revision;
    long topologyRevision;
    long capabilities;
    DesktopDisplay[] displays;
    DesktopTask[] tasks;
    long focusedDisplayToken;
    long focusedToken;
    // Survives APK/SystemUI restart and changes with system_server.
    long identityEpoch;
    // Trusted phone selection/confirmation is in progress; mutations wait.
    boolean interactionBlocked;
}
