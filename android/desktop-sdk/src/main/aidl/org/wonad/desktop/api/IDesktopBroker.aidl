package org.wonad.desktop.api;
import org.wonad.desktop.api.IDesktopCallback;
import org.wonad.desktop.api.IDesktopSession;

/** Version 3 contract; no platform service is installed by this SDK. */
interface IDesktopBroker {
    int getApiVersion();
    long getCapabilities();
    // The broker selects eligible external displays for the active user and
    // rejects unauthorized callers and every version other than API_VERSION.
    IDesktopSession openSession(int apiVersion, IDesktopCallback callback);
}
