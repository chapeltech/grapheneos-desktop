package com.android.server.wm

/**
 * Runs independent system-server cleanup steps without allowing a supported
 * framework/JNI failure to strand the remaining resources. Fatal VM/process
 * errors are remembered by identity and rethrown after every cleanup attempt.
 */
internal class WonadCleanupFailures {
    private var supported: Throwable? = null
    private var fatal: Throwable? = null

    val supportedFailure: Throwable? get() = supported

    fun attempt(action: () -> Unit) {
        try {
            action()
        } catch (error: Throwable) {
            if (error is Exception || error is LinkageError) appendSupported(error)
            else appendFatal(error)
        }
    }

    /** Complete an attempt-all boundary. A fatal primary error keeps its exact
     * identity; otherwise a fatal cleanup error wins. Supported extension
     * failures are attached for diagnostics but are never promoted to fatal. */
    fun rethrowFatal(primary: Throwable? = null) {
        val primaryFatal = primary?.takeIf { it !is Exception && it !is LinkageError }
        if (primaryFatal != null) {
            fatal?.let { if (it !== primaryFatal) primaryFatal.addSuppressed(it) }
            supported?.let { if (it !== primaryFatal) primaryFatal.addSuppressed(it) }
            throw primaryFatal
        }
        val terminal = fatal ?: return
        primary?.let { if (it !== terminal) terminal.addSuppressed(it) }
        supported?.let { if (it !== terminal && it !== primary) terminal.addSuppressed(it) }
        throw terminal
    }

    private fun appendSupported(error: Throwable) {
        val first = supported
        if (first == null) supported = error
        else if (first !== error) first.addSuppressed(error)
    }

    private fun appendFatal(error: Throwable) {
        val first = fatal
        if (first == null) fatal = error
        else if (first !== error) first.addSuppressed(error)
    }
}
