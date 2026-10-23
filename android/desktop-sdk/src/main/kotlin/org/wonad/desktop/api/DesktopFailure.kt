package org.wonad.desktop.api

/** Bounded diagnostic text, never an admission decision or a wire error code. */
object DesktopFailure {
    fun describe(error: Throwable): String {
        val message = error.message?.lineSequence()?.firstOrNull { it.isNotBlank() }
            ?.replace(Regex("[\\p{Cntrl}]"), " ")?.take(384)
        return if (message.isNullOrBlank()) error.javaClass.simpleName
            else "${error.javaClass.simpleName}: $message"
    }
}
