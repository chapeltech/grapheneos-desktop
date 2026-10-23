package org.wonad.desktop.api

import org.junit.Assert.*
import org.junit.Test

class DesktopFailureTest {
    @Test fun preservesAdmissionReason() {
        assertEquals("IllegalStateException: No eligible external display",
            DesktopFailure.describe(IllegalStateException("No eligible external display")))
    }
    @Test fun doesNotCopyRemoteStackTraceOrControlCharacters() {
        assertEquals("IllegalStateException: Locked phone",
            DesktopFailure.describe(IllegalStateException("Locked\tphone\nRemote stack trace")))
    }
    @Test fun boundedAndNullSafe() {
        assertEquals("IllegalStateException", DesktopFailure.describe(IllegalStateException()))
        assertEquals("IllegalStateException: ".length + 384,
            DesktopFailure.describe(IllegalStateException("x".repeat(10000))).length)
    }
}
