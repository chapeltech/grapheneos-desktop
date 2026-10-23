package org.wonad.desktop

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Test

class ConformanceSdkCoverageTest {
    private fun androidRoot(): File {
        var here = File(requireNotNull(System.getProperty("user.dir"))).canonicalFile
        repeat(4) {
            if (File(here, "desktop-sdk/src/main/aidl").isDirectory) return here
            here = here.parentFile ?: return@repeat
        }
        error("cannot locate Android Gradle root")
    }
    private fun methods(name: String): List<String> {
        val file = File(androidRoot(), "desktop-sdk/src/main/aidl/org/wonad/desktop/api/$name.aidl")
        val body = file.readText().substringAfter("interface $name").substringAfter('{').substringBeforeLast('}')
        return Regex("(?:^|\\n)\\s*(?:oneway\\s+)?(?:@nullable\\s+)?[A-Za-z0-9_<>]+\\s+([A-Za-z0-9_]+)\\s*\\(")
            .findAll(body).map { it.groupValues[1] }.toList()
    }
    @Test fun listsTrackTheGeneratedBinderOrderWithoutReflection() {
        assertEquals(ConformanceContract.brokerOperations, methods("IDesktopBroker"))
        assertEquals(ConformanceContract.sessionOperations, methods("IDesktopSession"))
        assertEquals(ConformanceContract.callbacks, methods("IDesktopCallback"))
    }
}
