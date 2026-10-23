package org.wonad.fixture

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.*
import org.junit.Test
import org.w3c.dom.Element

/** Ordinary fixture contract only; this cannot qualify framebuffer/input parity. */
class PaletteFixtureContractTest {
    private val android = "http://schemas.android.com/apk/res/android"
    private fun file(relative: String) = listOf(File(relative), File("android/fixture/$relative"))
        .firstOrNull { it.isFile } ?: error("Fixture source unavailable: $relative")
    private fun elements(root: Element, name: String): List<Element> {
        val nodes = root.getElementsByTagName(name)
        return (0 until nodes.length).map { nodes.item(it) as Element }
    }
    private fun manifest(): Element = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
        setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        setFeature("http://xml.org/sax/features/external-general-entities", false)
        setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    }.newDocumentBuilder().parse(file("src/main/AndroidManifest.xml")).documentElement

    @Test fun paletteClientsAreSeparateOrdinaryRealLauncherActivities() {
        val root = manifest()
        val activities = elements(root, "activity").associateBy { it.getAttributeNS(android, "name") }
        for ((name, label, affinity) in listOf(
            Triple(".PaletteOneActivity", "Wonad Linux palette one", "org.wonad.fixture.palette.one"),
            Triple(".PaletteTwoActivity", "Wonad Linux palette two", "org.wonad.fixture.palette.two"))) {
            val activity = requireNotNull(activities[name])
            assertEquals(label, activity.getAttributeNS(android, "label"))
            assertEquals(affinity, activity.getAttributeNS(android, "taskAffinity"))
            assertEquals("true", activity.getAttributeNS(android, "exported"))
            assertEquals("true", activity.getAttributeNS(android, "resizeableActivity"))
            assertEquals("screenSize|smallestScreenSize|orientation|screenLayout|density",
                activity.getAttributeNS(android, "configChanges"))
            for (attribute in listOf("permission", "launchMode", "noHistory", "excludeFromRecents")) {
                assertEquals(attribute, "", activity.getAttributeNS(android, attribute))
            }
            val filter = elements(activity, "intent-filter").single()
            assertEquals(listOf("android.intent.action.MAIN"), elements(filter, "action")
                .map { it.getAttributeNS(android, "name") })
            assertEquals(listOf("android.intent.category.LAUNCHER"), elements(filter, "category")
                .map { it.getAttributeNS(android, "name") })
        }
        val permissions = elements(root, "uses-permission").map { it.getAttributeNS(android, "name") }
        assertEquals(setOf("android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION", "android.permission.CAPTURE_KEYBOARD"),
            permissions.toSet())
        assertEquals(4, permissions.size)
        assertEquals("false", requireNotNull(activities[".FixedActivity"])
            .getAttributeNS(android, "resizeableActivity"))
    }

    @Test fun renderingUsesActualUnscaledOpaqueViewAndMatchingIndependentRgbBytes() {
        val source = file("src/main/kotlin/org/wonad/fixture/PaletteActivity.kt").readText()
        assertTrue(source.contains("override fun onDraw(canvas: Canvas)"))
        assertTrue(source.contains("canvas.drawColor(palette)"))
        assertTrue(source.contains("window.setDecorFitsSystemWindows(false)"))
        assertTrue(source.contains("window.setBackgroundDrawable(ColorDrawable(palette))"))
        assertTrue(source.contains("override val palette = 0xffcc4422.toInt()"))
        assertTrue(source.contains("override val palette = 0xff22aa66.toInt()"))
        for (forbidden in listOf("drawText", "drawBitmap", "setPadding", "canvas.scale", "canvas.translate",
            "SurfaceControl", "addView(", "FLAG_ACTIVITY_NEW_TASK", "TYPE_APPLICATION_OVERLAY",
            "requestPermissions", "grantRuntimePermission", "IDesktop", "BrokerNative", "ShellUi")) {
            assertFalse(forbidden, source.contains(forbidden))
        }
    }

    @Test fun diagnosticsUseRealFrameworkIdentityGeometryAndInputCallbacks() {
        val source = file("src/main/kotlin/org/wonad/fixture/PaletteActivity.kt").readText()
        for (actual in listOf("windowManager.currentWindowMetrics.bounds", "Process.myPid()", "Process.myUid()",
            ".put(\"task\", taskId)", "display?.displayId", "ledger.configured(w, h)", "ledger.drawn()",
            "ledger.focused(hasFocus)", "ledger.keyDown(event.keyCode)", "MotionEvent.ACTION_DOWN",
            "event.isFromSource(InputDevice.SOURCE_MOUSE)", "super.dispatchTouchEvent(event)",
            "WONAD_PALETTE ", ".put(\"instance\", actual.instance)")) {
            assertTrue(actual, source.contains(actual))
        }
        for (forbidden in listOf("setTaskWindowingMode", "setBounds", "setResult(", "getIntExtra",
            "sendBroadcast", "Runtime.getRuntime", "startActivity(")) {
            assertFalse(forbidden, source.contains(forbidden))
        }
    }
}
