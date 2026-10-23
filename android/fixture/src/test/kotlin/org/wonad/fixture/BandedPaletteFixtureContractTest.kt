package org.wonad.fixture

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.*
import org.junit.Test
import org.w3c.dom.Element

/** Fixture/source contracts only. Real framebuffer parity is a separate gate. */
class BandedPaletteFixtureContractTest {
    private val android = "http://schemas.android.com/apk/res/android"
    private fun file(relative: String) = listOf(File(relative), File("android/fixture/$relative"))
        .firstOrNull { it.isFile } ?: error("Missing actual fixture source")
    @Test fun fiveIndependentOrdinaryLauncherActivities() {
        val factory = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        }
        val root = factory.newDocumentBuilder().parse(file("src/main/AndroidManifest.xml")).documentElement
        val activities = root.getElementsByTagName("activity")
        val rows = (0 until activities.length).map { activities.item(it) as Element }
        for (name in listOf("One", "Two", "Three", "Four", "Five")) {
            val activity = rows.single { it.getAttributeNS(android, "name") == ".Banded${name}Activity" }
            assertEquals("Wonad Linux banded ${name.lowercase()}", activity.getAttributeNS(android, "label"))
            assertEquals("org.wonad.fixture.banded.${name.lowercase()}", activity.getAttributeNS(android, "taskAffinity"))
            assertEquals("true", activity.getAttributeNS(android, "exported"))
            assertEquals("true", activity.getAttributeNS(android, "resizeableActivity"))
            assertEquals("screenSize|smallestScreenSize|orientation|screenLayout|density", activity.getAttributeNS(android, "configChanges"))
            assertEquals("", activity.getAttributeNS(android, "permission"))
            assertEquals("", activity.getAttributeNS(android, "launchMode"))
            val action = activity.getElementsByTagName("action").item(0) as Element
            val category = activity.getElementsByTagName("category").item(0) as Element
            assertEquals("android.intent.action.MAIN", action.getAttributeNS(android, "name"))
            assertEquals("android.intent.category.LAUNCHER", category.getAttributeNS(android, "name"))
        }
    }
    @Test fun rawPhysicalThreeBandDrawingAndActualIdentityInputOnly() {
        val source = file("src/main/kotlin/org/wonad/fixture/BandedPaletteActivity.kt").readText()
        for (required in listOf("height / 3", "height * 2 / 3", "isAntiAlias = false", "isDither = false",
            "canvas.drawRect", "window.setDecorFitsSystemWindows(false)", "windowManager.currentWindowMetrics.bounds",
            "Process.myPid()", "Process.myUid()", "ledger.configured(w, h)", "ledger.keyDown(event.keyCode)",
            "InputDevice.SOURCE_MOUSE", "WONAD_BANDED_PALETTE", "actual.instance")) assertTrue(required, source.contains(required))
        for (forbidden in listOf("canvas.scale", "drawText", "drawBitmap", "SurfaceControl", "IDesktop", "setBounds(",
            "startActivity(", "requestPermissions", "getIntExtra", "sendBroadcast", "Shader", "setPadding"))
            assertFalse(forbidden, source.contains(forbidden))
    }
    @Test fun disablesOnlyDefaultFocusDecorationAndPreservesEveryBand() {
        val source = file("src/main/kotlin/org/wonad/fixture/BandedPaletteActivity.kt").readText()
        val init = Regex("init\\s*\\{([^}]*)}").find(source)!!.groupValues[1]
        assertTrue(init.contains("isFocusableInTouchMode = true"))
        assertTrue(init.contains("setDefaultFocusHighlightEnabled(false)"))
        assertEquals(1, Regex("setDefaultFocusHighlightEnabled\\(").findAll(source).count())
        for (forbidden in listOf("isFocusable = false", "isFocusableInTouchMode = false", "clearFocus(",
            "setFocusable(false)", "setTheme(", "colorControlHighlight", "selectableItemBackground"))
            assertFalse(forbidden, source.contains(forbidden))
        val colors = Regex("0x[0-9a-f]{8}\\.toInt\\(\\)").findAll(source).map { it.value }.toList()
        assertEquals(listOf("ffcc4422", "ffff8844", "ffffc488", "ff22aa66", "ff66dd88", "ffaaffcc",
            "ff7744bb", "ffaa77ee", "ffddbbff", "ff2266cc", "ff55aaff", "ff99ddff", "ffccaa22",
            "ffffdd55", "ffffffaa").map { "0x$it.toInt()" }, colors)
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        val root = factory.newDocumentBuilder().parse(file("src/main/AndroidManifest.xml")).documentElement
        val app = root.getElementsByTagName("application").item(0) as Element
        assertEquals("@android:style/Theme.Material.Light.NoActionBar", app.getAttributeNS(android, "theme"))
    }
}
