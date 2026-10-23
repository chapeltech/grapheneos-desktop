package org.wonad.fixture

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.*
import org.junit.Test
import org.w3c.dom.Element

/** Source contract only; genuine phone routing/result delivery needs an emulator acceptance run. */
class PermissionFixtureContractTest {
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

    @Test fun manifestDeclaresOnlyTheThreeRealDangerousPermissionsAndAnOrdinarySeparateActivity() {
        val root = manifest()
        val dangerousPermissions = PermissionRequestLedger.Kind.entries.flatMap { it.permissions }.toSet()
        val permissions = elements(root, "uses-permission").map { it.getAttributeNS(android, "name") }
        assertEquals(setOf("android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION"), dangerousPermissions)
        assertEquals(dangerousPermissions + "android.permission.CAPTURE_KEYBOARD", permissions.toSet())
        assertEquals(4, permissions.size)
        val activities = elements(root, "activity").associateBy { it.getAttributeNS(android, "name") }
        val permission = requireNotNull(activities[".PermissionActivity"])
        assertEquals("true", permission.getAttributeNS(android, "exported"))
        assertEquals("true", permission.getAttributeNS(android, "resizeableActivity"))
        assertEquals("org.wonad.fixture.permissions", permission.getAttributeNS(android, "taskAffinity"))
        assertEquals("", permission.getAttributeNS(android, "permission"))
        assertEquals("", permission.getAttributeNS(android, "launchMode"))
        assertTrue(elements(permission, "category").any {
            it.getAttributeNS(android, "name") == "android.intent.category.LAUNCHER"
        })
        for (name in listOf(".OneActivity", ".TwoActivity", ".LaunchActivity")) {
            assertEquals("true", requireNotNull(activities[name]).getAttributeNS(android, "resizeableActivity"))
        }
        assertEquals("false", requireNotNull(activities[".FixedActivity"])
            .getAttributeNS(android, "resizeableActivity"))
    }

    @Test fun secondDesktopFixtureIsARealDistinctLauncherActivityWithoutBehaviorChanges() {
        val root = manifest()
        val activities = elements(root, "activity").associateBy { it.getAttributeNS(android, "name") }
        val second = requireNotNull(activities[".TwoActivity"])
        assertEquals("Wonad second desktop fixture", second.getAttributeNS(android, "label"))
        assertEquals("true", second.getAttributeNS(android, "exported"))
        assertEquals("true", second.getAttributeNS(android, "resizeableActivity"))
        assertEquals("org.wonad.fixture.two", second.getAttributeNS(android, "taskAffinity"))
        assertEquals("screenSize|smallestScreenSize|orientation|screenLayout|density",
            second.getAttributeNS(android, "configChanges"))
        for (attribute in listOf("permission", "launchMode", "noHistory", "excludeFromRecents")) {
            assertEquals(attribute, "", second.getAttributeNS(android, attribute))
        }
        val filter = elements(second, "intent-filter").single()
        assertEquals(listOf("android.intent.action.MAIN"), elements(filter, "action")
            .map { it.getAttributeNS(android, "name") })
        assertEquals(listOf("android.intent.category.LAUNCHER"), elements(filter, "category")
            .map { it.getAttributeNS(android, "name") })
        assertEquals(listOf(".PermissionActivity", ".OneActivity", ".TwoActivity", ".LaunchActivity",
            ".PaletteOneActivity", ".PaletteTwoActivity", ".BandedOneActivity", ".BandedTwoActivity",
            ".BandedThreeActivity", ".BandedFourActivity", ".BandedFiveActivity",
            ".KeyboardCaptureOneActivity", ".KeyboardCaptureTwoActivity", ".KeyboardCapturePhoneActivity"),
            activities.values.filter { activity -> elements(activity, "category").any {
                it.getAttributeNS(android, "name") == "android.intent.category.LAUNCHER"
            } }.map { it.getAttributeNS(android, "name") })
        val labels = listOf(root.getElementsByTagName("application").item(0) as Element)
            .plus(activities.values).map { it.getAttributeNS(android, "label") }.filter { it.isNotEmpty() }
        assertEquals(labels.size, labels.toSet().size)
        assertEquals("false", requireNotNull(activities[".FixedActivity"])
            .getAttributeNS(android, "resizeableActivity"))
    }

    @Test fun activityUsesTheActualFrameworkPermissionResultPathAndNoPrivilegeShortcut() {
        val source = file("src/main/kotlin/org/wonad/fixture/PermissionActivity.kt").readText()
        assertEquals(1, Regex("\\brequestPermissions\\(").findAll(source).count())
        assertTrue(source.contains("requestPermissions(request.permissions.toTypedArray(), request.code)"))
        assertTrue(source.contains("super.onRequestPermissionsResult(requestCode, permissions, grantResults)"))
        assertTrue(source.contains("ledger.callback(requestCode, permissions, grantResults)"))
        assertTrue(source.contains("event.repeatCount == 0"))
        assertTrue(source.contains("!event.isCtrlPressed && !event.isAltPressed && !event.isMetaPressed"))
        assertTrue(source.contains("Request CAMERA permission"))
        assertTrue(source.contains("Request LOCATION permissions"))
        assertTrue(source.contains("WONAD_PERMISSION "))
        for (forbidden in listOf("FLAG_ACTIVITY_NEW_TASK", "grantRuntimePermission", "revokeRuntimePermission",
            "startActivity(", "setResult(", "Runtime.getRuntime", "getBooleanExtra")) {
            assertFalse(forbidden, source.contains(forbidden))
        }
    }
}
