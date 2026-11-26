package org.wonad.desktop.updates

import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class CatalogTest {
    private val key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val build = "2026112601"
    private val now = 1795690000L
    private fun encode(value: ByteArray) = Base64.getEncoder().encodeToString(value)
    private fun payload() = JSONObject().put("format", 1).put("channel", "stable")
        .put("device", "frankel").put("min_os", build).put("max_os", "2026120100")
        .put("issued", now).put("expires", now + 180 * 86400)
        .put("build", build).put("generation", build.toLong())
        .put("apps", JSONObject().apply {
            for ((apk, pkg) in PACKAGES) {
                put(apk, JSONObject().put("package", pkg)
                    .put("version_code", build.toLong() - 2_000_000_000)
                    .put("certificate", "a".repeat(64)).put("sha256", "b".repeat(64))
                    .put("size", 100))
            }
        })
    private fun body(payload: JSONObject = payload(), tamper: Boolean = false): ByteArray {
        val raw = payload.toString().toByteArray()
        val sig = Signature.getInstance("Ed25519").run { initSign(key.private); update(raw); sign() }
        val delivered = if (tamper) raw + " ".toByteArray() else raw
        return JSONObject().put("payload", encode(delivered)).put("signature", encode(sig))
            .toString().toByteArray()
    }
    private fun parse(body: ByteArray = body(), channel: String = "stable", device: String = "frankel",
        os: String = build, current: Long = now) =
        Catalog.parse(body, channel, device, os, current, encode(key.public.encoded))

    @Test fun authenticCatalogAndReplayPolicy() {
        val catalog = parse()
        assertEquals(PACKAGES, catalog.apps.associate { it.name to it.pkg })
        assertTrue(catalog.apps.all { it.url.contains("/desktop-apps-0.1-$build/") })
        assertTrue(catalog.isCurrent(0, null))
        assertTrue(catalog.isCurrent(catalog.generation, catalog.hash))
        assertFalse(catalog.isCurrent(catalog.generation, "different"))
        assertFalse(catalog.isCurrent(catalog.generation + 1, null))
    }

    @Test fun rejectsInvalidSignatureWrongChannelWrongOsAndExpiry() {
        for (attempt in listOf<() -> Catalog>(
            { parse(body(tamper = true)) }, { parse(channel = "beta") },
            { parse(device = "emu64x") }, { parse(os = "2026112600") },
            { parse(os = "2026120101") }, { parse(current = now + 180 * 86400) },
        )) assertThrows(IllegalArgumentException::class.java) { attempt() }
    }

    @Test fun rejectsIncompleteCatalogAndUnexpectedPackages() {
        val incomplete = payload().also { it.getJSONObject("apps").remove("styx.apk") }
        val wrongPackage = payload().also { it.getJSONObject("apps").getJSONObject("styx.apk")
            .put("package", "org.other.app") }
        for (data in listOf(incomplete, wrongPackage))
            assertThrows(IllegalArgumentException::class.java) { parse(body(data)) }
    }
}
