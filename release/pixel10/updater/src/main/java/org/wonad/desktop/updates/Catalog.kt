package org.wonad.desktop.updates

import org.json.JSONObject
import java.io.IOException
import java.io.InputStream
import java.net.URI
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.net.ssl.HttpsURLConnection

internal const val BASE = "https://repo.chapeltech.uk/android/"
internal const val UPDATER = "org.wonad.desktop.updates"
internal val PACKAGES = linkedMapOf(
    "controller.apk" to "org.wonad.desktop",
    "styx.apk" to "org.wonad.styx.desktop",
    "xmonad.apk" to "org.wonad.xmonad",
    "desktop-updates.apk" to UPDATER,
)
private const val MAX_CATALOG = 32 * 1024
private const val MAX_APK = 512L * 1024 * 1024
private val sha256 = Regex("[a-f0-9]{64}")
private val buildNumber = Regex("20[0-9]{8}")
internal fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
internal fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).hex()

internal data class App(
    val name: String, val pkg: String, val code: Long, val cert: String,
    val bytes: Long, val hash: String, val release: String,
) {
    val url get() = "https://github.com/chapeltech/grapheneos-desktop/releases/download/$release/$name"
}

internal data class Catalog(val generation: Long, val hash: String, val apps: List<App>) {
    fun isCurrent(previous: Long, previousHash: String?) =
        generation > previous || (generation == previous && hash == previousHash)

    companion object {
        fun load(channel: String, device: String, osBuild: String, now: Long, key: String): Catalog {
            require(channel == "stable" || channel == "beta")
            return https(BASE + "desktop-apps-$channel.json", false) {
                val body = it.readNBytes(MAX_CATALOG + 1)
                require(body.size <= MAX_CATALOG) { "Update catalog too large" }
                parse(body, channel, device, osBuild, now, key)
            }
        }

        fun parse(body: ByteArray, channel: String, device: String, osBuild: String, now: Long, key: String): Catalog {
            val envelope = JSONObject(body.decodeToString(throwOnInvalidSequence = true))
            val payload = Base64.getDecoder().decode(envelope.getString("payload"))
            val signature = Base64.getDecoder().decode(envelope.getString("signature"))
            val publicKey = KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(key)))
            require(signature.size == 64 && Signature.getInstance("Ed25519").run {
                initVerify(publicKey)
                update(payload)
                verify(signature)
            }) { "Invalid update catalog signature" }
            val index = JSONObject(payload.decodeToString(throwOnInvalidSequence = true))
            require(index.getInt("format") == 1 && index.getString("channel") == channel)
            require(device == "frankel" && index.getString("device") == device && buildNumber.matches(osBuild))
            val minOs = index.getString("min_os")
            val maxOs = index.getString("max_os")
            require(buildNumber.matches(minOs) && buildNumber.matches(maxOs) && osBuild in minOs..maxOs) {
                "No app update for this OS build. Check for a system update first."
            }
            val issued = index.getLong("issued")
            val expires = index.getLong("expires")
            require(issued in 1..(now + 300) && expires > now && expires == issued + 180 * 86400) {
                "Update catalog is expired or the phone clock is incorrect"
            }
            val build = index.getString("build")
            require(buildNumber.matches(build))
            val generation = index.getLong("generation")
            require(generation == build.toLong())
            val version = build.toLong() - 2_000_000_000
            val entries = index.getJSONObject("apps")
            require(entries.keys().asSequence().toSet() == PACKAGES.keys)
            val apps = PACKAGES.map { (name, pkg) ->
                val entry = entries.getJSONObject(name)
                require(entry.getString("package") == pkg && entry.getLong("version_code") == version)
                val cert = entry.getString("certificate")
                val hash = entry.getString("sha256")
                val size = entry.getLong("size")
                require(sha256.matches(cert) && sha256.matches(hash) && size in 1..MAX_APK)
                App(name, pkg, version, cert, size, hash, "desktop-apps-0.1-$build")
            }
            return Catalog(generation, digest(payload), apps)
        }
    }
}

internal fun <T> https(url: String, github: Boolean, read: (InputStream) -> T): T {
    val allowed = if (github) setOf("github.com", "release-assets.githubusercontent.com",
        "objects.githubusercontent.com", "github-releases.githubusercontent.com")
    else setOf("repo.chapeltech.uk", "android-ota.chapeltech.uk")
    var uri = URI(url)
    repeat(5) {
        require(uri.scheme == "https" && uri.host in allowed && uri.userInfo == null &&
            uri.port in listOf(-1, 443)) { "Unexpected download host" }
        val connection = uri.toURL().openConnection() as HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            connection.useCaches = false
            when (val status = connection.responseCode) {
                200 -> return connection.inputStream.use(read)
                301, 302, 303, 307, 308 -> uri = uri.resolve(
                    connection.getHeaderField("Location") ?: throw IOException("Missing redirect address"))
                else -> throw IOException("Update server returned HTTP $status")
            }
        } finally {
            connection.disconnect()
        }
    }
    throw IOException("Too many download redirects")
}
