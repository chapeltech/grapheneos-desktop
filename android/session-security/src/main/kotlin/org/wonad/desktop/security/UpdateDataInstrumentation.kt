package org.wonad.desktop.security

import android.app.Instrumentation
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.util.Base64
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

/** Exact target process incarnation; CPU ticks/state may legitimately advance.
 * The original complete raw reads are separately reported without trimming.
 */
internal object UpdateDataEpoch {
    fun startTicks(raw: String, ownerPid: Int): Long {
        check(ownerPid > 0 && raw.startsWith("$ownerPid (") && raw.endsWith("\n") &&
            raw.count { it == '\n' } == 1) { "Malformed target proc stat PID/line" }
        val close = raw.lastIndexOf(") ")
        check(close >= raw.indexOf('(')) { "Malformed target proc stat comm" }
        val fields = raw.substring(close + 2).removeSuffix("\n").split(" ")
        check(fields.size > 19 && fields[0].matches(Regex("[A-Z]")) &&
            fields[19].matches(Regex("[1-9][0-9]*"))) { "Malformed target proc start time" }
        return fields[19].toLong().also { check(it > 0) }
    }

    fun verified(before: String, after: String, ownerPid: Int): Long {
        val start = startTicks(before, ownerPid)
        check(start == startTicks(after, ownerPid)) { "Target PID/start epoch changed during canary" }
        return start
    }
}

/** Private-data canary for a version-only APK update. Runs as the ordinary
 * non-debuggable Wonad UID, never Shell. Touches only one random test-owned file;
 * it never clears preferences, removes other data or adds a production endpoint.
 */
class UpdateDataInstrumentation : Instrumentation() {
    private lateinit var arguments: Bundle
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        this.arguments = Bundle(checkNotNull(arguments))
        start()
    }

    override fun onStart() {
        val report = Bundle()
        try {
            val mode = arguments.getString("mode")
            val run = checkNotNull(arguments.getString("run"))
            val nonce = checkNotNull(arguments.getString("nonce"))
            check(mode in listOf("create", "read", "remove"))
            check(run.matches(Regex("[0-9a-f]{32}")) && nonce.matches(Regex("[0-9a-f]{32}")))
            check(targetContext.packageName == "org.wonad.desktop" && Process.myUid() in 10000..19999)
            check(targetContext.applicationInfo.uid == Process.myUid())
            check(targetContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0)
            val ownerPid = Process.myPid()
            val before = String(Files.readAllBytes(Paths.get("/proc/self/stat")), Charsets.UTF_8)
            UpdateDataEpoch.startTicks(before, ownerPid)
            val path = targetContext.filesDir.toPath().resolve("wonad-update-test-$run")
            check(!Files.isSymbolicLink(path))
            if (mode == "create") {
                Files.write(path, nonce.toByteArray(Charsets.UTF_8), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            }
            val existed = Files.exists(path)
            if (mode != "remove" || existed) {
                check(Files.isRegularFile(path) && Files.size(path) == 32L)
                check(Files.readAllBytes(path).contentEquals(nonce.toByteArray(Charsets.UTF_8))) { "Private update canary changed" }
            }
            if (mode == "remove" && existed) Files.delete(path)
            val after = String(Files.readAllBytes(Paths.get("/proc/self/stat")), Charsets.UTF_8)
            val startTicks = UpdateDataEpoch.verified(before, after, ownerPid)
            check(Process.myPid() == ownerPid && targetContext.applicationInfo.uid == Process.myUid())
            report.putString("update_marker", "passed")
            report.putString("mode", mode)
            report.putString("run", run)
            report.putInt("owner_uid", Process.myUid())
            report.putInt("owner_pid", ownerPid)
            report.putLong("owner_start_ticks", startTicks)
            report.putString("proc_stat_before_b64", Base64.encodeToString(before.toByteArray(Charsets.UTF_8), Base64.NO_WRAP))
            report.putString("proc_stat_after_b64", Base64.encodeToString(after.toByteArray(Charsets.UTF_8), Base64.NO_WRAP))
            report.putLong("version_code", targetContext.packageManager.getPackageInfo(targetContext.packageName, 0).longVersionCode)
            report.putString("nonce_sha256", MessageDigest.getInstance("SHA-256").digest(nonce.toByteArray())
                .joinToString("") { "%02x".format(it.toInt() and 255) })
            report.putString("existed", existed.toString())
            report.putString("fingerprint", Build.FINGERPRINT)
            report.putString("native_abi", Build.SUPPORTED_ABIS.first())
            finish(-1, report)
        } catch (error: Throwable) {
            report.putString("update_marker", "not_passed")
            report.putString("failure_details", error.stackTraceToString())
            finish(0, report)
        }
    }
}
