package org.wonad.desktop.updates

import android.Manifest
import android.app.*
import android.app.job.*
import android.content.*
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.*
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

private const val NOTICE = "updates"
private const val SESSION = "session"
private const val STATUS = "status"
private val worker = Executors.newSingleThreadExecutor()
private val Context.prefs get() = getSharedPreferences("updates", Context.MODE_PRIVATE)
private val Context.jobs get() = getSystemService(JobScheduler::class.java)
private val Context.notifications get() = getSystemService(NotificationManager::class.java)
private val Context.installer get() = packageManager.packageInstaller
private fun Context.status(text: String) { prefs.edit().putString(STATUS, text).apply() }
private fun Context.channel() = prefs.getString("channel", "stable")!!
private fun Context.enabled() = prefs.getBoolean("automatic", true)
private fun Context.schedule(immediate: Boolean = false) {
    if (!enabled()) {
        jobs.cancel(1)
        jobs.cancel(2)
        return
    }
    fun job(id: Int) = JobInfo.Builder(id, ComponentName(this, UpdateJob::class.java))
        .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED).setRequiresStorageNotLow(true)
    if (jobs.getPendingJob(1) == null)
        jobs.schedule(job(1).setPeriodic(TimeUnit.HOURS.toMillis(8)).setPersisted(true).build())
    if (immediate) jobs.schedule(job(2).setBackoffCriteria(
        TimeUnit.MINUTES.toMillis(10), JobInfo.BACKOFF_POLICY_EXPONENTIAL).build())
}

private fun Context.approvalIntent(id: Int, approval: Intent? = null): PendingIntent? =
    PendingIntent.getActivity(this, id, Intent(this, ApprovalActivity::class.java)
        .setData(Uri.parse("chapeltech-update:session/$id"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        .apply { if (approval != null) putExtra(Intent.EXTRA_INTENT, approval) },
        PendingIntent.FLAG_IMMUTABLE or if (approval == null) PendingIntent.FLAG_NO_CREATE
        else PendingIntent.FLAG_UPDATE_CURRENT)

class UpdatesActivity : Activity() {
    private lateinit var report: TextView
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        notifications.createNotificationChannel(NotificationChannel(NOTICE, "Install approvals",
            NotificationManager.IMPORTANCE_DEFAULT))
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
        }
        report = TextView(this)
        layout.addView(report)
        fun button(label: String, click: () -> Unit) {
            layout.addView(Button(this).apply { text = label; setOnClickListener { click() } })
        }
        layout.addView(Switch(this).apply {
            text = "Automatic updates on unmetered networks"
            isChecked = enabled()
            setOnCheckedChangeListener { _, value ->
                prefs.edit().putBoolean("automatic", value).apply()
                schedule()
            }
        })
        layout.addView(Switch(this).apply {
            text = "Use Beta app releases (independent of OS channel)"
            isChecked = channel() == "beta"
            setOnCheckedChangeListener { _, value ->
                prefs.edit().putString("channel", if (value) "beta" else "stable").apply()
                val context = applicationContext
                worker.execute { context.cancelPending() }
            }
        })
        button("Allow app installation") {
            startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName")))
        }
        button("Enable update approval notifications") {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
            else startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
        }
        button("Install desktop apps / check now") {
            val id = prefs.getInt(SESSION, -1)
            val pending = if (id >= 0) approvalIntent(id) else null
            if (pending != null) runCatching { pending.send() }
            else worker.execute { applicationContext.checkUpdates(true) { true } }
        }
        button("Cancel a pending installation") {
            val context = applicationContext
            worker.execute { context.cancelPending() }
        }
        setContentView(ScrollView(this).apply { addView(layout) })
        schedule()
    }

    private val change = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == STATUS) showStatus()
    }
    private fun showStatus() { report.text = prefs.getString(STATUS, "Install the desktop apps to get started.") }
    override fun onResume() {
        super.onResume()
        prefs.registerOnSharedPreferenceChangeListener(change)
        showStatus()
    }
    override fun onPause() {
        prefs.unregisterOnSharedPreferenceChangeListener(change)
        super.onPause()
    }
}

class ApprovalActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val id = prefs.getInt(SESSION, -1)
        if (id >= 0 && prefs.getString("sessionChannel", null) == channel() &&
            intent.data?.schemeSpecificPart == "session/$id")
            intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)?.let { startActivity(it) }
        finish()
    }
}

class Replaced : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) { context.schedule(immediate = true) }
}

class UpdateJob : JobService() {
    private val active = ConcurrentHashMap<Int, Any>()
    override fun onStartJob(params: JobParameters): Boolean {
        val token = Any()
        active[params.jobId] = token
        worker.execute {
            val retry = active[params.jobId] === token && checkUpdates(false) {
                active[params.jobId] === token && enabled()
            }
            if (active.remove(params.jobId, token)) jobFinished(params, retry)
        }
        return true
    }
    override fun onStopJob(params: JobParameters): Boolean {
        active.remove(params.jobId)
        return enabled()
    }
}

class InstallResult : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) = with(context) {
        val id = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1)
        val root = intent.data?.schemeSpecificPart?.toIntOrNull() ?: return
        if (id < 0 || prefs.getInt(SESSION, -1) != root) return
        val result = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        if (result == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            if (id != root && installer.getSessionInfo(root)?.childSessionIds?.contains(id) != true) return
            val approval = intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java) ?: return
            val pending = approvalIntent(root, approval)
            status("Android requires confirmation. Tap Install desktop apps / check now.")
            if (pending != null && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED) {
                notifications.createNotificationChannel(NotificationChannel(NOTICE, "Install approvals",
                    NotificationManager.IMPORTANCE_DEFAULT))
                notifications.notify(1, Notification.Builder(this, NOTICE)
                    .setContentTitle("Approve ChapelTech app installation").setSmallIcon(android.R.drawable.stat_sys_download)
                    .setContentIntent(pending).setAutoCancel(true).build())
            }
        } else {
            if (id != root) return
            approvalIntent(root)?.cancel()
            notifications.cancel(1)
            clearSession()
            if (result == PackageInstaller.STATUS_SUCCESS) {
                status("Desktop app installation finished.")
                schedule(immediate = true)
            } else status("Android did not install the update. Open Desktop Updates and retry.")
        }
    }
}

private fun Context.clearSession() {
    prefs.edit().remove(SESSION).remove("sessionTime").remove("sessionChannel").apply()
}
private fun Context.cancelPending() {
    val id = prefs.getInt(SESSION, -1)
    if (id < 0) return
    runCatching { installer.abandonSession(id) }
    approvalIntent(id)?.cancel()
    notifications.cancel(1)
    clearSession()
    status("Pending installation cleared. Check again to retry.")
}
private fun fingerprint(info: PackageInfo): String {
    val signers = info.signingInfo?.apkContentsSigners ?: error("Missing APK signer")
    require(signers.size == 1) { "Unexpected APK signers" }
    return digest(signers.single().toByteArray())
}

private val signingFlags = PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
private fun Context.installed(pkg: String): PackageInfo? = try {
    packageManager.getPackageInfo(pkg, signingFlags)
} catch (_: PackageManager.NameNotFoundException) {
    null
}

private fun Context.checkUpdates(manual: Boolean, active: () -> Boolean): Boolean = try {
    runUpdate(manual, active)
    false
} catch (e: IOException) {
    if (active()) status(e.message ?: "Could not reach the update server.")
    true
} catch (e: Exception) {
    if (active()) status(e.message ?: "Could not verify the app update.")
    false
}

private fun Context.runUpdate(manual: Boolean, active: () -> Boolean) {
    val selected = channel()
    val pending = prefs.getInt(SESSION, -1)
    if (pending >= 0) {
        if (installer.getSessionInfo(pending) != null &&
            System.currentTimeMillis() - prefs.getLong("sessionTime", 0) < TimeUnit.HOURS.toMillis(24)) return
        cancelPending()
    }
    if (!packageManager.canRequestPackageInstalls()) {
        status("Allow app installation for ChapelTech Desktop Updates first.")
        return
    }
    // Clean up sessions left by a process death before commit.
    installer.mySessions.filter { !it.isCommitted }.forEach { runCatching { installer.abandonSession(it.sessionId) } }
    status("Checking for updates…")
    val catalog = Catalog.load(selected, Build.DEVICE, Build.VERSION.INCREMENTAL,
        System.currentTimeMillis() / 1000, BuildConfig.CATALOG_KEY)
    val sequenceKey = "generation-$selected"
    val hashKey = "hash-$selected"
    val prior = prefs.getLong(sequenceKey, 0)
    require(catalog.isCurrent(prior, prefs.getString(hashKey, null))) { "Rejected a stale update catalog" }
    val deviceApps = catalog.apps.associateWith { app ->
        val current = installed(app.pkg)
        val expected = if (app.pkg == UPDATER) fingerprint(checkNotNull(current)) else BuildConfig.DESKTOP_CERT
        require(app.cert == expected && (current == null || fingerprint(current) == expected)) {
            "Unexpected signer for ${app.pkg}; installed apps were not changed."
        }
        current?.longVersionCode
    }
    if (!active() || selected != channel()) return
    check(prefs.edit().putLong(sequenceKey, catalog.generation).putString(hashKey, catalog.hash).commit())
    val desktop = catalog.apps.filterNot { it.pkg == UPDATER }
    val updater = catalog.apps.single { it.pkg == UPDATER }
    val changes = desktop.filter { (deviceApps[it] ?: 0) < it.code }
    val mixed = desktop.any { (deviceApps[it] ?: 0) > it.code }
    val batch = when {
        changes.isNotEmpty() && !mixed && (manual || desktop.all { deviceApps[it] != null }) -> changes
        deviceApps.getValue(updater)!! < updater.code -> listOf(updater)
        else -> {
            status(when {
                mixed -> "Installed apps are newer than this channel; no downgrade was attempted."
                desktop.any { deviceApps[it] == null } -> "Open Desktop Updates to install the desktop apps."
                else -> "Desktop apps are up to date."
            })
            return
        }
    }
    stage(batch, selected, manual, active)
}

private fun Context.stage(batch: List<App>, selected: String, manual: Boolean, active: () -> Boolean) {
    val sessions = mutableListOf<Int>()
    val local = File(File(cacheDir, "update").apply { mkdirs() }, "download.apk")
    var committed = false
    fun current() = active() && selected == channel()
    try {
        val parent = if (batch.first().pkg != UPDATER) installer.createSession(PackageInstaller.SessionParams(
            PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply { setMultiPackage() }).also(sessions::add) else null
        val requireApproval = batch.any { installed(it.pkg) == null }
        for (app in batch) {
            if (!current()) return
            val sha = MessageDigest.getInstance("SHA-256")
            val size = https(app.url, true) { input ->
                local.outputStream().use { out ->
                    val buffer = ByteArray(128 * 1024)
                    var length = 0L
                    while (true) {
                        if (!current()) throw IOException("Update check paused")
                        val count = input.read(buffer)
                        if (count < 0) break
                        length += count
                        require(length <= app.bytes) { "APK size does not match the catalog" }
                        sha.update(buffer, 0, count)
                        out.write(buffer, 0, count)
                    }
                    length
                }
            }
            require(size == app.bytes && sha.digest().hex() == app.hash) { "APK digest or size mismatch" }
            val info = packageManager.getPackageArchiveInfo(local.path, signingFlags) ?: error("Invalid APK")
            require(info.packageName == app.pkg && info.longVersionCode == app.code &&
                fingerprint(info) == app.cert) { "APK does not match the catalog identity" }
            if (!manual && installed(app.pkg) == null) return
            val id = installer.createSession(PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                setAppPackageName(app.pkg)
                setSize(size)
                setRequireUserAction(if (requireApproval) PackageInstaller.SessionParams.USER_ACTION_REQUIRED else
                    PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            }).also(sessions::add)
            installer.openSession(id).use { session ->
                session.openWrite("base.apk", 0, size).use { out ->
                    local.inputStream().use { it.copyTo(out) }
                    session.fsync(out)
                }
            }
            if (parent != null) installer.openSession(parent).use { it.addChildSessionId(id) }
            local.delete()
        }
        if (!current()) return
        val id = parent ?: sessions.single()
        val result = PendingIntent.getBroadcast(this, id, Intent(this, InstallResult::class.java)
            .setData(Uri.parse("chapeltech-install:$id")),
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        check(prefs.edit().putInt(SESSION, id).putLong("sessionTime", System.currentTimeMillis())
            .putString("sessionChannel", selected).commit())
        status("Waiting for Android to install the update…")
        try {
            installer.openSession(id).use { it.commit(result.intentSender) }
            committed = true
        } finally {
            if (!committed) clearSession()
        }
    } finally {
        local.delete()
        if (!committed) sessions.forEach { runCatching { installer.abandonSession(it) } }
    }
}
