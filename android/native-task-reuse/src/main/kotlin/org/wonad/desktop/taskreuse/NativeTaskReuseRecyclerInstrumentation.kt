package org.wonad.desktop.taskreuse

import android.app.ActivityManager
import android.app.ActivityOptions
import android.app.Instrumentation
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.SystemClock

/** Self-targeted independent ordinary UID, not the authenticated WM owner. */
class NativeTaskReuseRecyclerInstrumentation : Instrumentation() {
    private lateinit var run: String
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments); run = checkNotNull(arguments?.getString("run"))
        check(run.matches(Regex("[0-9a-f]{32}"))); start()
    }
    private fun phase(name: String, id: Int, count: Int, wraps: Int) = sendStatus(1, Bundle().apply {
        putInt("api",3); putString("scope",NativeTaskReuseSpec.SCOPE); putString("run",run); putString("role","recycler")
        putString("phase",name); putInt("task",id); putInt("count",count); putInt("wraps",wraps)
        putInt("uid",Process.myUid()); putInt("pid",Process.myPid())
    })
    override fun onStart() {
        val report = Bundle(); var outcome = 0
        var seed: android.app.Activity? = null; var thumbnail: Bitmap? = null
        try {
            check(targetContext.packageName == NativeTaskReuseSpec.PACKAGE && targetContext.applicationInfo.uid == Process.myUid())
            check(Process.myUid() in 10000..19999 && targetContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0)
            val component = ComponentName(NativeTaskReuseSpec.PACKAGE, NativeTaskReuseSpec.PACKAGE+".RecyclerActivity")
            val options = ActivityOptions.makeBasic().setLaunchDisplayId(0).toBundle()
            val activeSeed = startActivitySync(Intent().setComponent(component).putExtra("run",run).putExtra("role","seed")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_MULTIPLE_TASK), options)
            seed = activeSeed
            check(activeSeed.taskId > 0 && activeSeed.display?.displayId == 0)
            val manager = targetContext.getSystemService(ActivityManager::class.java)
            val size = manager.appTaskThumbnailSize
            val image = Bitmap.createBitmap(size.width,size.height,Bitmap.Config.ARGB_8888)
            thumbnail = image
            var created = 0
            fun task(): Pair<Int,ActivityManager.AppTask> {
                check(!activeSeed.isDestroyed && !activeSeed.isFinishing)
                val intent = Intent(Intent.ACTION_MAIN).setComponent(component).setData(Uri.parse("wonad-reuse://$run/${created++}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_DOCUMENT or Intent.FLAG_ACTIVITY_MULTIPLE_TASK)
                val id = manager.addAppTask(activeSeed,intent,ActivityManager.TaskDescription.Builder().setLabel("Ordinary task recycler").build(),image)
                check(id in 0..99999)
                return id to manager.appTasks.single { it.taskInfo.taskId == id }.also {
                    check(it.taskInfo.baseIntent.component == component && it.taskInfo.baseIntent.data == intent.data)
                }
            }
            fun launch(value: ActivityManager.AppTask, role: String) {
                value.startActivity(targetContext,Intent(Intent.ACTION_MAIN).setComponent(component)
                    .putExtra("run",run).putExtra("role",role),options)
            }
            NativeTaskReuseSignals(targetContext,run,"recycler").use { signals ->
                val (original,oldTask) = task(); launch(oldTask,"original"); phase("original-launched",original,0,0)
                signals.await("original-closed")
                check(manager.appTasks.none { it.taskInfo.taskId == original })
                phase("original-removed",original,0,0)
                val cycle = NativeTaskReuseSpec(original); var replacement: ActivityManager.AppTask? = null
                val deadline = SystemClock.elapsedRealtime()+1200000
                while (replacement == null) {
                    check(SystemClock.elapsedRealtime()<deadline)
                    val (id,value) = task()
                    if (cycle.observed(id)) replacement = value else value.finishAndRemoveTask()
                    if (cycle.allocations%1000 == 0) phase("allocator-progress",id,cycle.allocations,cycle.wraps)
                }
                check(replacement.taskInfo.taskId == original)
                launch(replacement,"replacement"); phase("replacement-launched",original,cycle.allocations,cycle.wraps)
                signals.await("replacement-closed")
                check(manager.appTasks.none { it.taskInfo.taskId == original })
                report.putInt("task",original); report.putInt("allocations",cycle.allocations); report.putInt("wraps",cycle.wraps)
                report.putString("native_task_reuse_recycler","passed"); outcome=-1
            }
        } catch(error: Throwable) { report.putString("native_task_reuse_recycler","not_passed"); report.putString("failure_details",error.stackTraceToString()) }
        finally {
            try { seed?.let { activity -> runOnMainSync { activity.finishAndRemoveTask() } }; thumbnail?.recycle() }
            catch(error:Throwable) { outcome=0; report.putString("cleanup_error",error.toString()) }
            report.putInt("api",3); report.putString("scope",NativeTaskReuseSpec.SCOPE); report.putString("run",run)
            report.putString("role","recycler"); report.putInt("uid",Process.myUid()); report.putInt("pid",Process.myPid())
            report.putString("fingerprint",Build.FINGERPRINT); report.putString("native_abi",Build.SUPPORTED_ABIS.first())
            finish(outcome,report)
        }
    }
}
