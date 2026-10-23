package org.wonad.fixture

import android.app.Activity
import android.app.ActivityManager
import android.os.Bundle
import android.os.Process
import android.util.Log
import org.json.JSONObject

/** Fresh-test setup only: forget this APK's saved tasks using its own authority.
 * Force-stop alone leaves Recents entries which Android's desk restore can
 * relaunch later. No privileged task API or another package's task is used.
 */
class ResetActivity : Activity() {
    override fun onCreate(savedState: Bundle?) {
        super.onCreate(savedState)
        val run = intent.getStringExtra("wonad_run")
        require(run != null && run.matches(Regex("[a-f0-9]{32}")))
        val manager = getSystemService(ActivityManager::class.java)
        val previous = manager.appTasks.filter { it.taskInfo.taskId != taskId }
        // Resolve every root before removing anything, even though getAppTasks
        // itself is already scoped by Android to this unprivileged APK.
        check(previous.all { it.taskInfo.baseIntent.component?.packageName == packageName })
        previous.forEach { it.finishAndRemoveTask() }
        val remaining = manager.appTasks.count { it.taskInfo.taskId != taskId }
        check(remaining == 0) { "Fixture tasks remain in Recents" }
        Log.i("WonadFixtureReset", JSONObject().put("run", run).put("uid", Process.myUid())
            .put("removed", previous.size).put("remaining", remaining).toString())
        finishAndRemoveTask()
    }
}
