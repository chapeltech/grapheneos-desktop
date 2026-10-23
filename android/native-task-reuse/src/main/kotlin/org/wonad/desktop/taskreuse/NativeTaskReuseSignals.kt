package org.wonad.desktop.taskreuse

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Handler
import android.os.Looper
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** Public nonce correlation, not an authority credential. Only the host's
 * ordered original broadcasts may advance a reported test phase. */
internal class NativeTaskReuseSignals(private val context: Context, private val run: String,
    private val role: String) : AutoCloseable {
    private val queue = LinkedBlockingQueue<String>()
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == NativeTaskReuseSpec.NEXT && intent.getStringExtra("run") == run &&
                intent.getStringExtra("role") == role) intent.getStringExtra("step")?.let { queue.add(it) }
        }
    }
    init { context.registerReceiver(receiver, IntentFilter(NativeTaskReuseSpec.NEXT), null,
        Handler(Looper.getMainLooper()), Context.RECEIVER_EXPORTED) }
    fun await(step: String, seconds: Long = 90) {
        check(queue.poll(seconds, TimeUnit.SECONDS) == step) { "Missing exact original host phase $role/$step" }
    }
    override fun close() = context.unregisterReceiver(receiver)
}
