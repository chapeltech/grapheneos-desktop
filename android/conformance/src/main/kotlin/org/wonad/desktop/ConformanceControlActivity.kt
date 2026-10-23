package org.wonad.desktop

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.view.Gravity
import android.widget.TextView

/** Ordinary phone-side launcher. It starts only a fixed, validated script and
 * conveys no authority or object identity to the broker. */
class ConformanceControlActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var status: TextView
    private var service: ConformanceService.LocalBinder? = null
    private data class Pending(val run: String, val mode: String, val nonce: String)
    private var pending: Pending? = null
    private var bound = false
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service = binder as ConformanceService.LocalBinder
            pending?.let { value ->
                pending = null
                try { service?.start(value.run, value.mode, value.nonce) }
                catch (error: Throwable) { status.text = error.toString() }
            }
        }
        override fun onServiceDisconnected(name: ComponentName) { service = null }
    }
    private val refresh = object : Runnable {
        override fun run() {
            service?.let { status.text = getString(R.string.control_status, it.status()) }
            handler.postDelayed(this, 500)
        }
    }
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        status = TextView(this).apply {
            setTextColor(Color.WHITE); setBackgroundColor(Color.BLACK); gravity = Gravity.CENTER
            text = getString(R.string.control_waiting)
            setPadding(32, 32, 32, 32)
        }
        setContentView(status)
        accept(intent)
    }
    override fun onNewIntent(value: Intent) { super.onNewIntent(value); setIntent(value); accept(value) }
    private fun accept(value: Intent?) {
        if (value?.action != ConformanceContract.ACTION_RUN) return
        val run = value.getStringExtra(ConformanceContract.EXTRA_RUN).orEmpty()
        val mode = value.getStringExtra(ConformanceContract.EXTRA_MODE).orEmpty()
        val nonce = value.getStringExtra(ConformanceContract.EXTRA_NONCE).orEmpty()
        val phase = value.getStringExtra(ConformanceContract.EXTRA_PHASE).orEmpty()
        if (!ConformanceContract.validRun(run) || !ConformanceContract.validMode(mode) ||
            (mode == ConformanceContract.MODE_RUNTIME &&
                (!ConformanceContract.validNonce(nonce) || phase != ConformanceContract.RUNTIME_START))) {
            status.text = getString(R.string.control_rejected); return
        }
        service?.let { try { it.start(run, mode, nonce) } catch (error: Throwable) { status.text = error.toString() } }
            ?: run { pending = Pending(run, mode, nonce) }
    }
    override fun onStart() {
        super.onStart()
        if (!bound) bound = bindService(Intent(this, ConformanceService::class.java), connection, Context.BIND_AUTO_CREATE)
        handler.post(refresh)
    }
    override fun onStop() { handler.removeCallbacks(refresh); super.onStop() }
    override fun onDestroy() {
        if (bound) { unbindService(connection); bound = false }
        super.onDestroy()
    }
}
