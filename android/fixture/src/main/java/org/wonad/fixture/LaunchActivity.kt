package org.wonad.fixture

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.FrameLayout

/** Separate launcher target: system picker must really launch it, without test extras. */
class LaunchActivity : FixtureActivity() {
    override fun color(): Int = 0xffb9e4c9.toInt()

    override fun onCreate(savedState: Bundle?) {
        super.onCreate(savedState)
        // A real app-owned close action lets the consent test invalidate its
        // selected phone task without any privileged task-removal command.
        val content = findViewById<FrameLayout>(android.R.id.content).getChildAt(0) as LinearLayout
        content.addView(Button(this).apply {
            text = "Finish this fixture window"
            setOnClickListener { finishAndRemoveTask() }
        })
    }
}
