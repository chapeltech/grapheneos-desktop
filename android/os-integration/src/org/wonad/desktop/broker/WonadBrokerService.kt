package org.wonad.desktop.broker

import android.app.Service
import android.content.Intent
import android.os.IBinder

/** Exported, but possessing this Binder is not authorization; each call checks UID/signature. */
class WonadBrokerService : Service() {
    override fun onBind(intent: Intent): IBinder? =
        if (intent.action == WonadController.BIND_ACTION) WonadController.instance?.binder else null
}
