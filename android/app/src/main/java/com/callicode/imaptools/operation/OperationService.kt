package com.callicode.imaptools.operation

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors

class OperationService : Service() {
    private val executor = Executors.newSingleThreadExecutor()
    private var runner: OperationRunner? = null

    override fun onCreate() {
        super.onCreate()
        OperationNotifications.ensureChannel(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_START) start(startId)
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        runner?.cancel()
        executor.shutdownNow()
        super.onDestroy()
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        runner?.cancel("Operation stopped because Android's background time limit was reached.")
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf(startId)
    }

    private fun start(startId: Int) {
        val pending = OperationCoordinator.pending() ?: return stopSelf(startId)
        val operationRunner = OperationRunner(this, pending) { event ->
            showNotification(event.message, event.total == null)
        }
        if (!OperationCoordinator.attach(pending, operationRunner)) return stopSelf(startId)
        runner = operationRunner
        showNotification("Starting ${pending.operation.title}…", true)
        executor.execute {
            try {
                operationRunner.run()
            } finally {
                OperationCoordinator.detach(operationRunner)
                runner = null
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf(startId)
            }
        }
    }

    private fun showNotification(message: String, indeterminate: Boolean) {
        ServiceCompat.startForeground(
            this,
            OperationNotifications.NOTIFICATION_ID,
            OperationNotifications.build(this, message, indeterminate),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            } else {
                0
            },
        )
    }

    companion object {
        private const val ACTION_START = "com.callicode.imaptools.START"

        internal fun start(context: Context, pending: PendingOperation): Boolean {
            val intent = Intent(context, OperationService::class.java).setAction(ACTION_START)
            return try {
                ContextCompat.startForegroundService(context, intent)
                true
            } catch (exception: RuntimeException) {
                OperationCoordinator.release(pending)
                false
            }
        }
    }
}
