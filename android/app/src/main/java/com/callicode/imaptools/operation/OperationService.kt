package com.callicode.imaptools.operation

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.callicode.imaptools.MainActivity
import com.callicode.imaptools.R
import com.callicode.imaptools.auth.SilentTokenProvider
import com.callicode.imaptools.engine.CancellationSignal
import com.callicode.imaptools.engine.EngineResult
import com.callicode.imaptools.engine.EventListener
import com.callicode.imaptools.engine.PythonEngine
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationEvent
import com.callicode.imaptools.model.OperationState
import com.callicode.imaptools.model.RunStatus
import com.callicode.imaptools.storage.StorageCapacity
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class OperationService : Service() {
    private val executor = Executors.newSingleThreadExecutor()
    private var cancellation: CancellationSignal? = null
    private val forcedFailure = AtomicReference<String?>()
    private var storageMonitor: ScheduledExecutorService? = null

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.operation_channel),
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CANCEL -> cancellation?.cancel() ?: stopSelf(startId)
            ACTION_STORAGE_FAILURE -> {
                forcedFailure.compareAndSet(null, intent.getStringExtra(EXTRA_FAILURE) ?: "Insufficient storage")
                cancellation?.cancel() ?: stopSelf(startId)
            }
            ACTION_START -> start(intent, startId)
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        cancellation?.cancel()
        storageMonitor?.shutdownNow()
        executor.shutdownNow()
        super.onDestroy()
    }

    private fun start(intent: Intent, startId: Int) {
        if (OperationBus.state.value.status == RunStatus.RUNNING) {
            pendingRequest.set(null)
            return
        }
        val pending = pendingRequest.getAndSet(null) ?: return stopSelf(startId)
        val request = pending.request
        val operation = intent.getStringExtra(EXTRA_OPERATION)?.let(Operation::valueOf) ?: return stopSelf(startId)
        val signal = CancellationSignal()
        cancellation = signal
        forcedFailure.set(null)
        val initialEvents = if (operation == Operation.BACKUP && pending.estimateInProgress) {
            listOf(
                OperationEvent(
                    operation = "backup",
                    phase = "storage",
                    message = "Backup started while the storage estimate continues; " +
                        "${formatBytes(StorageCapacity.availableBytes(applicationContext))} available.",
                ),
            )
        } else {
            emptyList()
        }
        OperationBus.update { OperationState(status = RunStatus.RUNNING, operation = operation, events = initialEvents) }
        showNotification("Starting ${operation.title}…", indeterminate = true)

        executor.execute {
            storageMonitor = if (operation == Operation.BACKUP) {
                Executors.newSingleThreadScheduledExecutor().also { monitor ->
                    monitor.scheduleAtFixedRate(
                        {
                            val available = StorageCapacity.availableBytes(applicationContext)
                            if (available < StorageCapacity.RESERVED_BYTES &&
                                forcedFailure.compareAndSet(
                                    null,
                                    "Backup stopped because less than ${formatBytes(StorageCapacity.RESERVED_BYTES)} " +
                                        "of storage remains.",
                                )
                            ) {
                                signal.cancel()
                            }
                        },
                        STORAGE_CHECK_INTERVAL_SECONDS,
                        STORAGE_CHECK_INTERVAL_SECONDS,
                        TimeUnit.SECONDS,
                    )
                }
            } else {
                null
            }
            val result = if (operation == Operation.BACKUP &&
                StorageCapacity.availableBytes(applicationContext) < StorageCapacity.RESERVED_BYTES
            ) {
                EngineResult.Failed(
                    "At least ${formatBytes(StorageCapacity.RESERVED_BYTES)} of available storage is required " +
                        "to start a backup.",
                )
            } else {
                runCatching {
                    PythonEngine().run(
                        request,
                        EventListener { event ->
                            OperationBus.update { state ->
                                state.copy(events = (state.events + event).takeLast(MAX_VISIBLE_EVENTS))
                            }
                            showNotification(event.message, indeterminate = event.total == null)
                        },
                        signal,
                        SilentTokenProvider(applicationContext, request),
                    )
                }.getOrElse { EngineResult.Failed(it.message ?: "Operation failed") }
            }
            storageMonitor?.shutdownNow()
            storageMonitor = null
            val finalResult = forcedFailure.get()?.let(EngineResult::Failed) ?: result
            OperationBus.update { state ->
                when (finalResult) {
                    is EngineResult.Succeeded -> state.copy(status = RunStatus.SUCCEEDED, result = finalResult.result)
                    is EngineResult.Failed -> state.copy(status = RunStatus.FAILED, error = finalResult.message)
                    EngineResult.Cancelled -> state.copy(status = RunStatus.CANCELLED)
                }
            }
            HistoryStore(this).append(OperationBus.state.value)
            cancellation = null
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf(startId)
        }
    }

    private fun showNotification(message: String, indeterminate: Boolean) {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val cancelIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, OperationService::class.java).setAction(ACTION_CANCEL),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle("IMAP Migration Tools")
            .setContentText(message.take(120))
            .setContentIntent(openIntent)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .setProgress(0, 0, indeterminate)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Cancel", cancelIntent)
            .build()
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            notification,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            } else {
                0
            },
        )
    }

    companion object {
        private const val CHANNEL_ID = "imap-operations"
        private const val NOTIFICATION_ID = 1001
        private const val ACTION_START = "com.callicode.imaptools.START"
        private const val ACTION_CANCEL = "com.callicode.imaptools.CANCEL"
        private const val ACTION_STORAGE_FAILURE = "com.callicode.imaptools.STORAGE_FAILURE"
        private const val EXTRA_OPERATION = "operation"
        private const val EXTRA_FAILURE = "failure"
        private const val MAX_VISIBLE_EVENTS = 1000
        private const val STORAGE_CHECK_INTERVAL_SECONDS = 5L
        private val pendingRequest = AtomicReference<PendingOperation?>()

        fun start(
            context: Context,
            operation: Operation,
            request: String,
            estimateInProgress: Boolean = false,
        ): Boolean {
            val pending = PendingOperation(request, estimateInProgress)
            if (!pendingRequest.compareAndSet(null, pending)) return false
            val intent = Intent(context, OperationService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_OPERATION, operation.name)
            return try {
                ContextCompat.startForegroundService(context, intent)
                true
            } catch (exception: RuntimeException) {
                pendingRequest.compareAndSet(pending, null)
                throw exception
            }
        }

        fun cancel(context: Context) {
            context.startService(Intent(context, OperationService::class.java).setAction(ACTION_CANCEL))
        }

        fun stopForInsufficientEstimate(context: Context, message: String) {
            context.startService(
                Intent(context, OperationService::class.java)
                    .setAction(ACTION_STORAGE_FAILURE)
                    .putExtra(EXTRA_FAILURE, message),
            )
        }

        private fun formatBytes(bytes: Long): String = "${bytes / (1024L * 1024L)} MB"

        private data class PendingOperation(val request: String, val estimateInProgress: Boolean)
    }
}
