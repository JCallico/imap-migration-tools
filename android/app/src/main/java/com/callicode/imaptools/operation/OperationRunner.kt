package com.callicode.imaptools.operation

import android.content.Context
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

internal class OperationRunner(
    private val context: Context,
    private val pending: PendingOperation,
    private val availableBytes: (Context) -> Long = { StorageCapacity.availableBytes(it) },
    private val onEvent: (OperationEvent) -> Unit,
) {
    private val cancellation = CancellationSignal()
    private val forcedFailure = AtomicReference<String?>()
    private var storageMonitor: ScheduledExecutorService? = null

    fun cancel(message: String? = null) {
        if (message != null) forcedFailure.compareAndSet(null, message)
        cancellation.cancel()
    }

    fun run(): OperationState {
        val operation = pending.operation
        val privacyRedactor = PrivacyRedactor(pending.request, context.filesDir)
        val initialEvents = if (operation == Operation.BACKUP && pending.estimateInProgress) {
            listOf(
                OperationEvent(
                    operation = "backup",
                    phase = "storage",
                    message = "Backup started while the storage estimate continues; " +
                        "${formatBytes(StorageCapacity.availableBytes(context))} available.",
                ),
            )
        } else {
            emptyList()
        }
        OperationBus.update { OperationState(status = RunStatus.RUNNING, operation = operation, events = initialEvents) }

        storageMonitor = if (operation == Operation.BACKUP) {
            Executors.newSingleThreadScheduledExecutor().also { monitor ->
                monitor.scheduleAtFixedRate(
                    {
                        val available = availableBytes(context)
                        if (available < StorageCapacity.RESERVED_BYTES &&
                            forcedFailure.compareAndSet(
                                null,
                                "Backup stopped because less than ${formatBytes(StorageCapacity.RESERVED_BYTES)} " +
                                    "of storage remains.",
                            )
                        ) {
                            cancellation.cancel()
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
            availableBytes(context) < StorageCapacity.RESERVED_BYTES
        ) {
            EngineResult.Failed(
                "At least ${formatBytes(StorageCapacity.RESERVED_BYTES)} of available storage is required " +
                    "to start a backup.",
            )
        } else {
            runCatching {
                PythonEngine().run(
                    pending.request,
                    EventListener { event ->
                        val safeEvent = privacyRedactor.event(event)
                        OperationBus.update { state ->
                            state.copy(events = (state.events + safeEvent).takeLast(MAX_VISIBLE_EVENTS))
                        }
                        onEvent(safeEvent)
                    },
                    cancellation,
                    SilentTokenProvider(context, pending.request),
                )
            }.getOrElse { EngineResult.Failed(it.message ?: "Operation failed") }
        }
        storageMonitor?.shutdownNow()
        storageMonitor = null
        val finalResult = forcedFailure.get()?.let(EngineResult::Failed) ?: result
        OperationBus.update { state ->
            when (finalResult) {
                is EngineResult.Succeeded -> state.copy(
                    status = RunStatus.SUCCEEDED,
                    result = privacyRedactor.text(finalResult.result),
                )
                is EngineResult.Failed -> state.copy(
                    status = RunStatus.FAILED,
                    error = privacyRedactor.text(finalResult.message),
                )
                EngineResult.Cancelled -> state.copy(status = RunStatus.CANCELLED)
            }
        }
        return OperationBus.state.value.also { HistoryStore(context).append(it) }
    }

    private fun formatBytes(bytes: Long): String = "${bytes / (1024L * 1024L)} MB"

    private companion object {
        const val MAX_VISIBLE_EVENTS = 1000
        const val STORAGE_CHECK_INTERVAL_SECONDS = 5L
    }
}
