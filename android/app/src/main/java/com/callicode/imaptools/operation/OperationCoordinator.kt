package com.callicode.imaptools.operation

import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationState
import com.callicode.imaptools.model.RunStatus
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal data class PendingOperation(
    val operation: Operation,
    val request: String,
    val estimateInProgress: Boolean,
    val allowMeteredNetwork: Boolean,
    val estimatedBytes: Long?,
)

internal object OperationCoordinator {
    private val pending = AtomicReference<PendingOperation?>()
    private val active = AtomicReference<OperationRunner?>()
    private val busy = AtomicBoolean(false)

    @Synchronized
    fun reserve(operation: PendingOperation): Boolean {
        if (!busy.compareAndSet(false, true)) return false
        pending.set(operation)
        return true
    }

    @Synchronized
    fun release(operation: PendingOperation) {
        if (pending.compareAndSet(operation, null)) busy.set(false)
    }

    fun pending(): PendingOperation? = pending.get()

    @Synchronized
    fun attach(operation: PendingOperation, runner: OperationRunner): Boolean {
        if (!pending.compareAndSet(operation, null)) return false
        if (active.compareAndSet(null, runner)) return true
        busy.set(false)
        return false
    }

    @Synchronized
    fun detach(runner: OperationRunner) {
        if (active.compareAndSet(runner, null)) busy.set(false)
    }

    @Synchronized
    fun cancel(message: String? = null): Boolean {
        val runner = active.get()
        if (runner != null) {
            runner.cancel(message)
            return false
        } else if (pending.getAndSet(null) != null) {
            busy.set(false)
            OperationBus.update { state ->
                state.copy(status = RunStatus.CANCELLED)
            }
            return true
        }
        return false
    }

    fun hasWork(): Boolean = busy.get() ||
        OperationBus.state.value.status == RunStatus.RUNNING

    fun markScheduled(operation: Operation) {
        OperationBus.update {
            OperationState(
                status = RunStatus.RUNNING,
                operation = operation,
            )
        }
    }
}
