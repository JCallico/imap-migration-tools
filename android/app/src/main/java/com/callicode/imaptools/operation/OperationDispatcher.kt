package com.callicode.imaptools.operation

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import androidx.annotation.RequiresApi
import com.callicode.imaptools.model.Operation

internal enum class OperationExecutionMode { FOREGROUND_SERVICE, USER_INITIATED_JOB }

internal fun executionMode(apiLevel: Int): OperationExecutionMode =
    if (apiLevel >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        OperationExecutionMode.USER_INITIATED_JOB
    } else {
        OperationExecutionMode.FOREGROUND_SERVICE
    }

object OperationDispatcher {
    fun start(
        context: Context,
        operation: Operation,
        request: String,
        estimateInProgress: Boolean = false,
        allowMeteredNetwork: Boolean = false,
        estimatedBytes: Long? = null,
    ): Boolean {
        val pending = PendingOperation(
            operation = operation,
            request = request,
            estimateInProgress = estimateInProgress,
            allowMeteredNetwork = allowMeteredNetwork,
            estimatedBytes = estimatedBytes?.takeIf { it > 0 },
        )
        if (!OperationCoordinator.reserve(pending)) return false
        OperationCoordinator.markScheduled(operation)
        val started = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            scheduleUserInitiatedJob(context, pending)
        } else {
            OperationService.start(context, pending)
        }
        if (!started) {
            OperationCoordinator.release(pending)
            OperationBus.update { com.callicode.imaptools.model.OperationState() }
        }
        return started
    }

    fun cancel(context: Context) {
        val cancelledBeforeStart = OperationCoordinator.cancel()
        if (cancelledBeforeStart && Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            context.getSystemService(JobScheduler::class.java).cancel(USER_INITIATED_JOB_ID)
        }
    }

    fun stopForInsufficientEstimate(context: Context, message: String) {
        val cancelledBeforeStart = OperationCoordinator.cancel(message)
        if (cancelledBeforeStart && Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            context.getSystemService(JobScheduler::class.java).cancel(USER_INITIATED_JOB_ID)
        }
    }

    fun hasWork(): Boolean = OperationCoordinator.hasWork()

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    private fun scheduleUserInitiatedJob(context: Context, pending: PendingOperation): Boolean {
        return runCatching {
            context.getSystemService(JobScheduler::class.java).schedule(buildUserInitiatedJobInfo(context, pending)) ==
                JobScheduler.RESULT_SUCCESS
        }.getOrDefault(false)
    }

    internal const val USER_INITIATED_JOB_ID = 41001
}

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
internal fun buildUserInitiatedJobInfo(context: Context, pending: PendingOperation): JobInfo {
    val builder = JobInfo.Builder(
        OperationDispatcher.USER_INITIATED_JOB_ID,
        ComponentName(context, UserInitiatedTransferJobService::class.java),
    )
        .setUserInitiated(true)
        .setRequiredNetwork(
            NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .apply {
                    if (!pending.allowMeteredNetwork) {
                        addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                    }
                }
                .build(),
        )
    if (pending.operation == Operation.BACKUP) builder.setRequiresStorageNotLow(true)
    pending.estimatedBytes?.let { bytes ->
        when (pending.operation) {
            Operation.BACKUP -> builder.setEstimatedNetworkBytes(bytes, JobInfo.NETWORK_BYTES_UNKNOWN.toLong())
            Operation.RESTORE -> builder.setEstimatedNetworkBytes(JobInfo.NETWORK_BYTES_UNKNOWN.toLong(), bytes)
            else -> Unit
        }
    }
    return builder.build()
}
