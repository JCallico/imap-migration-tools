package com.callicode.imaptools.operation

import android.app.job.JobParameters
import android.app.job.JobService
import android.os.Build
import androidx.annotation.RequiresApi
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class UserInitiatedTransferJobService : JobService() {
    private val executor = Executors.newSingleThreadExecutor()
    private var runner: OperationRunner? = null
    private val stopped = AtomicBoolean(false)

    override fun onCreate() {
        super.onCreate()
        OperationNotifications.ensureChannel(this)
    }

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun onStartJob(params: JobParameters): Boolean {
        val pending = OperationCoordinator.pending() ?: return false
        val operationRunner = OperationRunner(this, pending) { event ->
            setJobNotification(params, event.message, event.total == null)
        }
        if (!OperationCoordinator.attach(pending, operationRunner)) return false
        runner = operationRunner
        stopped.set(false)
        setJobNotification(params, "Starting ${pending.operation.title}…", true)
        executor.execute {
            try {
                operationRunner.run()
            } finally {
                OperationCoordinator.detach(operationRunner)
                runner = null
                if (!stopped.get()) jobFinished(params, false)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        stopped.set(true)
        runner?.cancel("Transfer stopped by Android. Open the app to start it again.")
        return false
    }

    override fun onDestroy() {
        runner?.cancel()
        executor.shutdownNow()
        super.onDestroy()
    }

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    private fun setJobNotification(params: JobParameters, message: String, indeterminate: Boolean) {
        setNotification(
            params,
            OperationNotifications.NOTIFICATION_ID,
            OperationNotifications.build(this, message, indeterminate),
            JOB_END_NOTIFICATION_POLICY_REMOVE,
        )
    }
}
