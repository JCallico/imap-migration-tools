package com.callicode.imaptools.operation

import android.content.Context
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.RunStatus
import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OperationResilienceTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun largeLocalMailboxCanBeCancelledAndSafelyRetried() {
        val backup = syntheticBackup("cancel-and-retry", folders = 50, messagesPerFolder = 40)
        val pending = localCount(backup)
        lateinit var cancellingRunner: OperationRunner
        cancellingRunner = OperationRunner(context, pending, onEvent = { event ->
            if (event.phase == "scan") cancellingRunner.cancel()
        })

        try {
            val cancelled = cancellingRunner.run()
            assertEquals(RunStatus.CANCELLED, cancelled.status)

            val retried = OperationRunner(context, pending, onEvent = {}).run()
            assertEquals(RunStatus.SUCCEEDED, retried.status)
            assertEquals(2_000, JSONObject(retried.result.orEmpty()).getInt("total"))
        } finally {
            backup.deleteRecursively()
        }
    }

    @Test
    fun systemStopReasonIsRetainedAsAFriendlyFailure() {
        val backup = syntheticBackup("system-stop", folders = 2, messagesPerFolder = 2)
        val pending = localCount(backup)
        lateinit var runner: OperationRunner
        runner = OperationRunner(context, pending, onEvent = { event ->
            if (event.phase == "scan") runner.cancel("Transfer stopped by Android. Open the app to start it again.")
        })

        try {
            val stopped = runner.run()
            assertEquals(RunStatus.FAILED, stopped.status)
            assertEquals("Transfer stopped by Android. Open the app to start it again.", stopped.error)
        } finally {
            backup.deleteRecursively()
        }
    }

    @Test
    fun backupDoesNotStartWhenReservedStorageWouldBeConsumed() {
        val runner = OperationRunner(
            context = context,
            pending = PendingOperation(Operation.BACKUP, "{}", false, false, null),
            onEvent = {},
            availableBytes = { 0L },
        )

        val result = runner.run()

        assertEquals(RunStatus.FAILED, result.status)
        assertTrue(result.error.orEmpty().contains("256 MB"))
    }

    @Test
    @SdkSuppress(maxSdkVersion = 33)
    fun legacyForegroundServiceCompletesWorkWithNoVisibleActivity() {
        val backup = syntheticBackup("legacy-background", folders = 25, messagesPerFolder = 20)

        try {
            assertTrue(
                OperationDispatcher.start(
                    context = context,
                    operation = Operation.COUNT,
                    request = localCount(backup).request,
                ),
            )
            val deadline = SystemClock.elapsedRealtime() + 60_000L
            while (OperationBus.state.value.status == RunStatus.RUNNING && SystemClock.elapsedRealtime() < deadline) {
                SystemClock.sleep(100L)
            }

            val completed = OperationBus.state.value
            assertEquals(RunStatus.SUCCEEDED, completed.status)
            assertEquals(500, JSONObject(completed.result.orEmpty()).getInt("total"))
        } finally {
            OperationDispatcher.cancel(context)
            backup.deleteRecursively()
        }
    }

    private fun localCount(path: File): PendingOperation = PendingOperation(
        operation = Operation.COUNT,
        request = JSONObject()
            .put("operation", "count")
            .put("target", JSONObject().put("kind", "local").put("path", path.absolutePath))
            .toString(),
        estimateInProgress = false,
        allowMeteredNetwork = false,
        estimatedBytes = null,
    )

    private fun syntheticBackup(name: String, folders: Int, messagesPerFolder: Int): File {
        val root = File(context.cacheDir, "resilience/$name").apply {
            deleteRecursively()
            mkdirs()
        }
        repeat(folders) { folderIndex ->
            val folder = File(root, "folder-$folderIndex").apply { mkdirs() }
            repeat(messagesPerFolder) { messageIndex ->
                File(folder, "$messageIndex.eml").writeText(
                    "Subject: Synthetic $folderIndex/$messageIndex\r\n" +
                        "Message-ID: <$folderIndex-$messageIndex@example.invalid>\r\n\r\nBody",
                )
            }
        }
        return root
    }
}
