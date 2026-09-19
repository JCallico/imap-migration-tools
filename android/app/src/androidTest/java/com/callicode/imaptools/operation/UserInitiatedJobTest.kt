package com.callicode.imaptools.operation

import android.app.job.JobInfo
import android.content.Context
import android.net.NetworkCapabilities
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import com.callicode.imaptools.model.Operation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 34)
class UserInitiatedJobTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun backupJobRequiresInternetAndUnmeteredNetworkAndIncludesEstimate() {
        val job = buildUserInitiatedJobInfo(
            context,
            PendingOperation(Operation.BACKUP, "{}", false, false, 1234L),
        )

        assertTrue(job.isUserInitiated)
        assertTrue(job.requiredNetwork?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true)
        assertTrue(job.requiredNetwork?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == true)
        assertTrue(job.isRequireStorageNotLow)
        assertEquals(1234L, job.estimatedNetworkDownloadBytes)
        assertEquals(JobInfo.NETWORK_BYTES_UNKNOWN.toLong(), job.estimatedNetworkUploadBytes)
    }

    @Test
    fun approvedMeteredJobDoesNotRequireUnmeteredNetwork() {
        val job = buildUserInitiatedJobInfo(
            context,
            PendingOperation(Operation.MIGRATE, "{}", false, true, null),
        )

        assertTrue(job.isUserInitiated)
        assertTrue(job.requiredNetwork?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true)
        assertFalse(job.requiredNetwork?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == true)
        assertFalse(job.isRequireStorageNotLow)
    }
}
