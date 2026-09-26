package com.callicode.imaptools.storage

import android.content.Context
import android.os.Build
import android.os.storage.StorageManager
import java.io.File

object StorageCapacity {
    const val RESERVED_BYTES = 256L * 1024L * 1024L
    private const val ESTIMATE_MARGIN_PERCENT = 15L

    fun availableBytes(context: Context, path: File = context.filesDir): Long = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = context.getSystemService(StorageManager::class.java)
            manager.getAllocatableBytes(manager.getUuidForPath(path))
        } else {
            path.usableSpace
        }
    }.getOrElse { path.usableSpace }

    fun requiredBytes(estimatedBytes: Long): Long =
        estimatedBytes + (estimatedBytes * ESTIMATE_MARGIN_PERCENT / 100L) + RESERVED_BYTES
}
