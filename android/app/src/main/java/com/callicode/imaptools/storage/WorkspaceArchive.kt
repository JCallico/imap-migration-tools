package com.callicode.imaptools.storage

import android.content.ContentResolver
import android.net.Uri
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class WorkspaceArchive(
    private val resolver: ContentResolver,
    private val workspaceRoot: File,
) {
    fun export(name: String, destination: Uri) {
        val source = File(workspaceRoot, name)
        require(source.isDirectory) { "Workspace does not exist" }
        val output = resolver.openOutputStream(destination) ?: error("Unable to open export destination")
        output.use { stream ->
            ZipOutputStream(stream.buffered()).use { archive ->
                source.walkTopDown().filter(File::isFile).forEach { file ->
                    val relative = file.relativeTo(source).invariantSeparatorsPath
                    archive.putNextEntry(ZipEntry(relative))
                    file.inputStream().buffered().use { it.copyTo(archive) }
                    archive.closeEntry()
                }
            }
        }
    }

    fun import(name: String, source: Uri) {
        val destination = File(workspaceRoot, name)
        require(!destination.exists()) { "Choose a new workspace name; this workspace already exists" }
        val temporary = File(workspaceRoot, ".import-$name-${System.currentTimeMillis()}")
        check(temporary.mkdirs()) { "Unable to create import workspace" }
        try {
            val input = resolver.openInputStream(source) ?: error("Unable to open backup archive")
            var entries = 0
            var bytes = 0L
            input.use { stream ->
                ZipInputStream(stream.buffered()).use { archive ->
                    while (true) {
                        val entry = archive.nextEntry ?: break
                        entries += 1
                        require(entries <= MAX_ENTRIES) { "Backup archive contains too many files" }
                        val output = File(temporary, entry.name)
                        require(output.canonicalPath.startsWith(temporary.canonicalPath + File.separator)) {
                            "Backup archive contains an unsafe path"
                        }
                        if (entry.isDirectory) {
                            check(output.mkdirs() || output.isDirectory) { "Unable to create backup directory" }
                        } else {
                            val parent = output.parentFile ?: error("Backup entry has no parent directory")
                            check(parent.mkdirs() || parent.isDirectory) { "Unable to create backup directory" }
                            output.outputStream().buffered().use { file ->
                                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                                while (true) {
                                    val count = archive.read(buffer)
                                    if (count < 0) break
                                    bytes += count
                                    require(bytes <= MAX_UNCOMPRESSED_BYTES) { "Backup archive is too large" }
                                    file.write(buffer, 0, count)
                                }
                            }
                        }
                        archive.closeEntry()
                    }
                }
            }
            check(temporary.renameTo(destination)) { "Unable to finalize imported workspace" }
        } finally {
            if (temporary.exists()) temporary.deleteRecursively()
        }
    }

    companion object {
        private const val MAX_ENTRIES = 500_000
        private const val MAX_UNCOMPRESSED_BYTES = 50L * 1024 * 1024 * 1024
    }
}
