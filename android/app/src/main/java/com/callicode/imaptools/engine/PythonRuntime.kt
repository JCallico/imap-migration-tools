package com.callicode.imaptools.engine

import androidx.annotation.VisibleForTesting
import com.chaquo.python.Python
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

/**
 * Owns the embedded CPython runtime lifecycle.
 *
 * Chaquopy starts the interpreter on first [Python.getInstance] access, which unpacks
 * the interpreter and standard library — seconds of disk IO that must never run on
 * the main thread. [ensureStarted] blocks until startup completes and is idempotent:
 * concurrent callers wait on the first starter instead of racing it. [prewarm] hops
 * to a background thread so UI code can trigger an early warm-up without blocking.
 *
 * A failed startup is recorded on [lastStartError] and rethrown to the caller; the
 * next [ensureStarted] call retries instead of caching the failure.
 */
object PythonRuntime {
    private val lock = Any()

    @Volatile
    private var started = false
    private val startError = AtomicReference<Throwable?>(null)
    private val prewarmExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "python-runtime-prewarm").apply { isDaemon = true }
    }

    /**
     * Blocks until the runtime is started. Call only from a background thread.
     *
     * @param starter how to start the runtime; defaults to Chaquopy's first access,
     * which initializes from the application context automatically.
     */
    fun ensureStarted(starter: () -> Unit = { Python.getInstance(); Unit }) {
        if (started) return
        synchronized(lock) {
            if (started) return
            try {
                starter()
                started = true
            } catch (t: Throwable) {
                startError.compareAndSet(null, t)
                throw t
            }
        }
    }

    /**
     * Best-effort background warm-up. Safe to call from the UI thread; startup
     * failures are recorded on [lastStartError] instead of thrown.
     */
    fun prewarm() {
        if (started || startError.get() != null) return
        prewarmExecutor.execute {
            runCatching { ensureStarted() }
        }
    }

    /**
     * The last startup failure, or null when the runtime is healthy or has never
     * been started.
     */
    fun lastStartError(): Throwable? = startError.get()

    @VisibleForTesting
    internal fun resetForTest() {
        synchronized(lock) {
            started = false
            startError.set(null)
        }
    }
}
