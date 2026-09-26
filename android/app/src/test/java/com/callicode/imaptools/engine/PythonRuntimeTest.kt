package com.callicode.imaptools.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class PythonRuntimeTest {
    @Before
    fun resetRuntime() {
        PythonRuntime.resetForTest()
    }

    @Test
    fun starterRunsExactlyOnce() {
        val calls = AtomicInteger(0)
        repeat(3) { PythonRuntime.ensureStarted(starter = { calls.incrementAndGet(); Unit }) }
        assertEquals(1, calls.get())
    }

    @Test
    fun concurrentCallersStartOnlyOnce() {
        val calls = AtomicInteger(0)
        val threads = 8
        val ready = CountDownLatch(threads)
        val done = CountDownLatch(threads)
        val pool = Executors.newFixedThreadPool(threads)
        repeat(threads) {
            pool.execute {
                ready.countDown()
                ready.await(10, TimeUnit.SECONDS)
                try {
                    PythonRuntime.ensureStarted(
                        starter = {
                            Thread.sleep(50)
                            calls.incrementAndGet()
                            Unit
                        },
                    )
                } finally {
                    done.countDown()
                }
            }
        }
        assertTrue(done.await(30, TimeUnit.SECONDS))
        pool.shutdownNow()
        assertEquals(1, calls.get())
    }

    @Test
    fun startupFailureIsRecordedAndRetried() {
        val failure = RuntimeException("interpreter failed to start")
        try {
            PythonRuntime.ensureStarted(starter = { throw failure })
            fail("expected the startup failure to propagate")
        } catch (t: Throwable) {
            assertSame(failure, t)
        }
        assertSame(failure, PythonRuntime.lastStartError())

        // A failed start must not latch the runtime as started; the next call retries.
        val calls = AtomicInteger(0)
        PythonRuntime.ensureStarted(starter = { calls.incrementAndGet(); Unit })
        assertEquals(1, calls.get())
        assertNull(PythonRuntime.lastStartError())
    }

    @Test
    fun prewarmRecordsBackgroundFailureWithoutThrowing() {
        PythonRuntime.prewarm()
        // The default starter touches Chaquopy, which is unavailable on the JVM;
        // assert only that prewarm itself never throws from the calling thread and
        // that the background failure is recorded instead of swallowed.
        val deadline = System.currentTimeMillis() + 5_000L
        while (PythonRuntime.lastStartError() == null && System.currentTimeMillis() < deadline) {
            Thread.sleep(50)
        }
        assertTrue(PythonRuntime.lastStartError() != null)
    }
}
