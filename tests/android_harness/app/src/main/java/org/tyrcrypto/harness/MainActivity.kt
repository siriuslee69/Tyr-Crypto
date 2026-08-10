package org.tyrcrypto.harness

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import java.io.File

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val statusView = TextView(this)
        statusView.text = "Running Tyr native harness..."
        setContentView(statusView)

        Thread {
            val output = runHarness()
            File(filesDir, "last_test_output.txt").writeText(output)
            runOnUiThread {
                statusView.text = output
            }
        }.start()
    }

    private fun runHarness(): String {
        return try {
            val libDir = applicationInfo.nativeLibraryDir
            val bin = File(libDir, "libtyrtests.so")
            val traceFile = File(filesDir, "last_trace_output.txt")
            traceFile.delete()
            val proc = ProcessBuilder(bin.absolutePath)
                .apply {
                    environment()["TYR_OTTER_TRACE_PATH"] = traceFile.absolutePath
                    environment()["OTTER_TRACE_PATH"] = traceFile.absolutePath
                }
                .redirectErrorStream(true)
                .start()
            val out = proc.inputStream.bufferedReader().use { it.readText() }
            val code = proc.waitFor()
            "exit=$code\n$out"
        } catch (exc: Throwable) {
            "error=${exc.message}\n${exc.stackTraceToString()}"
        }
    }
}
