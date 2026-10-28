package dev.github.thepanoc95.usersu.server

import android.os.ParcelFileDescriptor
import java.io.File
import java.io.InputStream
import java.io.OutputStream

class ShellSession {

    fun newProcess(
        cmdline: List<String>,
        workingDir: String?,
        envs: List<String>?,
        stdin: ParcelFileDescriptor?,
        stdout: ParcelFileDescriptor?,
        stderr: ParcelFileDescriptor?
    ): Int {
        val pb = ProcessBuilder(cmdline)
        if (workingDir != null) pb.directory(File(workingDir))
        if (envs != null) {
            val env = pb.environment()
            for (e in envs) {
                val parts = e.split("=", limit = 2)
                if (parts.size == 2) env[parts[0]] = parts[1]
            }
        }
        return try {
            val process = pb.start()
            val threads = mutableListOf<Thread>()

            if (stdin != null) {
                val t = Thread {
                    try {
                        ParcelFileDescriptor.AutoCloseInputStream(stdin)
                            .use { stdinStream -> stdinStream.copyTo(process.outputStream) }
                        process.outputStream.flush()
                    } catch (_: Exception) {
                    } finally {
                        try { process.outputStream.close() } catch (_: Exception) {}
                    }
                }
                t.start(); threads.add(t)
            }

            if (stdout != null) {
                val t = Thread {
                    try {
                        ParcelFileDescriptor.AutoCloseOutputStream(stdout)
                            .use { s -> process.inputStream.copyTo(s) }
                    } catch (_: Exception) {
                    }
                }
                t.start(); threads.add(t)
            }

            if (stderr != null) {
                val t = Thread {
                    try {
                        ParcelFileDescriptor.AutoCloseOutputStream(stderr)
                            .use { s -> process.errorStream.copyTo(s) }
                    } catch (_: Exception) {
                    }
                }
                t.start(); threads.add(t)
            }

            val exit = process.waitFor()
            threads.forEach { it.join(1000) }
            exit
        } catch (e: Exception) {
            e.printStackTrace()
            -1
        }
    }
 
    fun dispatchCommand(command: String): String {
        return try {
            val parts = command.split("\\s+".toRegex())
            val pb = ProcessBuilder(parts)
            val process = pb.start()
            val output = process.inputStream.bufferedReader().readText().trim()
            process.waitFor()
            output
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    fun shell(command: String): String {
        return try {
            val pb = ProcessBuilder("/system/bin/sh", "-c", command)
            val process = pb.start()
            val output = process.inputStream.bufferedReader().readText().trim()
            val error = process.errorStream.bufferedReader().readText().trim()
            process.waitFor()
            if (error.isNotEmpty()) "stderr:\n$error\nstdout:\n$output" else output
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    companion object {
        private var _instance: ShellSession? = null
        fun get(): ShellSession {
            if (_instance == null) _instance = ShellSession()
            return _instance!!
        }
    }
}
