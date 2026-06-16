package dev.github.thepanoc95.usersu.server

import android.content.Context
import android.net.Uri
import android.os.IBinder
import android.os.ParcelFileDescriptor
import dev.github.thepanoc95.usersu.IUserSU
import java.io.File
import java.io.FileDescriptor

object SuClient {
    private const val APP_PKG = "dev.github.thepanoc95.usersu"
    private const val PROVIDER_AUTH = "dev.github.thepanoc95.usersu.provider"

    @JvmStatic
    fun main(args: Array<String>) {
        val activityThreadClass = Class.forName("android.app.ActivityThread")
        val currentActivityThread = activityThreadClass.getMethod("currentActivityThread").invoke(null)
        val systemContext = activityThreadClass.getMethod("getSystemContext").invoke(currentActivityThread) as Context

        val resolver = systemContext.contentResolver
        val uri = Uri.parse("content://$PROVIDER_AUTH")
        val bundle = try {
            resolver.call(uri, "getBinder", null, null)
        } catch (e: Exception) {
            System.err.println("Error: Failed to contact UserSU Provider. Is the Manager app installed?")
            System.exit(1)
            return
        }

        if (bundle == null || !bundle.getBoolean("authorized", false)) {
            System.err.println("Permission denied: App is not authorized in UserSU Manager.")
            System.exit(1)
            return
        }

        val binder = bundle.getBinder("binder")
        if (binder == null) {
            System.err.println("Error: UserSU Daemon is not running.")
            System.err.println("Start it with: adb shell sh /data/data/$APP_PKG/files/bin/start.sh")
            System.exit(1)
            return
        }

        val daemon = IUserSU.Stub.asInterface(binder)

        // ── Parse arguments ──────────────────────────────────────
        // su [--startkernel | -c <command> | --shell]

        val startKernelFlag = args.any { it == "--startkernel" || it == "-k" }

        if (startKernelFlag) {
            // Custom su: run startkernel.sh from the app directory
            val kernelScript = File("/data/data/$APP_PKG/files/bin/startkernel.sh")
            if (!kernelScript.exists()) {
                System.err.println("Error: startkernel.sh not found at ${kernelScript.absolutePath}")
                System.exit(1)
                return
            }
            kernelScript.setExecutable(true)
            val exitCode = try {
                val cmd = listOf("/system/bin/sh", kernelScript.absolutePath)
                val envs = listOf(
                    "HOME=/data/data/$APP_PKG/files",
                    "USER=root",
                    "CLASSPATH=/data/data/$APP_PKG/files/bin/usersu-server.dex",
                    "APP_DIR=/data/data/$APP_PKG/files"
                )
                val stdinFd = ParcelFileDescriptor.dup(FileDescriptor.`in`)
                val stdoutFd = ParcelFileDescriptor.dup(FileDescriptor.out)
                val stderrFd = ParcelFileDescriptor.dup(FileDescriptor.err)
                daemon.newProcess(cmd, "/data/data/$APP_PKG/files", envs, stdinFd, stdoutFd, stderrFd)
            } catch (e: Exception) {
                e.printStackTrace()
                -1
            }
            System.exit(exitCode)
            return
        }

        // ── Normal su behavior ──────────────────────────────────
        val cmdList = mutableListOf<String>()
        var i = 0
        var useShell = false

        while (i < args.size) {
            when (args[i]) {
                "-c" -> {
                    if (i + 1 < args.size) {
                        cmdList.add(args[i + 1])
                        i += 2
                    } else i++
                }
                "--shell", "-s" -> {
                    useShell = true
                    i++
                }
                else -> {
                    cmdList.add(args[i])
                    i++
                }
            }
        }

        if (useShell || cmdList.isEmpty()) {
            // Interactive shell
            val stdinFd = ParcelFileDescriptor.dup(FileDescriptor.`in`)
            val stdoutFd = ParcelFileDescriptor.dup(FileDescriptor.out)
            val stderrFd = ParcelFileDescriptor.dup(FileDescriptor.err)
            val exitCode = try {
                daemon.newProcess(
                    listOf("/system/bin/sh"),
                    null, null, stdinFd, stdoutFd, stderrFd
                )
            } catch (e: Exception) {
                e.printStackTrace()
                -1
            }
            System.exit(exitCode)
            return
        }

        // Single command execution
        val stdinFd = ParcelFileDescriptor.dup(FileDescriptor.`in`)
        val stdoutFd = ParcelFileDescriptor.dup(FileDescriptor.out)
        val stderrFd = ParcelFileDescriptor.dup(FileDescriptor.err)

        val cmd = cmdList[0]
        val remainingArgs = if (cmdList.size > 1) cmdList.subList(1, cmdList.size) else null

        val exitCode = try {
            if (remainingArgs != null) {
                daemon.newProcess(
                    listOf(cmd) + remainingArgs,
                    null, null, stdinFd, stdoutFd, stderrFd
                )
            } else {
                daemon.dispatchCommand(cmd)
                0
            }
        } catch (e: Exception) {
            e.printStackTrace()
            -1
        }

        System.exit(exitCode)
    }
}
