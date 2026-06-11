package dev.github.thepanoc95.usersu.server

import android.content.Context
import android.net.Uri
import android.os.IBinder
import android.os.ParcelFileDescriptor
import dev.github.thepanoc95.usersu.IUserSU
import java.io.FileDescriptor

object SuClient {
    @JvmStatic
    fun main(args: Array<String>) {
        val activityThreadClass = Class.forName("android.app.ActivityThread")
        val currentActivityThread = activityThreadClass.getMethod("currentActivityThread").invoke(null)
        val systemContext = activityThreadClass.getMethod("getSystemContext").invoke(currentActivityThread) as Context

        val resolver = systemContext.contentResolver
        val uri = Uri.parse("content://dev.github.thepanoc95.usersu.provider")
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
            System.exit(1)
            return
        }

        val daemon = IUserSU.Stub.asInterface(binder)

        val stdinFd = ParcelFileDescriptor.dup(FileDescriptor.`in`)
        val stdoutFd = ParcelFileDescriptor.dup(FileDescriptor.out)
        val stderrFd = ParcelFileDescriptor.dup(FileDescriptor.err)

        // Simple su flag parsing (e.g. su -c "command")
        val cmdList = mutableListOf<String>()
        var i = 0
        while (i < args.size) {
            if (args[i] == "-c" && i + 1 < args.size) {
                cmdList.add(args[i + 1])
                i += 2
            } else {
                cmdList.add(args[i])
                i++
            }
        }

        val cmd = if (cmdList.isNotEmpty()) cmdList[0] else "/system/bin/sh"
        val remainingArgs = if (cmdList.size > 1) cmdList.subList(1, cmdList.size) else null

        val exitCode = try {
            daemon.executeCommand(cmd, remainingArgs, null, null, stdinFd, stdoutFd, stderrFd)
        } catch (e: Exception) {
            e.printStackTrace()
            -1
        }

        System.exit(exitCode)
    }
}
