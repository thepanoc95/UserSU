package dev.github.thepanoc95.usersu.server

import android.content.ComponentName
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import dev.github.thepanoc95.usersu.IUserSU
import java.io.File
import java.io.InputStream
import java.io.OutputStream

class UserSUServer : IUserSU.Stub() {
    private var activeBranch: String = "main"
    private val branchesDir = File("/data/local/tmp/usersu/branches")
    private val activeLink = File("/data/local/tmp/usersu/active")

    private val appFilesBin = File("/data/data/dev.github.thepanoc95.usersu/files/bin")
    private val appFilesLib = File("/data/data/dev.github.thepanoc95.usersu/files/lib")
    private val localBin = File("/data/local/tmp/usersu/bin")
    private val localLib = File("/data/local/tmp/usersu/lib")

    private val shell = ShellSession.get()

    init {
        localBin.mkdirs()
        localLib.mkdirs()
        branchesDir.mkdirs()

        copyDaemonBinaries()

        val mainBranch = File(branchesDir, "main")
        if (!mainBranch.exists()) {
            mainBranch.mkdirs()
            setupBranchFS(mainBranch)
        }
        if (!activeLink.exists()) {
            createSymlink(mainBranch.absolutePath, activeLink.absolutePath)
        }
    }

    private fun copyDaemonBinaries() {
        val binFiles = listOf("proot", "psu", "psudo", "su", "start.sh", "startkernel.sh")
        for (f in binFiles) {
            val src = File(appFilesBin, f)
            val dst = File(localBin, f)
            if (src.exists()) {
                try {
                    src.copyTo(dst, overwrite = true)
                    dst.setExecutable(true, false)
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }
        val srcHook = File(appFilesLib, "libusersuhook.so")
        val dstHook = File(localLib, "libusersuhook.so")
        if (srcHook.exists()) {
            try {
                srcHook.copyTo(dstHook, overwrite = true)
                dstHook.setReadable(true, false)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    override fun getVersion(): Int = 2

    // ── Legacy: PRoot-sandboxed execution ──────────────────────────
    override fun executeCommand(
        command: String?,
        args: List<String>?,
        envs: List<String>?,
        workingDir: String?,
        stdin: ParcelFileDescriptor?,
        stdout: ParcelFileDescriptor?,
        stderr: ParcelFileDescriptor?
    ): Int {
        val processBuilder = ProcessBuilder()
        val cmdList = mutableListOf(
            "/data/local/tmp/usersu/bin/proot",
            "-r", "/data/local/tmp/usersu/active",
            "-b", "/dev",
            "-b", "/proc",
            "-b", "/sys",
            "-0"
        )
        if (command != null) cmdList.add(command)
        if (args != null) cmdList.addAll(args)
        processBuilder.command(cmdList)
        if (workingDir != null) processBuilder.directory(File(workingDir))
        if (envs != null) {
            val environment = processBuilder.environment()
            for (env in envs) {
                val parts = env.split("=", limit = 2)
                if (parts.size == 2) environment[parts[0]] = parts[1]
            }
        }
        try {
            val process = processBuilder.start()
            val stdinStream = stdin?.let { ParcelFileDescriptor.AutoCloseInputStream(it) }
            val stdoutStream = stdout?.let { ParcelFileDescriptor.AutoCloseOutputStream(it) }
            val stderrStream = stderr?.let { ParcelFileDescriptor.AutoCloseOutputStream(it) }
            val threads = mutableListOf<Thread>()
            if (stdinStream != null) {
                val t = Thread {
                    try {
                        stdinStream.copyTo(process.outputStream)
                        process.outputStream.flush()
                    } catch (_: Exception) {}
                    finally { try { process.outputStream.close() } catch (_: Exception) {} }
                }
                t.start(); threads.add(t)
            }
            if (stdoutStream != null) {
                val t = Thread {
                    try {
                        process.inputStream.copyTo(stdoutStream)
                        stdoutStream.flush()
                    } catch (_: Exception) {}
                    finally { try { stdoutStream.close() } catch (_: Exception) {} }
                }
                t.start(); threads.add(t)
            }
            if (stderrStream != null) {
                val t = Thread {
                    try {
                        process.errorStream.copyTo(stderrStream)
                        stderrStream.flush()
                    } catch (_: Exception) {}
                    finally { try { stderrStream.close() } catch (_: Exception) {} }
                }
                t.start(); threads.add(t)
            }
            val exitCode = process.waitFor()
            for (t in threads) t.join(1000)
            return exitCode
        } catch (e: Exception) {
            e.printStackTrace()
            return -1
        }
    }

    // ── Shizuku-style: direct process execution (no sandbox) ─────
    override fun newProcess(
        cmdline: List<String>?,
        workingDir: String?,
        envs: List<String>?,
        stdin: ParcelFileDescriptor?,
        stdout: ParcelFileDescriptor?,
        stderr: ParcelFileDescriptor?
    ): Int {
        if (cmdline.isNullOrEmpty()) return -1
        return shell.newProcess(cmdline, workingDir, envs, stdin, stdout, stderr)
    }

    override fun dispatchCommand(command: String?): String {
        if (command.isNullOrEmpty()) return ""
        return shell.dispatchCommand(command)
    }

    override fun shell(command: String?): String {
        if (command.isNullOrEmpty()) return ""
        return shell.shell(command)
    }

    // ── Custom su: runs startkernel.sh from the app dir ──────────
    override fun setupKernel(): Int {
        val kernelScript = File(appFilesBin, "startkernel.sh")
        if (!kernelScript.exists()) {
            System.err.println("[UserSU] startkernel.sh not found in ${appFilesBin.absolutePath}")
            return -1
        }
        kernelScript.setExecutable(true)
        return try {
            val pb = ProcessBuilder(
                "/system/bin/sh", "-c",
                "export CLASSPATH=/data/data/dev.github.thepanoc95.usersu/files/bin/usersu-server.dex && ${kernelScript.absolutePath}"
            )
            pb.directory(appFilesBin)
            pb.environment()["HOME"] = appFilesBin.absolutePath
            pb.environment()["USER"] = "root"
            val proc = pb.start()
            val output = proc.inputStream.bufferedReader().readText()
            val error = proc.errorStream.bufferedReader().readText()
            val exit = proc.waitFor()
            if (output.isNotEmpty()) println("[UserSU:kernel] $output")
            if (error.isNotEmpty()) System.err.println("[UserSU:kernel:err] $error")
            exit
        } catch (e: Exception) {
            e.printStackTrace()
            -1
        }
    }

    // ── Branch management ────────────────────────────────────────
    override fun createBranch(branchName: String?) {
        if (branchName.isNullOrEmpty()) return
        val newBranchDir = File(branchesDir, branchName)
        if (newBranchDir.exists()) return
        newBranchDir.mkdirs()
        val activeBranchDir = File(activeLink.canonicalPath)
        copyBranch(activeBranchDir, newBranchDir)
        try {
            runCommand(listOf("git", "init"), newBranchDir)
            runCommand(listOf("git", "add", "."), newBranchDir)
            runCommand(listOf("git", "commit", "-m", "Initial branch creation"), newBranchDir)
        } catch (_: Exception) {}
    }

    override fun switchBranch(branchName: String?) {
        if (branchName.isNullOrEmpty()) return
        val targetBranchDir = File(branchesDir, branchName)
        if (!targetBranchDir.exists()) return
        activeLink.delete()
        createSymlink(targetBranchDir.absolutePath, activeLink.absolutePath)
        activeBranch = branchName
    }

    override fun deleteBranch(branchName: String?) {
        if (branchName.isNullOrEmpty() || branchName == "main" || branchName == activeBranch) return
        val targetBranchDir = File(branchesDir, branchName)
        targetBranchDir.deleteRecursively()
    }

    override fun listBranches(): List<String> {
        return branchesDir.list()?.toList() ?: listOf("main")
    }

    override fun getActiveBranch(): String = activeBranch

    override fun rollbackActiveBranch() {
        val activeBranchDir = File(activeLink.canonicalPath)
        try {
            runCommand(listOf("git", "reset", "--hard", "HEAD"), activeBranchDir)
            runCommand(listOf("git", "clean", "-fd"), activeBranchDir)
        } catch (_: Exception) {}
    }

    // ── App wrapping ─────────────────────────────────────────────
    override fun setAppWrapped(packageName: String?, wrapped: Boolean) {
        if (packageName.isNullOrEmpty()) return
        val propName = "wrap.$packageName"
        val propValue = if (wrapped) "LD_PRELOAD=/data/local/tmp/usersu/lib/libusersuhook.so" else ""
        try {
            runCommand(listOf("setprop", propName, propValue), File("/"))
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun isAppWrapped(packageName: String?): Boolean {
        if (packageName.isNullOrEmpty()) return false
        val propName = "wrap.$packageName"
        return try {
            val process = ProcessBuilder("getprop", propName).start()
            val output = process.inputStream.bufferedReader().readText().trim()
            output.contains("libusersuhook.so")
        } catch (_: Exception) { false }
    }

    // ── Private helpers ──────────────────────────────────────────
    private fun setupBranchFS(branchDir: File) {
        val dirs = listOf("bin", "sbin", "etc", "root", "home", "tmp", "usr/bin", "usr/sbin", "usr/lib", "var")
        for (dir in dirs) File(branchDir, dir).mkdirs()
        val sysBin = File("/system/bin")
        val guestBin = File(branchDir, "bin")
        sysBin.listFiles()?.forEach { file ->
            if (file.isFile) {
                createSymlink(file.absolutePath, File(guestBin, file.name).absolutePath)
            }
        }
    }

    private fun copyBranch(src: File, dst: File) {
        src.walk().forEach { file ->
            val relPath = file.relativeTo(src).path
            if (relPath.isEmpty()) return@forEach
            val target = File(dst, relPath)
            if (file.isDirectory) target.mkdirs()
            else {
                if (isSymlink(file)) {
                    val targetLink = readSymlink(file)
                    createSymlink(targetLink, target.absolutePath)
                } else {
                    file.copyTo(target, overwrite = true)
                }
            }
        }
    }

    private fun isSymlink(file: File): Boolean =
        java.nio.file.Files.isSymbolicLink(file.toPath())

    private fun readSymlink(file: File): String =
        java.nio.file.Files.readSymbolicLink(file.toPath()).toString()

    private fun createSymlink(target: String, link: String) {
        try {
            java.nio.file.Files.createSymbolicLink(
                java.nio.file.Paths.get(link),
                java.nio.file.Paths.get(target)
            )
        } catch (_: Exception) {
            runCommand(listOf("ln", "-s", target, link), File("/"))
        }
    }

    private fun runCommand(cmd: List<String>, workingDir: File) {
        ProcessBuilder(cmd).directory(workingDir).start().waitFor()
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            Looper.prepareMainLooper()
            val server = UserSUServer()
            println("[UserSU] Server daemon v${server.getVersion()} started, registering binder...")

            val amClass = Class.forName("android.app.ActivityManager")
            val amsClass = Class.forName("android.app.IActivityManager\$Stub")
            val asInterface = amsClass.getMethod("asInterface", IBinder::class.java)
            val smClass = Class.forName("android.os.ServiceManager")
            val getService = smClass.getMethod("getService", String::class.java)
            val amBinder = getService.invoke(null, "activity") as IBinder
            val am = asInterface.invoke(null, amBinder)

            val intent = Intent().apply {
                component = ComponentName(
                    "dev.github.thepanoc95.usersu",
                    "dev.github.thepanoc95.usersu.service.UserSUDaemonService"
                )
            }

            // Manual Binder implementation of android.app.IServiceConnection
            // (avoids AIDL compilation issues on different SDK/arch combos)
            val connection = object : Binder() {
                init {
                    attachInterface(this, "android.app.IServiceConnection")
                }

                override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
                    if (code == FIRST_CALL_TRANSACTION) {
                        data.enforceInterface("android.app.IServiceConnection")
                        val name: ComponentName? = if (data.readInt() != 0) {
                            ComponentName.CREATOR.createFromParcel(data)
                        } else null
                        val service = data.readStrongBinder()
                        val dead = data.readInt() != 0
                        connected(name, service, dead)
                        return true
                    }
                    return super.onTransact(code, data, reply, flags)
                }

                private fun connected(name: ComponentName?, service: IBinder?, dead: Boolean) {
                    println("[UserSU] Connected to UserSUDaemonService.")
                    try {
                        val parcel = android.os.Parcel.obtain()
                        val reply = android.os.Parcel.obtain()
                        try {
                            parcel.writeInterfaceToken("dev.github.thepanoc95.usersu.service.IUserSUDaemonService")
                            parcel.writeStrongBinder(server.asBinder())
                            service?.transact(IBinder.FIRST_CALL_TRANSACTION, parcel, reply, 0)
                        } finally {
                            parcel.recycle()
                            reply.recycle()
                        }
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }
                }
            }

            val bindMethod = am.javaClass.methods.firstOrNull {
                it.name == "bindService" || it.name == "bindServiceInstance"
            } ?: throw IllegalStateException("Could not find bindService method on ActivityManager")

            val params = bindMethod.parameterTypes
            val bindArgs = arrayOfNulls<Any>(params.size)
            for (i in params.indices) {
                val type = params[i]
                when {
                    type.isAssignableFrom(Intent::class.java) -> bindArgs[i] = intent
                    type == String::class.java -> {
                        bindArgs[i] = if (i == 3) null else "shell"
                    }
                    type == Int::class.javaPrimitiveType -> {
                        bindArgs[i] = if (i == params.size - 1) 0 else 1
                    }
                    type == Long::class.javaPrimitiveType -> bindArgs[i] = 1L
                    type.name.contains("IApplicationThread") -> bindArgs[i] = null
                    type.name.contains("IBinder") -> bindArgs[i] = null
                    type.name.contains("IServiceConnection") -> bindArgs[i] = connection
                }
            }

            try {
                bindMethod.invoke(am, *bindArgs)
                println("[UserSU] Bind request sent to manager app service.")
            } catch (e: Exception) {
                e.printStackTrace()
            }

            Looper.loop()
        }
    }
}
