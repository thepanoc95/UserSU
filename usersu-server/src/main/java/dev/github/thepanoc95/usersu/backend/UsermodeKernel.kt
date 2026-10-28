package dev.github.thepanoc95.usersu.backend

object UsermodeKernel {
    private var loaded = false
    private var kernelState = KernelState.HALTED

    enum class KernelState {
        HALTED,
        BOOTING,
        RUNNING,
        PANIC
    }

    fun loadNative(): Boolean {
        if (loaded) return true
        return try {
            System.loadLibrary("usersu_kernel")
            loaded = true
            true
        } catch (e: UnsatisfiedLinkError) {
            System.err.println("[UserSU:Kernel] Failed to load native library: ${e.message}")
            false
        }
    }

    fun boot(cmdline: String = ""): Int {
        if (!loadNative()) return -1
        val rc = nativeInit(cmdline)
        if (rc == 0) kernelState = KernelState.RUNNING
        return rc
    }

    fun shutdown(): Int {
        if (!loaded) return 0
        val rc = nativeShutdown()
        kernelState = KernelState.HALTED
        loaded = false
        return rc
    }

    fun syscall(number: Int, vararg args: Long): Int {
        if (!loaded) return -1
        return nativeSyscall(number, args)
    }

    fun getRoot(): Int {
        if (!loaded) return -1
        return nativeGetRoot()
    }

    fun bypassSELinux(): Int {
        if (!loaded) return -1
        return nativeBypassSELinux()
    }

    fun isRunning(): Boolean {
        if (!loaded) return false
        return nativeIsRunning()
    }

    fun getInfo(): String {
        if (!loaded) return "Kernel not loaded"
        return nativeGetInfo()
    }

    fun forkAndExec(path: String, argv: Array<String> = emptyArray(), envp: Array<String> = emptyArray()): Int {
        if (!loaded) return -1
        return nativeForkAndExec(path, argv, envp)
    }

    fun enterSingleUser(): Int {
        if (!loaded) return -1
        return nativeEnterSingleUser()
    }

    fun mount(source: String, target: String, fstype: String, flags: Long = 0L): Int {
        if (!loaded) return -1
        return nativeMount(source, target, fstype, flags)
    }

    fun umount(target: String, flags: Int = 0): Int {
        if (!loaded) return -1
        return nativeUmount(target, flags)
    }

    fun chroot(path: String): Int {
        if (!loaded) return -1
        return nativeChroot(path)
    }

    fun getKernelState(): KernelState {
        if (!loaded) return KernelState.HALTED
        val state = nativeGetKernelState()
        kernelState = when (state) {
            1 -> KernelState.BOOTING
            2 -> KernelState.RUNNING
            3 -> KernelState.PANIC
            else -> KernelState.HALTED
        }
        return kernelState
    }

    fun getPanicMessage(): String {
        if (!loaded) return ""
        return nativeGetPanicMessage()
    }

    fun getCapabilities(): Int {
        if (!loaded) return 0
        return nativeGetCapabilities()
    }

    fun setCapabilities(caps: Long) {
        if (loaded) nativeSetCapabilities(caps)
    }

    fun grantRootAndShell() {
        if (!loadNative()) return
        bypassSELinux()
        getRoot()
        enterSingleUser()
    }

    private external fun nativeInit(cmdline: String): Int
    private external fun nativeShutdown(): Int
    private external fun nativeSyscall(number: Int, args: LongArray): Int
    private external fun nativeGetRoot(): Int
    private external fun nativeBypassSELinux(): Int
    private external fun nativeIsRunning(): Boolean
    private external fun nativeGetInfo(): String
    private external fun nativeForkAndExec(path: String, argv: Array<String>, envp: Array<String>): Int
    private external fun nativeEnterSingleUser(): Int
    private external fun nativeMount(source: String, target: String, fstype: String, flags: Long): Int
    private external fun nativeUmount(target: String, flags: Int): Int
    private external fun nativeChroot(path: String): Int
    private external fun nativeGetKernelState(): Int
    private external fun nativeGetPanicMessage(): String
    private external fun nativeGetCapabilities(): Int
    private external fun nativeSetCapabilities(caps: Long)
}
