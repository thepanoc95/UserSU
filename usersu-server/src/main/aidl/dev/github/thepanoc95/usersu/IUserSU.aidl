package dev.github.thepanoc95.usersu;

import android.os.ParcelFileDescriptor;
import java.util.List;

interface IUserSU {
    int getVersion();

    // Legacy: execute command in PRoot sandbox
    int executeCommand(
        String command,
        in List<String> args,
        in List<String> envs,
        String workingDir,
        in ParcelFileDescriptor stdin,
        in ParcelFileDescriptor stdout,
        in ParcelFileDescriptor stderr
    );

    // Shizuku-style: execute a command directly (no sandbox) 
    // Returns exit code. stdin/stdout/stderr are forwarded via PFD.
    int newProcess(
        in List<String> cmdline,
        String workingDir,
        in List<String> envs,
        in ParcelFileDescriptor stdin,
        in ParcelFileDescriptor stdout,
        in ParcelFileDescriptor stderr
    );

    // Shizuku-style: get stdout of a simple command as a string
    String dispatchCommand(String command);

    // Shizuku-style: run a shell command and get output
    String shell(String command);

    // Kernel setup: runs startkernel.sh from the app dir
    int setupKernel();

    // Branch management (Git-backed sandbox)
    void createBranch(String branchName);
    void switchBranch(String branchName);
    void deleteBranch(String branchName);
    List<String> listBranches();
    String getActiveBranch();
    void rollbackActiveBranch();

    // App hooking/redirection management
    void setAppWrapped(String packageName, boolean wrapped);
    boolean isAppWrapped(String packageName);
}
