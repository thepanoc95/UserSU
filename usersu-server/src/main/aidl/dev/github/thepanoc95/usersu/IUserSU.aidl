package dev.github.thepanoc95.usersu;

import android.os.ParcelFileDescriptor;
import java.util.List;

interface IUserSU {
    int getVersion();

    int executeCommand(
        String command,
        in List<String> args,
        in List<String> envs,
        String workingDir,
        in ParcelFileDescriptor stdin,
        in ParcelFileDescriptor stdout,
        in ParcelFileDescriptor stderr
    );

    int newProcess(
        in List<String> cmdline,
        String workingDir,
        in List<String> envs,
        in ParcelFileDescriptor stdin,
        in ParcelFileDescriptor stdout,
        in ParcelFileDescriptor stderr
    );

    String dispatchCommand(String command);

    String shell(String command);

    int setupKernel();

    void createBranch(String branchName);
    void switchBranch(String branchName);
    void deleteBranch(String branchName);
    List<String> listBranches();
    String getActiveBranch();
    void rollbackActiveBranch();
    void setAppWrapped(String packageName, boolean wrapped);
    boolean isAppWrapped(String packageName);
}
