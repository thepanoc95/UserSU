package dev.github.thepanoc95.usersu;

import android.os.ParcelFileDescriptor;
import java.util.List;

interface IUserSU {
    int getVersion();
    
    // Command execution in the sandboxed rootFS
    int executeCommand(
        String command, 
        in List<String> args, 
        in List<String> envs, 
        String workingDir, 
        in ParcelFileDescriptor stdin, 
        in ParcelFileDescriptor stdout, 
        in ParcelFileDescriptor stderr
    );

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
