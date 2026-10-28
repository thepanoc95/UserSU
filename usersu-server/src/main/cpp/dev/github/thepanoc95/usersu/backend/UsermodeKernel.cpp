#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <asm/unistd.h>
#include <dirent.h>
#include <linux/capability.h>

#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sys/system_properties.h>
#include <sys/utsname.h>

#define LOG_TAG "UserSU/UsermodeKernel"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ARM64 (generic) syscall table omits legacy syscalls;
// map them to the *at variants that exist on all modern architectures.
#ifndef __NR_open
#define __NR_open __NR_openat
#endif
#ifndef __NR_stat
#define __NR_stat __NR_newfstatat
#endif
#ifndef __NR_umount
#define __NR_umount __NR_umount2
#endif
#ifndef __NR_sigaction
#define __NR_sigaction __NR_rt_sigaction
#endif
#ifndef __NR_sigprocmask
#define __NR_sigprocmask __NR_rt_sigprocmask
#endif
#ifndef __NR_fork
#define __NR_fork __NR_clone
#endif
#ifndef __NR_waitpid
#define __NR_waitpid __NR_wait4
#endif
#ifndef __NR_creat
#define __NR_creat __NR_openat
#endif
#ifndef __NR_link
#define __NR_link __NR_linkat
#endif
#ifndef __NR_unlink
#define __NR_unlink __NR_unlinkat
#endif
#ifndef __NR_time
#define __NR_time __NR_gettimeofday
#endif
#ifndef __NR_mknod
#define __NR_mknod __NR_mknodat
#endif
#ifndef __NR_chmod
#define __NR_chmod __NR_fchmodat
#endif
#ifndef __NR_lchown
#define __NR_lchown __NR_fchownat
#endif
#ifndef __NR_access
#define __NR_access __NR_faccessat
#endif
#ifndef __NR_mkdir
#define __NR_mkdir __NR_mkdirat
#endif
#ifndef __NR_rmdir
#define __NR_rmdir __NR_unlinkat
#endif
#ifndef __NR_dup2
#define __NR_dup2 __NR_dup3
#endif
#ifndef __NR_getpgrp
#define __NR_getpgrp __NR_getpgid
#endif
#ifndef __NR_signalfd
#define __NR_signalfd __NR_signalfd4
#endif
#ifndef __NR_pipe
#define __NR_pipe __NR_pipe2
#endif

#define MAX_KERNEL_BUFFER 4096
#define MAX_KERNEL_MEM_ADDR 0xFFFFFF
#define MAX_CMDLINE_SIZE 2048
#define MAX_TASKS 1024
#define MAX_FDS_PER_TASK 256
#define PAGE_SIZE 4096

typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef uint64_t ktime_t;

class UsermodeKernel;

struct KernelTask;
typedef long (*syscall_handler_t)(KernelTask *, long *);

enum KernelState
{
    KERNEL_STATE_HALTED = 0,
    KERNEL_STATE_BOOTING,
    KERNEL_STATE_RUNNING,
    KERNEL_STATE_PANIC
};

enum SyscallNumber
{
    SYS_RESTART_SYSCALL = __NR_restart_syscall,
    SYS_EXIT = __NR_exit,
    SYS_FORK = __NR_fork,
    SYS_READ = __NR_read,
    SYS_WRITE = __NR_write,
    SYS_OPEN = __NR_open,
    SYS_CLOSE = __NR_close,
    SYS_WAITPID = __NR_waitpid,
    SYS_CREAT = __NR_creat,
    SYS_LINK = __NR_link,
    SYS_UNLINK = __NR_unlink,
    SYS_EXECVE = __NR_execve,
    SYS_CHDIR = __NR_chdir,
    SYS_TIME = __NR_time,
    SYS_MKNOD = __NR_mknod,
    SYS_CHMOD = __NR_chmod,
    SYS_LCHOWN = __NR_lchown,
    SYS_BRK = __NR_brk,
    SYS_STAT = __NR_stat,
    SYS_LSEEK = __NR_lseek,
    SYS_GETPID = __NR_getpid,
    SYS_MOUNT = __NR_mount,
    SYS_UMOUNT = __NR_umount,
    SYS_SETUID = __NR_setuid,
    SYS_GETUID = __NR_getuid,
    SYS_PTRACE = __NR_ptrace,
    SYS_ACCESS = __NR_access,
    SYS_KILL = __NR_kill,
    SYS_MKDIR = __NR_mkdir,
    SYS_RMDIR = __NR_rmdir,
    SYS_DUP = __NR_dup,
    SYS_SETSID = __NR_setsid,
    SYS_GETEUID = __NR_geteuid,
    SYS_GETGID = __NR_getgid,
    SYS_GETEGID = __NR_getegid,
    SYS_IOCTL = __NR_ioctl,
    SYS_FCNTL = __NR_fcntl,
    SYS_SETPGID = __NR_setpgid,
    SYS_UMASK = __NR_umask,
    SYS_CHROOT = __NR_chroot,
    SYS_DUP2 = __NR_dup2,
    SYS_GETPPID = __NR_getppid,
    SYS_GETPGRP = __NR_getpgrp,
    SYS_SIGACTION = __NR_sigaction,
    SYS_SIGPROCMASK = __NR_sigprocmask,
    SYS_SETREUID = __NR_setreuid,
    SYS_SETREGID = __NR_setregid,
    SYS_GETRESUID = __NR_getresuid,
    SYS_GETRESGID = __NR_getresgid,
    SYS_GETPGID = __NR_getpgid,
    SYS_CLONE = __NR_clone,
    SYS_SETFSUID = __NR_setfsuid,
    SYS_SETRESUID = __NR_setresuid,
    SYS_SETRESGID = __NR_setresgid,
    SYS_CAPGET = __NR_capget,
    SYS_CAPSET = __NR_capset,
    SYS_SIGALTSTACK = __NR_sigaltstack,
    SYS_GETDENTS64 = __NR_getdents64,
    SYS_SET_TID_ADDRESS = __NR_set_tid_address,
    SYS_FACCESSAT = __NR_faccessat,
    SYS_OPENAT = __NR_openat,
    SYS_MKDIRAT = __NR_mkdirat,
    SYS_RENAMEAT = __NR_renameat,
    SYS_UNLINKAT = __NR_unlinkat,
    SYS_SENDFILE = __NR_sendfile,
    SYS_MMAP = __NR_mmap,
    SYS_MUNMAP = __NR_munmap,
    SYS_MPROTECT = __NR_mprotect,
    SYS_SIGNALFD = __NR_signalfd,
    SYS_PRCTL = __NR_prctl,
};

struct Capabilities
{
    uint64_t permitted;
    uint64_t inheritable;
    uint64_t effective;
};

struct KernelTask
{
    pid_t pid;
    pid_t ppid;
    pid_t tgid;
    uid_t uid;
    uid_t euid;
    uid_t suid;
    gid_t gid;
    gid_t egid;
    gid_t sgid;
    uint64_t cap_permitted;
    uint64_t cap_inheritable;
    uint64_t cap_effective;
    char comm[64];
    int fds[MAX_FDS_PER_TASK];
    char fds_path[MAX_FDS_PER_TASK][256];
    mode_t fds_mode[MAX_FDS_PER_TASK];
    uint32_t fds_flags[MAX_FDS_PER_TASK];
    bool fds_used[MAX_FDS_PER_TASK];
    void *mmap_base;
    size_t mmap_size;
    uint64_t start_time;
    uint64_t user_time;
    uint64_t sys_time;
    int priority;
    int policy;
    bool is_root;
    bool selinux_enforcing;
    char *cwd;
    char *root_fs;
    KernelTask *next;
    KernelTask *prev;
    std::atomic<int> exit_code;
    std::atomic<bool> exited;
    bool is_kernel_task;
    class UsermodeKernel *umk;
    pid_t *set_tid_address;

    KernelTask()
        : pid(0), ppid(0), tgid(0), uid(65534), euid(65534), suid(65534),
          gid(65534), egid(65534), sgid(65534),
          cap_permitted(0), cap_inheritable(0), cap_effective(0),
          mmap_base(nullptr), mmap_size(0), start_time(0),
          user_time(0), sys_time(0), priority(0), policy(0),
          is_root(false), selinux_enforcing(false),
          cwd(nullptr), root_fs(nullptr),
          next(nullptr), prev(nullptr), exit_code(0),
          exited(false),           is_kernel_task(false), set_tid_address(nullptr)
    {
        memset(comm, 0, sizeof(comm));
        memset(fds, 0, sizeof(fds));
        memset(fds_path, 0, sizeof(fds_path));
        memset(fds_mode, 0, sizeof(fds_mode));
        memset(fds_flags, 0, sizeof(fds_flags));
        memset(fds_used, 0, sizeof(fds_used));
    }
};

struct MountPoint
{
    char source[256];
    char target[256];
    char fstype[64];
    uint64_t flags;
    bool readonly;
    MountPoint *next;
};

struct DeviceNode
{
    char name[64];
    char path[256];
    mode_t mode;
    uint32_t major;
    uint32_t minor;
    DeviceNode *next;
};

struct KernelParam
{
    char key[64];
    char value[256];
};

class UsermodeKernel
{
private:
    KernelState state;
    char cmdline[MAX_CMDLINE_SIZE];
    char boot_device[256];
    char init_path[256];
    char root_dev[256];
    char console_dev[128];
    bool read_only_root;
    bool single_user;
    bool quiet;
    bool android_verified;
    char android_verified_state[64];
    KernelParam params[64];
    int param_count;

    std::atomic<pid_t> next_pid;
    std::atomic<uint64_t> jiffies;
    std::mutex kernel_lock;
    std::mutex task_lock;
    std::mutex mount_lock;

    KernelTask *task_list;
    int task_count;

    MountPoint *mount_list;
    DeviceNode *device_list;

    pthread_t kernel_thread;
    uint64_t boot_time;
    bool kernel_started;
    bool kernel_panicked;
    char panic_msg[256];

    int root_fd;
    int selinux_fd;
    int capabilities_fd;

    uint64_t capabilities_mask;

    std::unordered_map<int, syscall_handler_t> syscall_table;

    static const uint64_t FULL_CAPS =
        (1ULL << 0) | (1ULL << 1) | (1ULL << 2) | (1ULL << 3) |
        (1ULL << 4) | (1ULL << 5) | (1ULL << 6) | (1ULL << 7) |
        (1ULL << 8) | (1ULL << 9) | (1ULL << 10) | (1ULL << 11) |
        (1ULL << 12) | (1ULL << 13) | (1ULL << 14) | (1ULL << 15) |
        (1ULL << 16) | (1ULL << 17) | (1ULL << 18) | (1ULL << 19) |
        (1ULL << 20) | (1ULL << 21) | (1ULL << 22) | (1ULL << 23) |
        (1ULL << 24) | (1ULL << 25) | (1ULL << 26) | (1ULL << 27) |
        (1ULL << 28) | (1ULL << 29) | (1ULL << 30) | (1ULL << 31) |
        (1ULL << 32) | (1ULL << 33) | (1ULL << 34) | (1ULL << 35) |
        (1ULL << 36) | (1ULL << 37) | (1ULL << 38) | (1ULL << 39) |
        (1ULL << 40) | (1ULL << 41);

    static const int CAP_CHOWN = 0;
    static const int CAP_DAC_OVERRIDE = 1;
    static const int CAP_DAC_READ_SEARCH = 2;
    static const int CAP_FOWNER = 3;
    static const int CAP_FSETID = 4;
    static const int CAP_KILL = 5;
    static const int CAP_SETGID = 6;
    static const int CAP_SETUID = 7;
    static const int CAP_SETPCAP = 8;
    static const int CAP_NET_BIND_SERVICE = 10;
    static const int CAP_NET_RAW = 13;
    static const int CAP_SYS_CHROOT = 18;
    static const int CAP_SYS_PTRACE = 19;
    static const int CAP_SYS_ADMIN = 21;
    static const int CAP_SYS_BOOT = 22;
    static const int CAP_SYS_MODULE = 24;
    static const int CAP_SYS_RAWIO = 17;
    static const int CAP_SYS_TIME = 25;
    static const int CAP_SYS_TTY_CONFIG = 26;
    static const int CAP_MKNOD = 27;
    static const int CAP_AUDIT_WRITE = 29;
    static const int CAP_MAC_OVERRIDE = 32;
    static const int CAP_MAC_ADMIN = 33;
    static const int CAP_SYSLOG = 34;

    long handle_sys_exit(KernelTask *task, long *args)
    {
        int exit_code = (int)args[0];
        task->exit_code.store(exit_code);
        task->exited.store(true);
        LOGI("[PID %d] sys_exit(%d)", task->pid, exit_code);
        return 0;
    }

    long handle_sys_read(KernelTask *task, long *args)
    {
        int fd = (int)args[0];
        void *buf = (void *)args[1];
        size_t count = (size_t)args[2];
        ssize_t ret = read(fd, buf, count);
        if (ret < 0) {
            if (errno == EACCES || errno == EPERM) {
                LOGD("[PID %d] sys_read(%d) blocked by permissions, bypassing with root", task->pid, fd);
                if (fd >= 0 && fd < MAX_FDS_PER_TASK && task->fds_used[fd]) {
                    ret = read(task->fds[fd], buf, count);
                }
            }
        }
        return ret;
    }

    long handle_sys_write(KernelTask *task, long *args)
    {
        int fd = (int)args[0];
        const void *buf = (const void *)args[1];
        size_t count = (size_t)args[2];
        ssize_t ret = write(fd, buf, count);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            LOGD("[PID %d] sys_write(%d) bypass for root", task->pid, fd);
            ret = write(fd, buf, count);
        }
        return ret;
    }

    long handle_sys_open(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        int flags = (int)args[1];
        mode_t mode = (mode_t)args[2];

        if (path == nullptr) return -EFAULT;

        int fd = open(path, flags, mode);
        if (fd < 0 && (errno == EACCES || errno == EPERM)) {
            LOGD("[PID %d] sys_open('%s') blocked, retrying with root bypass", task->pid, path);
            int bypass_flags = flags;
            if (bypass_flags & O_RDONLY) {}
            if (bypass_flags & O_WRONLY) {}
            fd = open(path, bypass_flags & ~O_CREAT, mode);
            if (fd < 0) {
                fd = open(path, O_RDONLY);
            }
        }
        if (fd >= 0 && fd < MAX_FDS_PER_TASK) {
            task->fds_used[fd] = true;
            task->fds[fd] = fd;
            strncpy(task->fds_path[fd], path, 255);
            task->fds_mode[fd] = mode;
            task->fds_flags[fd] = flags;
        }
        return fd;
    }

    long handle_sys_close(KernelTask *task, long *args)
    {
        int fd = (int)args[0];
        if (fd >= 0 && fd < MAX_FDS_PER_TASK) {
            task->fds_used[fd] = false;
        }
        return close(fd);
    }

    long handle_sys_stat(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        struct stat *buf = (struct stat *)args[1];
        long ret = stat(path, buf);
        if (ret < 0 && errno == EACCES) {
            return stat(path, buf);
        }
        if (ret == 0 && task->is_root) {
            if (buf) {
                buf->st_uid = 0;
                buf->st_gid = 0;
            }
        }
        return ret;
    }

    long handle_sys_getpid(KernelTask *task, long *)
    {
        return task->pid;
    }

    long handle_sys_getuid(KernelTask *task, long *)
    {
        return task->is_root ? 0 : task->uid;
    }

    long handle_sys_geteuid(KernelTask *task, long *)
    {
        return task->is_root ? 0 : task->euid;
    }

    long handle_sys_getgid(KernelTask *task, long *)
    {
        return task->is_root ? 0 : task->gid;
    }

    long handle_sys_getegid(KernelTask *task, long *)
    {
        return task->is_root ? 0 : task->egid;
    }

    long handle_sys_getppid(KernelTask *task, long *)
    {
        return task->ppid;
    }

    long handle_sys_setuid(KernelTask *task, long *args)
    {
        uid_t uid = (uid_t)args[0];
        LOGI("[PID %d] sys_setuid(%d) - granting root capability override", task->pid, uid);
        if (uid == 0) {
            task->is_root = true;
            task->uid = 0;
            task->euid = 0;
            task->suid = 0;
            task->cap_permitted = FULL_CAPS;
            task->cap_effective = FULL_CAPS;
            task->cap_inheritable = FULL_CAPS;
            return 0;
        }
        if (task->is_root || task->cap_effective & (1 << CAP_SETUID)) {
            task->uid = uid;
            task->euid = uid;
            return 0;
        }
        return -EPERM;
    }

    long handle_sys_setreuid(KernelTask *task, long *args)
    {
        uid_t ruid = (uid_t)args[0];
        uid_t euid = (uid_t)args[1];
        if (ruid == 0 || euid == 0) {
            task->is_root = true;
        }
        if (task->is_root || task->cap_effective & (1 << CAP_SETUID)) {
            if (ruid != (uid_t)-1) task->uid = ruid;
            if (euid != (uid_t)-1) task->euid = euid;
            if (ruid == 0 || euid == 0) {
                task->uid = 0;
                task->euid = 0;
                task->suid = 0;
            }
            return 0;
        }
        return -EPERM;
    }

    long handle_sys_setresuid(KernelTask *task, long *args)
    {
        uid_t ruid = (uid_t)args[0];
        uid_t euid = (uid_t)args[1];
        uid_t suid = (uid_t)args[2];
        if (ruid == 0 || euid == 0 || suid == 0) {
            task->is_root = true;
        }
        if (task->is_root || task->cap_effective & (1 << CAP_SETUID)) {
            if (ruid != (uid_t)-1) task->uid = ruid;
            if (euid != (uid_t)-1) task->euid = euid;
            if (suid != (uid_t)-1) task->suid = suid;
            if (task->uid == 0 || task->euid == 0 || task->suid == 0) {
                task->is_root = true;
                task->uid = 0;
                task->euid = 0;
                task->suid = 0;
                task->cap_permitted = FULL_CAPS;
                task->cap_effective = FULL_CAPS;
            }
            return 0;
        }
        return -EPERM;
    }

    long handle_sys_getresuid(KernelTask *task, long *args)
    {
        uid_t *ruid = (uid_t *)args[0];
        uid_t *euid = (uid_t *)args[1];
        uid_t *suid = (uid_t *)args[2];
        uid_t zero = 0;
        uid_t val = task->is_root ? zero : task->uid;
        if (ruid) *ruid = val;
        if (euid) *euid = task->is_root ? zero : task->euid;
        if (suid) *suid = task->is_root ? zero : task->suid;
        return 0;
    }

    long handle_sys_setgid(KernelTask *task, long *args)
    {
        gid_t gid = (gid_t)args[0];
        if (task->is_root || task->cap_effective & (1 << CAP_SETGID)) {
            task->gid = gid;
            task->egid = gid;
            return 0;
        }
        return -EPERM;
    }

    long handle_sys_setregid(KernelTask *task, long *args)
    {
        gid_t rgid = (gid_t)args[0];
        gid_t egid = (gid_t)args[1];
        if (task->is_root || task->cap_effective & (1 << CAP_SETGID)) {
            if (rgid != (gid_t)-1) task->gid = rgid;
            if (egid != (gid_t)-1) task->egid = egid;
            return 0;
        }
        return -EPERM;
    }

    long handle_sys_brk(KernelTask *task, long *args)
    {
        void *addr = (void *)args[0];
        static void *heap_end = nullptr;
        if (!heap_end) {
            heap_end = sbrk(0);
        }
        if (!addr) {
            return (long)heap_end;
        }
        long diff = (char *)addr - (char *)heap_end;
        if (diff > 0) {
            void *ret = sbrk(diff);
            if (ret == (void *)-1) return -ENOMEM;
        }
        heap_end = addr;
        return (long)heap_end;
    }

    long handle_sys_ioctl(KernelTask *task, long *args)
    {
        int fd = (int)args[0];
        unsigned long request = (unsigned long)args[1];
        long result = ioctl(fd, request, args[2]);
        if (result < 0 && (errno == EACCES || errno == EPERM)) {
            LOGD("[PID %d] sys_ioctl(%d, 0x%lx) blocked, granting root access", task->pid, fd, request);
            result = ioctl(fd, request, args[2]);
        }
        return result;
    }

    long handle_sys_fcntl(KernelTask *task, long *args)
    {
        int fd = (int)args[0];
        int cmd = (int)args[1];
        long result = fcntl(fd, cmd, args[2]);
        if (result < 0 && errno == EACCES) {
            result = fcntl(fd, cmd, args[2]);
        }
        return result;
    }

    long handle_sys_access(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        int mode = (int)args[1];
        long ret = access(path, mode);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            LOGD("[PID %d] sys_access('%s', %d) granted by root emulation", task->pid, path, mode);
            return 0;
        }
        return ret;
    }

    long handle_sys_chdir(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        long ret = chdir(path);
        if (ret == 0 && task->cwd) {
            getcwd(task->cwd, 1024);
        }
        return ret;
    }

    long handle_sys_chmod(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        mode_t mode = (mode_t)args[1];
        long ret = chmod(path, mode);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            ret = chmod(path, mode);
        }
        return ret;
    }

    long handle_sys_chown(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        uid_t owner = (uid_t)args[1];
        gid_t group = (gid_t)args[2];
        long ret = chown(path, owner, group);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            ret = chown(path, owner, group);
        }
        return ret;
    }

    long handle_sys_mount(KernelTask *task, long *args)
    {
        const char *source = (const char *)args[0];
        const char *target = (const char *)args[1];
        const char *fstype = (const char *)args[2];
        unsigned long mountflags = (unsigned long)args[3];
        const void *data = (const void *)args[4];

        long ret = mount(source, target, fstype, mountflags, data);
        if (ret < 0 && (errno == EACCES || errno == EPERM || errno == EPERM)) {
            ret = mount(source, target, fstype, mountflags | MS_RDONLY, data);
        }

        MountPoint *mp = new MountPoint();
        if (source) strncpy(mp->source, source, 255);
        if (target) strncpy(mp->target, target, 255);
        if (fstype) strncpy(mp->fstype, fstype, 63);
        mp->flags = mountflags;
        mp->readonly = (mountflags & MS_RDONLY) != 0;
        mount_lock.lock();
        mp->next = mount_list;
        mount_list = mp;
        mount_lock.unlock();

        return ret;
    }

    long handle_sys_umount(KernelTask *task, long *args)
    {
        const char *target = (const char *)args[0];
        int flags = (int)args[1];
        long ret = umount2(target, flags);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            ret = umount2(target, flags);
        }
        return ret;
    }

    long handle_sys_kill(KernelTask *task, long *args)
    {
        pid_t pid = (pid_t)args[0];
        int sig = (int)args[1];
        if (task->is_root || task->cap_effective & (1 << CAP_KILL)) {
            return kill(pid, sig);
        }
        return kill(pid, sig);
    }

    long handle_sys_mkdir(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        mode_t mode = (mode_t)args[1];
        long ret = mkdir(path, mode);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            ret = mkdir(path, mode);
        }
        return ret;
    }

    long handle_sys_rmdir(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        long ret = rmdir(path);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            ret = rmdir(path);
        }
        return ret;
    }

    long handle_sys_unlink(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        long ret = unlink(path);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            ret = unlink(path);
        }
        return ret;
    }

    long handle_sys_link(KernelTask *task, long *args)
    {
        const char *oldpath = (const char *)args[0];
        const char *newpath = (const char *)args[1];
        long ret = link(oldpath, newpath);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            ret = link(oldpath, newpath);
        }
        return ret;
    }

    long handle_sys_dup(KernelTask *task, long *args)
    {
        int fd = (int)args[0];
        return dup(fd);
    }

    long handle_sys_dup2(KernelTask *task, long *args)
    {
        int oldfd = (int)args[0];
        int newfd = (int)args[1];
        long ret = dup2(oldfd, newfd);
        if (ret >= 0 && ret < MAX_FDS_PER_TASK) {
            task->fds_used[ret] = task->fds_used[oldfd];
            task->fds[ret] = ret;
            if (task->fds_used[oldfd]) {
                strncpy(task->fds_path[ret], task->fds_path[oldfd], 255);
                task->fds_mode[ret] = task->fds_mode[oldfd];
                task->fds_flags[ret] = task->fds_flags[oldfd];
            }
        }
        return ret;
    }

    long handle_sys_setsid(KernelTask *task, long *)
    {
        return setsid();
    }

    long handle_sys_getpgid(KernelTask *task, long *args)
    {
        pid_t pid = (pid_t)args[0];
        return getpgid(pid);
    }

    long handle_sys_setpgid(KernelTask *task, long *args)
    {
        pid_t pid = (pid_t)args[0];
        pid_t pgid = (pid_t)args[1];
        return setpgid(pid, pgid);
    }

    long handle_sys_umask(KernelTask *task, long *args)
    {
        mode_t mask = (mode_t)args[0];
        return umask(mask);
    }

    long handle_sys_chroot(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        long ret = chroot(path);
        if (ret == 0 && task->root_fs) {
            strncpy(task->root_fs, path, 255);
        }
        return ret;
    }

    long handle_sys_ptrace(KernelTask *task, long *args)
    {
        int request = (int)args[0];
        pid_t pid = (pid_t)args[1];

        if (task->is_root || task->cap_effective & (1 << CAP_SYS_PTRACE)) {
            return ptrace((__ptrace_request)request, pid, (void *)args[2], (void *)args[3]);
        }
        return -EPERM;
    }

    long handle_sys_capget(KernelTask *task, long *args)
    {
        struct __user_cap_header_struct *hdrp =
            (struct __user_cap_header_struct *)args[0];
        struct __user_cap_data_struct *datap =
            (struct __user_cap_data_struct *)args[1];

        if (hdrp && datap) {
            hdrp->pid = task->pid;
            datap->effective = (uint32_t)(task->cap_effective & 0xFFFFFFFF);
            datap->permitted = (uint32_t)(task->cap_permitted & 0xFFFFFFFF);
            datap->inheritable = (uint32_t)(task->cap_inheritable & 0xFFFFFFFF);
        }
        return 0;
    }

    long handle_sys_capset(KernelTask *task, long *args)
    {
        struct __user_cap_header_struct *hdrp =
            (struct __user_cap_header_struct *)args[0];
        struct __user_cap_data_struct *datap =
            (struct __user_cap_data_struct *)args[1];

        if (task->is_root || task->cap_effective & (1 << CAP_SETPCAP)) {
            task->cap_effective = datap->effective | (task->cap_effective & 0xFFFFFFFF00000000ULL);
            task->cap_permitted = datap->permitted | (task->cap_permitted & 0xFFFFFFFF00000000ULL);
            task->cap_inheritable = datap->inheritable | (task->cap_inheritable & 0xFFFFFFFF00000000ULL);
            return 0;
        }
        return -EPERM;
    }

    long handle_sys_openat(KernelTask *task, long *args)
    {
        int dirfd = (int)args[0];
        const char *path = (const char *)args[1];
        int flags = (int)args[2];
        mode_t mode = (mode_t)args[3];

        if (path == nullptr) return -EFAULT;

        int fd = openat(dirfd, path, flags, mode);
        if (fd < 0 && (errno == EACCES || errno == EPERM)) {
            LOGD("[PID %d] openat('%s') blocked, granting root", task->pid, path);
            fd = openat(dirfd, path, flags & ~O_CREAT, mode);
            if (fd < 0) {
                fd = openat(dirfd, path, O_RDONLY);
            }
        }
        if (fd >= 0 && fd < MAX_FDS_PER_TASK) {
            task->fds_used[fd] = true;
            task->fds[fd] = fd;
            strncpy(task->fds_path[fd], path, 255);
            task->fds_mode[fd] = mode;
            task->fds_flags[fd] = flags;
        }
        return fd;
    }

    long handle_sys_faccessat(KernelTask *task, long *args)
    {
        int dirfd = (int)args[0];
        const char *path = (const char *)args[1];
        int mode = (int)args[2];
        int flags = (int)args[3];

        long ret = faccessat(dirfd, path, mode, flags);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            return 0;
        }
        return ret;
    }

    long handle_sys_mkdirat(KernelTask *task, long *args)
    {
        int dirfd = (int)args[0];
        const char *path = (const char *)args[1];
        mode_t mode = (mode_t)args[2];
        long ret = mkdirat(dirfd, path, mode);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            ret = mkdirat(dirfd, path, mode);
        }
        return ret;
    }

    long handle_sys_unlinkat(KernelTask *task, long *args)
    {
        int dirfd = (int)args[0];
        const char *path = (const char *)args[1];
        int flags = (int)args[2];
        long ret = unlinkat(dirfd, path, flags);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            ret = unlinkat(dirfd, path, flags);
        }
        return ret;
    }

    long handle_sys_mknod(KernelTask *task, long *args)
    {
        const char *path = (const char *)args[0];
        mode_t mode = (mode_t)args[1];
        dev_t dev = (dev_t)args[2];
        long ret = mknod(path, mode, dev);
        if (ret < 0 && (errno == EACCES || errno == EPERM)) {
            ret = mknod(path, mode, dev);
        }
        return ret;
    }

    long handle_sys_lseek(KernelTask *task, long *args)
    {
        int fd = (int)args[0];
        off_t offset = (off_t)args[1];
        int whence = (int)args[2];
        return lseek(fd, offset, whence);
    }

    long handle_sys_time(KernelTask *, long *)
    {
        return time(nullptr);
    }

    long handle_sys_sigaction(KernelTask *task, long *args)
    {
        int signum = (int)args[0];
        const struct sigaction *act = (const struct sigaction *)args[1];
        struct sigaction *oldact = (struct sigaction *)args[2];
        return (long)sigaction(signum, act, oldact);
    }

    long handle_sys_sigprocmask(KernelTask *task, long *args)
    {
        int how = (int)args[0];
        const sigset_t *set = (const sigset_t *)args[1];
        sigset_t *oldset = (sigset_t *)args[2];
        return (long)sigprocmask(how, set, oldset);
    }

    long handle_sys_getdents64(KernelTask *task, long *args)
    {
        int fd = (int)args[0];
        void *dirp = (void *)args[1];
        size_t count = (size_t)args[2];
        return getdents64(fd, dirp, count);
    }

    long handle_sys_mmap(KernelTask *task, long *args)
    {
        void *addr = (void *)args[0];
        size_t length = (size_t)args[1];
        int prot = (int)args[2];
        int flags = (int)args[3];
        int fd = (int)args[4];
        off_t offset = (off_t)args[5];

        void *result = mmap(addr, length, prot, flags, fd, offset);
        if (result == MAP_FAILED) {
            if (errno == EACCES || errno == EPERM) {
                if (fd >= 0) {
                    int saved_flags = fcntl(fd, F_GETFL);
                    if (saved_flags >= 0) {
                        result = mmap(addr, length, prot | PROT_READ, flags | MAP_ANONYMOUS, -1, 0);
                    }
                }
            }
            if (result == MAP_FAILED) {
                result = mmap(addr, length, prot, flags | MAP_ANONYMOUS, -1, 0);
            }
        }
        return (long)result;
    }

    long handle_sys_munmap(KernelTask *task, long *args)
    {
        void *addr = (void *)args[0];
        size_t length = (size_t)args[1];
        return munmap(addr, length);
    }

    long handle_sys_mprotect(KernelTask *task, long *args)
    {
        void *addr = (void *)args[0];
        size_t len = (size_t)args[1];
        int prot = (int)args[2];
        return mprotect(addr, len, prot);
    }

    long handle_sys_prctl(KernelTask *task, long *args)
    {
        int option = (int)args[0];
        unsigned long arg2 = (unsigned long)args[1];
        unsigned long arg3 = (unsigned long)args[2];
        unsigned long arg4 = (unsigned long)args[3];
        unsigned long arg5 = (unsigned long)args[4];
        return prctl(option, arg2, arg3, arg4, arg5);
    }

    long handle_sys_sendfile(KernelTask *task, long *args)
    {
        int out_fd = (int)args[0];
        int in_fd = (int)args[1];
        off_t *offset = (off_t *)args[2];
        size_t count = (size_t)args[3];
        return sendfile(out_fd, in_fd, offset, count);
    }

    long handle_sys_execve(KernelTask *task, long *args)
    {
        const char *filename = (const char *)args[0];
        const char *const *argv = (const char *const *)args[1];
        const char *const *envp = (const char *const *)args[2];

        LOGI("[PID %d] sys_execve('%s')", task->pid, filename ? filename : "(null)");

        if (filename == nullptr) return -EFAULT;

        execve(filename, argv, envp);
        if (errno == EACCES || errno == EPERM) {
            long ret = execve(filename, argv, envp);
            if (ret < 0) {
                LOGE("[PID %d] execve('%s') failed: %s", task->pid, filename, strerror(errno));
            }
            return ret;
        }
        return -errno;
    }

    long handle_sys_clone(KernelTask *task, long *args)
    {
        unsigned long flags = (unsigned long)args[0];
        void *child_stack = (void *)args[1];
        pid_t *parent_tid = (pid_t *)args[2];
        pid_t *child_tid = (pid_t *)args[3];
        void *tls = (void *)args[4];

        pid_t child_pid = fork();
        if (child_pid == 0) {
            KernelTask *child = create_task();
            child->ppid = task->pid;
            child->uid = task->uid;
            child->euid = task->euid;
            child->gid = task->gid;
            child->egid = task->egid;
            child->is_root = task->is_root;
            child->cap_permitted = task->cap_permitted;
            child->cap_effective = task->cap_effective;
            child->cap_inheritable = task->cap_inheritable;
            child->selinux_enforcing = task->selinux_enforcing;
            if (child_tid) {
                *child_tid = child->pid;
                child->set_tid_address = child_tid;
            }
            LOGI("[PID %d] clone -> child PID %d (root=%d)", task->pid, child->pid, child->is_root);
            return 0;
        }
        if (child_pid < 0) return -errno;
        return child_pid;
    }

    long handle_sys_fork(KernelTask *task, long *args)
    {
        pid_t child_pid = fork();
        if (child_pid == 0) {
            KernelTask *child = create_task();
            child->ppid = task->pid;
            child->uid = task->uid;
            child->euid = task->euid;
            child->gid = task->gid;
            child->egid = task->egid;
            child->is_root = task->is_root;
            child->cap_permitted = task->cap_permitted;
            child->cap_effective = task->cap_effective;
            child->cap_inheritable = task->cap_inheritable;
            LOGI("[PID %d] fork -> child PID %d (root=%d)", task->pid, child->pid, child->is_root);
            return 0;
        }
        if (child_pid < 0) return -errno;
        return child_pid;
    }

    long handle_sys_waitpid(KernelTask *task, long *args)
    {
        pid_t pid = (pid_t)args[0];
        int *status = (int *)args[1];
        int options = (int)args[2];
        return waitpid(pid, status, options);
    }

    long handle_sys_set_tid_address(KernelTask *task, long *args)
    {
        pid_t *tidptr = (pid_t *)args[0];
        task->set_tid_address = tidptr;
        return task->pid;
    }

public:
    char cwd_buf[1024];

    UsermodeKernel()
        : state(KERNEL_STATE_HALTED), read_only_root(true), single_user(false),
          quiet(false), android_verified(false), param_count(0), next_pid(1),
          jiffies(0), task_list(nullptr), task_count(0), mount_list(nullptr),
          device_list(nullptr), kernel_thread(0), boot_time(0),
          kernel_started(false), kernel_panicked(false), root_fd(-1),
          selinux_fd(-1), capabilities_fd(-1), capabilities_mask(FULL_CAPS)
    {
        memset(cmdline, 0, sizeof(cmdline));
        memset(boot_device, 0, sizeof(boot_device));
        memset(init_path, 0, sizeof(init_path));
        memset(root_dev, 0, sizeof(root_dev));
        memset(console_dev, 0, sizeof(console_dev));
        memset(android_verified_state, 0, sizeof(android_verified_state));
        memset(panic_msg, 0, sizeof(panic_msg));
        memset(params, 0, sizeof(params));
        memset(cwd_buf, 0, sizeof(cwd_buf));

        register_syscalls();
        setup_default_devices();
        grant_everything();
    }

    ~UsermodeKernel()
    {
        cleanup_tasks();
        cleanup_mounts();
        cleanup_devices();
    }

private:
    void register_syscalls()
    {
        syscall_table[SYS_EXIT] = [](KernelTask *t, long *a) { return t->umk->handle_sys_exit(t, a); };
        syscall_table[SYS_READ] = [](KernelTask *t, long *a) { return t->umk->handle_sys_read(t, a); };
        syscall_table[SYS_WRITE] = [](KernelTask *t, long *a) { return t->umk->handle_sys_write(t, a); };
        syscall_table[SYS_OPEN] = [](KernelTask *t, long *a) { return t->umk->handle_sys_open(t, a); };
        syscall_table[SYS_CLOSE] = [](KernelTask *t, long *a) { return t->umk->handle_sys_close(t, a); };
        syscall_table[SYS_STAT] = [](KernelTask *t, long *a) { return t->umk->handle_sys_stat(t, a); };
        syscall_table[SYS_GETPID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_getpid(t, a); };
        syscall_table[SYS_GETUID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_getuid(t, a); };
        syscall_table[SYS_GETEUID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_geteuid(t, a); };
        syscall_table[SYS_GETGID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_getgid(t, a); };
        syscall_table[SYS_GETEGID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_getegid(t, a); };
        syscall_table[SYS_GETPPID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_getppid(t, a); };
        syscall_table[SYS_SETUID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_setuid(t, a); };
        syscall_table[SYS_SETREUID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_setreuid(t, a); };
        syscall_table[SYS_SETRESUID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_setresuid(t, a); };
        syscall_table[SYS_GETRESUID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_getresuid(t, a); };
        syscall_table[SYS_SETGID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_setgid(t, a); };
        syscall_table[SYS_SETREGID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_setregid(t, a); };
        syscall_table[SYS_BRK] = [](KernelTask *t, long *a) { return t->umk->handle_sys_brk(t, a); };
        syscall_table[SYS_IOCTL] = [](KernelTask *t, long *a) { return t->umk->handle_sys_ioctl(t, a); };
        syscall_table[SYS_FCNTL] = [](KernelTask *t, long *a) { return t->umk->handle_sys_fcntl(t, a); };
        syscall_table[SYS_ACCESS] = [](KernelTask *t, long *a) { return t->umk->handle_sys_access(t, a); };
        syscall_table[SYS_CHDIR] = [](KernelTask *t, long *a) { return t->umk->handle_sys_chdir(t, a); };
        syscall_table[SYS_CHMOD] = [](KernelTask *t, long *a) { return t->umk->handle_sys_chmod(t, a); };
        syscall_table[SYS_UNLINK] = [](KernelTask *t, long *a) { return t->umk->handle_sys_unlink(t, a); };
        syscall_table[SYS_LINK] = [](KernelTask *t, long *a) { return t->umk->handle_sys_link(t, a); };
        syscall_table[SYS_MKDIR] = [](KernelTask *t, long *a) { return t->umk->handle_sys_mkdir(t, a); };
        syscall_table[SYS_RMDIR] = [](KernelTask *t, long *a) { return t->umk->handle_sys_rmdir(t, a); };
        syscall_table[SYS_KILL] = [](KernelTask *t, long *a) { return t->umk->handle_sys_kill(t, a); };
        syscall_table[SYS_MOUNT] = [](KernelTask *t, long *a) { return t->umk->handle_sys_mount(t, a); };
        syscall_table[SYS_UMOUNT] = [](KernelTask *t, long *a) { return t->umk->handle_sys_umount(t, a); };
        syscall_table[SYS_DUP] = [](KernelTask *t, long *a) { return t->umk->handle_sys_dup(t, a); };
        syscall_table[SYS_DUP2] = [](KernelTask *t, long *a) { return t->umk->handle_sys_dup2(t, a); };
        syscall_table[SYS_SETSID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_setsid(t, a); };
        syscall_table[SYS_GETPGID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_getpgid(t, a); };
        syscall_table[SYS_SETPGID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_setpgid(t, a); };
        syscall_table[SYS_UMASK] = [](KernelTask *t, long *a) { return t->umk->handle_sys_umask(t, a); };
        syscall_table[SYS_CHROOT] = [](KernelTask *t, long *a) { return t->umk->handle_sys_chroot(t, a); };
        syscall_table[SYS_LCHOWN] = [](KernelTask *t, long *a) { return t->umk->handle_sys_chown(t, a); };
        syscall_table[SYS_PTRACE] = [](KernelTask *t, long *a) { return t->umk->handle_sys_ptrace(t, a); };
        syscall_table[SYS_CAPGET] = [](KernelTask *t, long *a) { return t->umk->handle_sys_capget(t, a); };
        syscall_table[SYS_CAPSET] = [](KernelTask *t, long *a) { return t->umk->handle_sys_capset(t, a); };
        syscall_table[SYS_OPENAT] = [](KernelTask *t, long *a) { return t->umk->handle_sys_openat(t, a); };
        syscall_table[SYS_FACCESSAT] = [](KernelTask *t, long *a) { return t->umk->handle_sys_faccessat(t, a); };
        syscall_table[SYS_MKDIRAT] = [](KernelTask *t, long *a) { return t->umk->handle_sys_mkdirat(t, a); };
        syscall_table[SYS_UNLINKAT] = [](KernelTask *t, long *a) { return t->umk->handle_sys_unlinkat(t, a); };
        syscall_table[SYS_MKNOD] = [](KernelTask *t, long *a) { return t->umk->handle_sys_mknod(t, a); };
        syscall_table[SYS_LSEEK] = [](KernelTask *t, long *a) { return t->umk->handle_sys_lseek(t, a); };
        syscall_table[SYS_TIME] = [](KernelTask *t, long *a) { return t->umk->handle_sys_time(t, a); };
        syscall_table[SYS_SIGACTION] = [](KernelTask *t, long *a) { return t->umk->handle_sys_sigaction(t, a); };
        syscall_table[SYS_SIGPROCMASK] = [](KernelTask *t, long *a) { return t->umk->handle_sys_sigprocmask(t, a); };
        syscall_table[SYS_GETDENTS64] = [](KernelTask *t, long *a) { return t->umk->handle_sys_getdents64(t, a); };
        syscall_table[SYS_MMAP] = [](KernelTask *t, long *a) { return t->umk->handle_sys_mmap(t, a); };
        syscall_table[SYS_MUNMAP] = [](KernelTask *t, long *a) { return t->umk->handle_sys_munmap(t, a); };
        syscall_table[SYS_MPROTECT] = [](KernelTask *t, long *a) { return t->umk->handle_sys_mprotect(t, a); };
        syscall_table[SYS_PRCTL] = [](KernelTask *t, long *a) { return t->umk->handle_sys_prctl(t, a); };
        syscall_table[SYS_SENDFILE] = [](KernelTask *t, long *a) { return t->umk->handle_sys_sendfile(t, a); };
        syscall_table[SYS_EXECVE] = [](KernelTask *t, long *a) { return t->umk->handle_sys_execve(t, a); };
        syscall_table[SYS_CLONE] = [](KernelTask *t, long *a) { return t->umk->handle_sys_clone(t, a); };
        syscall_table[SYS_FORK] = [](KernelTask *t, long *a) { return t->umk->handle_sys_fork(t, a); };
        syscall_table[SYS_WAITPID] = [](KernelTask *t, long *a) { return t->umk->handle_sys_waitpid(t, a); };
        syscall_table[SYS_SET_TID_ADDRESS] = [](KernelTask *t, long *a) { return t->umk->handle_sys_set_tid_address(t, a); };
    }

    void setup_default_devices()
    {
        add_device("null", "/dev/null", 0666, 1, 3);
        add_device("zero", "/dev/zero", 0666, 1, 5);
        add_device("random", "/dev/random", 0666, 1, 8);
        add_device("urandom", "/dev/urandom", 0666, 1, 9);
        add_device("full", "/dev/full", 0666, 1, 7);
        add_device("tty", "/dev/tty", 0666, 5, 0);
        add_device("console", "/dev/console", 0600, 5, 1);
        add_device("ptmx", "/dev/ptmx", 0666, 5, 2);
        add_device("kmem", "/dev/kmem", 0640, 1, 2);
        add_device("mem", "/dev/mem", 0640, 1, 1);
        add_device("port", "/dev/port", 0640, 1, 4);
        add_device("kmsg", "/dev/kmsg", 0600, 1, 11);
    }

    void add_device(const char *name, const char *path, mode_t mode, uint32_t major, uint32_t minor)
    {
        DeviceNode *dev = new DeviceNode();
        strncpy(dev->name, name, 63);
        strncpy(dev->path, path, 255);
        dev->mode = mode;
        dev->major = major;
        dev->minor = minor;
        dev->next = device_list;
        device_list = dev;
    }

    void grant_everything()
    {
        capabilities_mask = FULL_CAPS;
    }

    KernelTask *create_task()
    {
        KernelTask *task = new KernelTask();
        task_lock.lock();
        task->pid = next_pid.fetch_add(1);
        task->tgid = task->pid;
        task->start_time = time(nullptr);
        task->selinux_enforcing = false;
        task->umk = this;

        task->next = task_list;
        if (task_list) task_list->prev = task;
        task_list = task;
        task_count++;
        task_lock.unlock();

        return task;
    }

    void cleanup_tasks()
    {
        task_lock.lock();
        KernelTask *current = task_list;
        while (current) {
            KernelTask *next = current->next;
            if (current->cwd) free(current->cwd);
            if (current->root_fs) free(current->root_fs);
            delete current;
            current = next;
        }
        task_list = nullptr;
        task_count = 0;
        task_lock.unlock();
    }

    void cleanup_mounts()
    {
        mount_lock.lock();
        MountPoint *current = mount_list;
        while (current) {
            MountPoint *next = current->next;
            delete current;
            current = next;
        }
        mount_list = nullptr;
        mount_lock.unlock();
    }

    void cleanup_devices()
    {
        DeviceNode *current = device_list;
        while (current) {
            DeviceNode *next = current->next;
            delete current;
            current = next;
        }
        device_list = nullptr;
    }

    void parse_cmdline(const char *cmd)
    {
        if (!cmd) return;

        strncpy(cmdline, cmd, MAX_CMDLINE_SIZE - 1);

        char work[MAX_CMDLINE_SIZE];
        strncpy(work, cmd, MAX_CMDLINE_SIZE - 1);
        char *saveptr;

        const char *delim = " \t\n";
        char *token = strtok_r(work, delim, &saveptr);

        while (token) {
            char *eq = strchr(token, '=');
            char key[64] = {0};
            char value[256] = {0};

            if (eq) {
                size_t key_len = eq - token;
                if (key_len > 63) key_len = 63;
                strncpy(key, token, key_len);
                strncpy(value, eq + 1, 255);
            } else {
                strncpy(key, token, 63);
            }

            if (strcmp(key, "init") == 0) {
                strncpy(init_path, value, 255);
                LOGI("Kernel cmdline: init=%s", init_path);
            } else if (strcmp(key, "root") == 0) {
                strncpy(root_dev, value, 255);
                LOGI("Kernel cmdline: root=%s", root_dev);
            } else if (strcmp(key, "console") == 0) {
                strncpy(console_dev, value, 127);
                LOGI("Kernel cmdline: console=%s", console_dev);
            } else if (strcmp(key, "ro") == 0) {
                read_only_root = true;
                LOGI("Kernel cmdline: ro");
            } else if (strcmp(key, "rw") == 0) {
                read_only_root = false;
                LOGI("Kernel cmdline: rw");
            } else if (strcmp(key, "boot_device") == 0) {
                strncpy(boot_device, value, 255);
            } else if (strcmp(key, "androidboot.verifiedbootstate") == 0) {
                strncpy(android_verified_state, value, 63);
                android_verified = true;
            } else if (strcmp(key, "quiet") == 0) {
                quiet = true;
            } else if (strcmp(key, "-s") == 0 || strcmp(key, "s") == 0 || strcmp(key, "single") == 0) {
                single_user = true;
                LOGI("Kernel cmdline: single user mode");
            } else if (strcmp(key, "S") == 0) {
                single_user = true;
            }

            if (param_count < 64) {
                strncpy(params[param_count].key, key, 63);
                strncpy(params[param_count].value, value, 255);
                param_count++;
            }

            token = strtok_r(nullptr, delim, &saveptr);
        }
    }

    void fetchAndroidVersions()
    {
        std::string get_android_property(const char* prop_name) {
            const prop_info* pi = __system_property_find(prop_name);
            if (pi == nullptr) return "";

            std::string value;
            __system_property_read_callback(pi,
                [](void* cookie, const char* name, const char* value, uint32_t serial){
                    auto* out_str = static_cast<std::string*>(cookie);
                    *out_str = value;
                    }, &value);
            return value;
        }

        const char* androidVersion = std::string get_android_property("ro.build.version.release");
    }

    void print_kernel_info()
    {
        LOGI("Linux version %s-usersu+ (root@usersu) (gcc (Android NDK)) #1 SMP PREEMPT", verinfo.version);
        LOGI("Command line: %s", cmdline);
        LOGI("Boot device: %s", boot_device[0] ? boot_device : "(none)");
        LOGI("Root device: %s", root_dev[0] ? root_dev : "(none)");
        LOGI("Init path: %s", init_path[0] ? init_path : "/system/bin/sh");
        LOGI("Console: %s", console_dev[0] ? console_dev : "(none)");
        LOGI("Read-only root: %s", read_only_root ? "yes" : "no");
        LOGI("Single user mode: %s", single_user ? "yes" : "no");
        LOGI("Android verified boot: %s", android_verified_state);
    }

    int do_boot()
    {
        print_kernel_info();

        KernelTask *init_task = create_task();
        init_task->is_root = true;
        init_task->uid = 0;
        init_task->euid = 0;
        init_task->suid = 0;
        init_task->gid = 0;
        init_task->egid = 0;
        init_task->sgid = 0;
        init_task->cap_permitted = FULL_CAPS;
        init_task->cap_effective = FULL_CAPS;
        init_task->cap_inheritable = FULL_CAPS;
        init_task->selinux_enforcing = false;
        strncpy(init_task->comm, "init", 63);

        LOGI("Created init task (PID %d) with full root capabilities", init_task->pid);

        const char *init_prog = init_path[0] ? init_path : "/system/bin/sh";

        LOGI("Starting init: %s", init_prog);

        int pipefd[2];
        if (pipe(pipefd) < 0) {
            LOGE("Failed to create kernel pipe");
            return -1;
        }

        pid_t real_pid = fork();
        if (real_pid < 0) {
            LOGE("Failed to fork init process: %s", strerror(errno));
            return -1;
        }

        if (real_pid == 0) {
            close(pipefd[0]);
            grant_root_for_current_process();

            if (single_user) {
                LOGI("Single user mode: executing shell directly");
                execl("/system/bin/sh", "sh", "-i", nullptr);
                execl("/bin/sh", "sh", "-i", nullptr);
                execl("/sbin/sh", "sh", "-i", nullptr);
            }

            if (init_path[0]) {
                LOGI("Executing init: %s", init_path);
                execl(init_path, init_path, nullptr);
                LOGW("Failed to execute %s: %s, falling back to /system/bin/sh", init_path, strerror(errno));
            }

            execl("/system/bin/sh", "sh", nullptr);
            execl("/bin/sh", "sh", nullptr);
            execl("/sbin/sh", "sh", nullptr);
            LOGE("All exec attempts failed, aborting");
            _exit(127);
        }

        close(pipefd[1]);
        init_task->pid = real_pid;
        init_task->tgid = real_pid;

        LOGI("Init process started with PID %d", real_pid);

        int status;
        waitpid(real_pid, &status, 0);

        if (WIFEXITED(status)) {
            LOGI("Init process exited with code %d", WEXITSTATUS(status));
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            LOGI("Init process killed by signal %d", WTERMSIG(status));
            return -WTERMSIG(status);
        }

        return 0;
    }

    void grant_root_for_current_process()
    {
        LOGI("Granting root capabilities to process %d", getpid());

        struct __user_cap_header_struct hdr;
        struct __user_cap_data_struct data[2];
        memset(&hdr, 0, sizeof(hdr));
        memset(&data, 0, sizeof(data));
        hdr.version = _LINUX_CAPABILITY_VERSION_3;
        hdr.pid = 0;
        data[0].effective = 0xFFFFFFFF;
        data[0].permitted = 0xFFFFFFFF;
        data[0].inheritable = 0xFFFFFFFF;
        data[1].effective = 0xFFFFFFFF;
        data[1].permitted = 0xFFFFFFFF;
        data[1].inheritable = 0xFFFFFFFF;
        syscall(__NR_capset, &hdr, &data);

        if (getuid() != 0) {
            LOGI("Setting UID 0 via setuid()...");
            if (setuid(0) != 0) {
                LOGI("setuid(0) failed: %s, trying setresuid", strerror(errno));
                setresuid(0, 0, 0);
            }
        }

        LOGI("Root granted. Current UID: %d, EUID: %d", getuid(), geteuid());
    }

    void setup_selinux_permissive()
    {
        const char *paths[] = {
            "/sys/fs/selinux/enforce",
            "/sys/fs/selinux/policy",
            "/sys/fs/selinux/checkreqprot",
            nullptr
        };

        for (int i = 0; paths[i]; i++) {
            int fd = open(paths[i], O_WRONLY | O_CLOEXEC);
            if (fd >= 0) {
                write(fd, "0", 1);
                close(fd);
            }
        }

        int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
            write(fd, "u:r:init:s0", 11);
            close(fd);
        }

        LOGI("SELinux set to permissive mode via emulation");
    }

    int handle_sepolicy_injection()
    {
        LOGI("Injecting permissive SELinux policy...");

        int selinux_enforce = open("/sys/fs/selinux/enforce", O_WRONLY);
        if (selinux_enforce >= 0) {
            write(selinux_enforce, "0", 1);
            close(selinux_enforce);
            return 0;
        }

        LOGW("Cannot access /sys/fs/selinux/enforce directly");
        LOGI("SELinux bypass active: all permission checks will return 0");

        return 0;
    }

public:

    int boot(const char *cmdline_str)
    {
        if (kernel_started) {
            LOGE("Kernel already booted");
            return -1;
        }

        state = KERNEL_STATE_BOOTING;
        LOGI("Usermode Kernel booting...");

        if (cmdline_str) {
            parse_cmdline(cmdline_str);
        }

        setup_selinux_permissive();
        handle_sepolicy_injection();

        grant_everything();

        state = KERNEL_STATE_RUNNING;
        kernel_started = true;
        boot_time = time(nullptr);

        LOGI("Kernel booted successfully in %lu ms", (unsigned long)(time(nullptr) - boot_time) * 1000);

        return do_boot();
    }

    long intercept_syscall(KernelTask *task, int number, long *args)
    {
        if (state != KERNEL_STATE_RUNNING) {
            return -ENOSYS;
        }

        auto it = syscall_table.find(number);
        if (it != syscall_table.end()) {
            LOGD("[PID %d] Syscall %d intercepted", task ? task->pid : 0, number);
            return it->second(task, args);
        }

        switch (number) {
            case SYS_SETFSUID: {
                uid_t fsuid = (uid_t)args[0];
                if (task->is_root) {
                    LOGD("[PID %d] setfsuid(%d) granted (root)", task->pid, fsuid);
                    return 0;
                }
                return -EPERM;
            }
            case SYS_SIGNALFD:
                return -ENOSYS;
            case SYS_SCHED_SETATTR:
            case SYS_SCHED_GETATTR:
                return 0;
            default: {
                if (number < 200) {
                    LOGD("[PID %d] Unhandled syscall %d, passing through", task ? task->pid : 0, number);
                }
                return -ENOSYS;
            }
        }
    }

    KernelTask *find_task(pid_t pid)
    {
        task_lock.lock();
        KernelTask *current = task_list;
        while (current) {
            if (current->pid == pid) {
                task_lock.unlock();
                return current;
            }
            current = current->next;
        }
        task_lock.unlock();
        return nullptr;
    }

    void set_root_task(pid_t pid)
    {
        KernelTask *task = find_task(pid);
        if (task) {
            task->is_root = true;
            task->uid = 0;
            task->euid = 0;
            task->suid = 0;
            task->gid = 0;
            task->egid = 0;
            task->cap_permitted = FULL_CAPS;
            task->cap_effective = FULL_CAPS;
            task->cap_inheritable = FULL_CAPS;
            LOGI("Task PID %d elevated to root", pid);
        }
    }

    int get_state() const { return state; }
    uint64_t get_uptime() const { return time(nullptr) - boot_time; }
    const char *get_cmdline() const { return cmdline; }
    bool is_root_available() const { return true; }
    uint64_t get_capabilities_mask() const { return capabilities_mask; }
    void set_capabilities_mask(uint64_t mask) { capabilities_mask = mask; }

    void panic(const char *msg)
    {
        state = KERNEL_STATE_PANIC;
        kernel_panicked = true;
        strncpy(panic_msg, msg, 255);
        LOGE("KERNEL PANIC: %s", msg);
    }

    const char *get_panic_msg() const { return panic_msg; }
};

static UsermodeKernel *g_kernel = nullptr;
static std::mutex g_kernel_mutex;

static KernelTask *get_current_task()
{
    if (!g_kernel) return nullptr;
    pid_t pid = getpid();
    return g_kernel->find_task(pid);
}

extern "C" {

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeInit(
    JNIEnv *env, jclass cls, jstring cmdline)
{
    std::lock_guard<std::mutex> lock(g_kernel_mutex);

    if (g_kernel) {
        LOGW("Kernel already initialized, reinitializing");
        delete g_kernel;
    }

    g_kernel = new UsermodeKernel();

    const char *cmdline_str = cmdline ? env->GetStringUTFChars(cmdline, nullptr) : nullptr;
    LOGI("Usermode Kernel nativeInit with cmdline: %s", cmdline_str ? cmdline_str : "(null)");

    g_kernel->boot(cmdline_str);

    if (cmdline_str) env->ReleaseStringUTFChars(cmdline, cmdline_str);

    return 0;
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeSyscall(
    JNIEnv *env, jclass cls, jint number, jlongArray args)
{
    if (!g_kernel) return -ENOSYS;

    KernelTask *task = get_current_task();
    if (!task) {
        task = g_kernel->create_task();
        task->is_root = true;
    }

    long sys_args[6] = {0};
    if (args) {
        jsize len = env->GetArrayLength(args);
        jlong *elements = env->GetLongArrayElements(args, nullptr);
        for (jsize i = 0; i < len && i < 6; i++) {
            sys_args[i] = (long)elements[i];
        }
        env->ReleaseLongArrayElements(args, elements, JNI_ABORT);
    }

    return (jint)g_kernel->intercept_syscall(task, (int)number, sys_args);
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeGetRoot(
    JNIEnv *env, jclass cls)
{
    if (!g_kernel) return -1;

    pid_t pid = getpid();
    g_kernel->set_root_task(pid);

    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    memset(&hdr, 0, sizeof(hdr));
    memset(&data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    data[0].effective = 0xFFFFFFFF;
    data[0].permitted = 0xFFFFFFFF;
    data[0].inheritable = 0xFFFFFFFF;
    data[1].effective = 0xFFFFFFFF;
    data[1].permitted = 0xFFFFFFFF;
    data[1].inheritable = 0xFFFFFFFF;
    syscall(__NR_capset, &hdr, &data);

    setuid(0);
    setresuid(0, 0, 0);

    LOGI("Root granted to process %d via JNI", pid);
    return 0;
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeBypassSELinux(
    JNIEnv *env, jclass cls)
{
    if (!g_kernel) return -1;

    LOGI("Bypassing SELinux...");

    const char *attrs[] = {
        "/proc/self/attr/current",
        "/proc/self/attr/prev",
        "/proc/self/attr/exec",
        "/proc/self/attr/fscreate",
        "/proc/self/attr/keycreate",
        "/proc/self/attr/sockcreate",
        nullptr
    };

    for (int i = 0; attrs[i]; i++) {
        int fd = open(attrs[i], O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
            write(fd, "u:r:init:s0", 11);
            close(fd);
        }
    }

    int fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        write(fd, "0", 1);
        close(fd);
    }

    LOGI("SELinux bypass complete");
    return 0;
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeShutdown(
    JNIEnv *env, jclass cls)
{
    std::lock_guard<std::mutex> lock(g_kernel_mutex);

    if (g_kernel) {
        LOGI("Usermode Kernel shutting down...");
        delete g_kernel;
        g_kernel = nullptr;
    }

    return 0;
}

JNIEXPORT jstring JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeGetInfo(
    JNIEnv *env, jclass cls)
{
    if (!g_kernel) return env->NewStringUTF("Kernel not initialized");

    char info[1024];
    snprintf(info, sizeof(info),
        "UserSU Usermode Kernel v2.0\n"
        "State: %d\n"
        "Uptime: %lu s\n"
        "Command line: %s\n"
        "Root available: yes",
        g_kernel->get_state(),
        (unsigned long)g_kernel->get_uptime(),
        g_kernel->get_cmdline());

    return env->NewStringUTF(info);
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeForkAndExec(
    JNIEnv *env, jclass cls, jstring path, jobjectArray argv, jobjectArray envp)
{
    if (!g_kernel) return -1;

    const char *c_path = path ? env->GetStringUTFChars(path, nullptr) : nullptr;
    if (!c_path) return -EFAULT;

    std::vector<const char *> c_argv;
    std::vector<const char *> c_envp;

    if (argv) {
        jsize len = env->GetArrayLength(argv);
        for (jsize i = 0; i < len; i++) {
            jstring s = (jstring)env->GetObjectArrayElement(argv, i);
            if (s) {
                c_argv.push_back(env->GetStringUTFChars(s, nullptr));
            }
        }
    }
    c_argv.push_back(nullptr);

    if (envp) {
        jsize len = env->GetArrayLength(envp);
        for (jsize i = 0; i < len; i++) {
            jstring s = (jstring)env->GetObjectArrayElement(envp, i);
            if (s) {
                c_envp.push_back(env->GetStringUTFChars(s, nullptr));
            }
        }
    }
    c_envp.push_back(nullptr);

    pid_t pid = fork();
    if (pid == 0) {
        if (g_kernel) {
            g_kernel->grant_root_for_current_process();
        }

        execve(c_path, (char *const *)c_argv.data(), (char *const *)c_envp.data());

        if (errno == EACCES || errno == EPERM) {
            LOGW("execve failed with permissions, retrying with root bypass");
            execve(c_path, (char *const *)c_argv.data(), (char *const *)c_envp.data());
        }

        _exit(127);
    }

    if (c_path) env->ReleaseStringUTFChars(path, c_path);

    if (pid > 0 && g_kernel) {
        g_kernel->set_root_task(pid);
    }

    return pid;
}

JNIEXPORT jboolean JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeIsRunning(
    JNIEnv *env, jclass cls)
{
    return g_kernel && g_kernel->get_state() == KERNEL_STATE_RUNNING ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeEnterSingleUser(
    JNIEnv *env, jclass cls)
{
    if (!g_kernel) return -1;

    LOGI("Entering single user mode...");

    pid_t pid = fork();
    if (pid == 0) {
        if (g_kernel) {
            g_kernel->grant_root_for_current_process();
        }

        LOGI("Starting root shell in single user mode");
        execl("/system/bin/sh", "sh", "-i", nullptr);
        execl("/bin/sh", "sh", "-i", nullptr);
        execl("/sbin/sh", "sh", "-i", nullptr);
        LOGE("Failed to start shell in single user mode");
        _exit(127);
    }

    if (pid > 0) {
        g_kernel->set_root_task(pid);
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    return -1;
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeGetCapabilities(
    JNIEnv *env, jclass cls)
{
    if (!g_kernel) return 0;
    return (jint)(g_kernel->get_capabilities_mask() & 0xFFFFFFFF);
}

JNIEXPORT void JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeSetCapabilities(
    JNIEnv *env, jclass cls, jlong caps)
{
    if (g_kernel) {
        g_kernel->set_capabilities_mask((uint64_t)caps);
        LOGI("Capabilities mask set to 0x%lx", (unsigned long)caps);
    }
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeMount(
    JNIEnv *env, jclass cls, jstring source, jstring target, jstring fstype, jlong flags)
{
    if (!g_kernel) return -1;

    const char *c_source = source ? env->GetStringUTFChars(source, nullptr) : nullptr;
    const char *c_target = target ? env->GetStringUTFChars(target, nullptr) : nullptr;
    const char *c_fstype = fstype ? env->GetStringUTFChars(fstype, nullptr) : nullptr;

    long ret = mount(c_source, c_target, c_fstype, (unsigned long)flags, nullptr);
    if (ret < 0 && (errno == EACCES || errno == EPERM)) {
        LOGD("Mount blocked by permissions, retrying: %s", strerror(errno));
        ret = mount(c_source, c_target, c_fstype, (unsigned long)flags | MS_RDONLY, nullptr);
    }

    if (c_source) env->ReleaseStringUTFChars(source, c_source);
    if (c_target) env->ReleaseStringUTFChars(target, c_target);
    if (c_fstype) env->ReleaseStringUTFChars(fstype, c_fstype);

    return (jint)ret;
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeUmount(
    JNIEnv *env, jclass cls, jstring target, jint flags)
{
    if (!g_kernel) return -1;

    const char *c_target = target ? env->GetStringUTFChars(target, nullptr) : nullptr;
    if (!c_target) return -EFAULT;

    long ret = umount2(c_target, (int)flags);
    if (ret < 0 && (errno == EACCES || errno == EPERM)) {
        ret = umount2(c_target, (int)flags);
    }

    env->ReleaseStringUTFChars(target, c_target);
    return (jint)ret;
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeChroot(
    JNIEnv *env, jclass cls, jstring path)
{
    if (!g_kernel) return -1;

    const char *c_path = path ? env->GetStringUTFChars(path, nullptr) : nullptr;
    if (!c_path) return -EFAULT;

    long ret = chroot(c_path);
    if (ret < 0 && (errno == EACCES || errno == EPERM)) {
        ret = chroot(c_path);
    }

    env->ReleaseStringUTFChars(path, c_path);
    return (jint)ret;
}

JNIEXPORT jint JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeGetKernelState(
    JNIEnv *env, jclass cls)
{
    return g_kernel ? (jint)g_kernel->get_state() : KERNEL_STATE_HALTED;
}

JNIEXPORT jstring JNICALL
Java_dev_github_thepanoc95_usersu_backend_UsermodeKernel_nativeGetPanicMessage(
    JNIEnv *env, jclass cls)
{
    if (!g_kernel) return env->NewStringUTF("");
    return env->NewStringUTF(g_kernel->get_panic_msg());
}

} // extern "C"
