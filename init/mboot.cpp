/*
 * Copyright (C) 2019 UNISOC Communications Inc.
 */

#include "mboot.h"
#include <android-base/logging.h>

using namespace std::literals;

namespace android {
namespace mboot {
    static int fd_kmsg = -1;

    bool IsMboot(void) {
        return access("/mboot", R_OK) == 0;
    }

    void envsetup(void) {
        printf("envsetup start\n");
        // From system/core/init/first_stage_init.cpp -> FirstStageMain
        // Clear the umask.
        umask(0);
        // clearenv();
        setenv("PATH", _PATH_DEFPATH, 1);
        // mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755");
        // mkdir("/dev/pts", 0755);
        // mkdir("/dev/socket", 0755);
        // mount("devpts", "/dev/pts", "devpts", 0, NULL);
        // // Don't expose the raw commandline to unprivileged processes.
        // chmod("/proc/cmdline", 0440);
        // mount("sysfs", "/sys", "sysfs", 0, NULL);
        // mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11));
        // mknod("/dev/random", S_IFCHR | 0666, makedev(1, 8));
        // mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));
        // // This is needed for log wrapper, which gets called before ueventd runs.
        // mknod("/dev/ptmx", S_IFCHR | 0666, makedev(5, 2));
        // mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
        printf("envsetup done\n");
    }

    void open_console(void) {
        // envsetup();
/**
 * 因为kernel的代码在执行init之前会执行如下语句来占据fd 0,1,2
 * sprdroidq_trunk/bsp/kernel/kernel4.14/init/main.c
 *
 * 1054  static noinline void __init kernel_init_freeable(void) {
 * ......
 * 1091    // Open the /dev/console on the rootfs, this should never fail
 * 1092    if (sys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
 * 1093            pr_err("Warning: unable to open an initial console.\n");
 * 1094
 * 1095    (void) sys_dup(0);
 * 1096    (void) sys_dup(0);
 * ......
 * }
 *
 * 所有Android 10代码有如下一句非常明确的解释：
 * sprdroidq_trunk/system/core/init/util.cpp
 *
 * // The kernel opens /dev/console and uses that fd for stdin/stdout/stderr if there is a serial
 * // console enabled and no initramfs, otherwise it does not provide any fds for stdin/stdout/stderr.
 * // SetStdioToDevNull() is used to close these existing fds if they exist and replace them with
 * // /dev/null regardless.
 * //
 * // In the case that these fds are provided by the kernel, the exec of second stage init causes an
 * // SELinux denial as it does not have access to /dev/console.  In the case that they are not
 * // provided, exec of any further process is potentially dangerous as the first fd's opened by that
 * // process will take the stdin/stdout/stderr fileno's, which can cause issues if printf(), etc is
 * // then used by that process.
 * //
 * // Lastly, simply calling SetStdioToDevNull() in first stage init is not enough, since first
 * // stage init still runs in kernel context, future child processes will not have permissions to
 * // access any fds that it opens, including the one opened below for /dev/null.  Therefore,
 * // SetStdioToDevNull() must be called again in second stage init.
 * void SetStdioToDevNull(char** argv) {
 *     // Make stdin/stdout/stderr all point to /dev/null.
 *     int fd = open("/dev/null", O_RDWR);
 *     if (fd == -1) {
 *         int saved_errno = errno;
 *         android::base::InitLogging(argv, &android::base::KernelLogger, InitAborter);
 *         errno = saved_errno;
 *         PLOG(FATAL) << "Couldn't open /dev/null";
 *     }
 *     dup2(fd, STDIN_FILENO);
 *     dup2(fd, STDOUT_FILENO);
 *     dup2(fd, STDERR_FILENO);
 *     if (fd > STDERR_FILENO) close(fd);
 * }
 *
 * int dup(int oldfd);
 * int dup2(int oldfd, int newfd);
 *
 * The  dup()  system  call  creates  a copy of the file descriptor oldfd,
 * using the lowest-numbered unused file descriptor for the  new  descriptor.
 *
 * After a successful return, the old and new file descriptors may be used
 * interchangeably.  They refer to the same  open  file  description  (see
 * open(2)) and thus share file offset and file status flags; for example,
 * if the file offset is modified by using lseek(2) on  one  of  the  file
 * descriptors, the offset is also changed for the other.
 *
 * The two file descriptors do not share file descriptor flags (the close-
 * on-exec flag).  The close-on-exec flag (FD_CLOEXEC; see  fcntl(2))  for
 * the duplicate descriptor is off.
 *
 * dup2() makes newfd be the copy of oldfd, closing newfd first if  necessary,
 * but note the following:
 *
 * *  If  oldfd  is  not a valid file descriptor, then the call fails, and
 *    newfd is not closed.
 *
 * *  If oldfd is a valid file descriptor, and newfd has the same value as
 *    oldfd, then dup2() does nothing, and returns newfd.
 */
        {
            // Make stdin/stdout/stderr all point to /dev/null.
            mknod("/dev/null.mboot", S_IFCHR | 0666, makedev(1, 3));
            int fd = open("/dev/null.mboot", O_RDWR);
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) close(fd);
        }

        mknod("/dev/console.mboot", S_IFCHR | 0666, makedev(5, 1)); // initramfs built-in mknod /dev/console c 5 1 dev node
        int fd = open("/dev/console.mboot", O_RDWR | O_NOCTTY); // Like ioctl TIOCNOTTY, O_RDWR | O_NOCTTY -- there is no control terminal to maintain shareing console device with others
        if (fd == -1) {
            list_dir("/");
            list_dir("/dev");
            // fd = open("/dev/null", O_RDWR);
            printf("/dev/console open failed\n");
            fd = fd_kmsg;
        } else {
            // write(fd, "mboot: mdb is on /dev/console\n", 33); // 直接打印到了控制终端，而非/dev/kmsg的串口，因为<0>未起作用，不过在init first stage之前执行，一执行就死
        }
        // list_dir("/proc/self/fd/");
/** http://www.man7.org/linux/man-pages/man4/tty_ioctl.4.html
 * Controlling terminal
 *     TIOCSCTTY int arg
 *            Make the given terminal the controlling terminal of the call‐
 *            ing process.  The calling process must be a session leader and
 *            not have a controlling terminal already.  For this case, arg
 *            should be specified as zero.
 *
 *            If this terminal is already the controlling terminal of a dif‐
 *            ferent session group, then the ioctl fails with EPERM, unless
 *            the caller has the CAP_SYS_ADMIN capability and arg equals 1,
 *            in which case the terminal is stolen, and all processes that
 *            had it as controlling terminal lose it.
 *
 *     TIOCNOTTY void
 *            If the given terminal was the controlling terminal of the
 *            calling process, give up this controlling terminal.  If the
 *            process was session leader, then send SIGHUP and SIGCONT to
 *            the foreground process group and all processes in the current
 *            session lose their controlling terminal.
 */
        #if 0
        setsid(); // system/core/init/service.cpp Service::OpenConsole()
        ioctl(fd, TIOCSCTTY, 0); // system/core/init/service.cpp Service::OpenConsole()
        #endif
        // printf("mdb mode fd=%d\n", fd);
        if (fd != fd_kmsg)
            dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd != fd_kmsg)
            close(fd);
#if 0
        {
            // Make stdin/stdout/stderr all point to /dev/null.
            mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
            int fd = open("/dev/null", O_RDWR);
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) close(fd);
        }
        mknod("/dev/console.mboot", S_IFCHR | 0777, makedev(1, 5)); // initramfs built-in mknod /dev/console c 5 1 dev node
        printf("mdb mode busybox open /dev/console.mboot\n");
        dup2(fd_kmsg, STDOUT_FILENO);
        dup2(fd_kmsg, STDERR_FILENO);
        write(STDOUT_FILENO, "888888888888888888888\n", 22);
        setenv("CONSOLE", "/dev/console.mboot", 0); // For B-u-s-y-b-o-x v1.29.3 init getenv("CONSOLE");
#endif
    }

    void spath(void) {
        if (!IsMboot())
            return;
        char *path = getenv("PATH");
        if (path)
            setenv("PATH2", path, 1);
        // printf("PATH=%s\n", path);
    }

    void mdb(const char *tag, const char *env_name, const char *env_value, const char *cmd, const char **args) {
        // if (0) {
        //     const char *margs[] = {"-l", "/", nullptr};
        //     android::mboot::mdb("ls -l /", nullptr, nullptr, "ls", margs);
        // }
        if (!IsMboot())
            return;
        pid_t child_pid = fork();
        if (child_pid == 0) {
            setsid();
            std::string pid = std::to_string(getpid());
            setenv("mdbpid", pid.c_str(), 1);
            if (env_name)
                setenv(env_name, env_value, 1);
            if (tag)
                printf("%s\n", tag);
            const char *ta[32];
            android::mboot::spath();
            #if 0
            // printf("%s : %d\n", __func__, __LINE__);
            std::string path = getenv("PATH2");
            printf("PATH=%s\n", path.c_str());
            #endif
            // ta[0] = "/sbin/env.sh";
            // ta[1] = nullptr;
            // execv(ta[0], const_cast<char**>(ta));
            open_console();
            ta[0] = "/msystem/bin/busybox"; // kill -15 to reboot
            ta[1] = cmd;
            int i = 2;
            if (args) {
                for (; i < 31; i++) {
                    const char *arg = args[i-2];
                    ta[i] = arg;
                    if (!arg)
                        break;
                }
            }
            ta[i] = nullptr;
            execv(ta[0], const_cast<char**>(ta));
            exit(0);
        } else if (child_pid > 0) {
            if (child_pid > 0) {
                pid_t waited_pid;
                int status;
                // LOG(INFO) << "Waiting for child..";
                while ((waited_pid = wait(&status)) > 0) {
                    // This loop will end when there are no processes left inside the
                    // PID namespace or when the init process inside the PID namespace
                    // gets a signal.
                    if (waited_pid == child_pid) {
                        // LOG(INFO) << "Child done.";
                        break;
                    }
                }
            }
        }
    }

    void mc(const char *cmd) {
        const char *margs[] = {"-c", cmd, nullptr};
        mdb(nullptr, nullptr, nullptr, "sh", margs);
    }

    void do_overlayfs(void) {
        if (android::mboot::IsMboot()) {
            // mkdir -p /system2 /msystem /system
            // mount -t overlay -o lowerdir=/system2,upperdir=/msystem,workdir=/system overlay /system2 2019/07/29 09:33:28 luther
            // const char* path = "/sbin/mboot-chroot-hook";
            // const char* args[] = {path, "selinux_setup", nullptr};
            // int ret = execv(path, const_cast<char**>(args));
            int ret = system("/sbin/mboot-chroot-hook");
            if (ret)
                PLOG(ERROR) << "/sbin/mboot-chroot-hook";
        }
    }

    void printf(const char* fmt, ...) {
        #define LOG_BUF_SIZE (1024)
        int ret;
        va_list ap;
        char buf[LOG_BUF_SIZE];
        char *p = buf, *pe = p + LOG_BUF_SIZE - 1;
        p += snprintf(p, pe-p, "<0>mboot: ");
        if (fd_kmsg < 0) {
            // int fd = open("/dev/console", O_RDWR | O_NOCTTY); // O_NOCTTY -- there is no control terminal to maintain shareing console device with others
            mknod("/dev/kmsg.mboot", S_IFCHR | 0600, makedev(1, 11));
            fd_kmsg = open("/dev/kmsg.mboot", O_RDWR);
            if (fd_kmsg <= STDERR_FILENO) {
                if (fd_kmsg < 0)
                    return;
                char *op = p;
                op += sprintf(op, "fd 0,1,2 is reserved for STDIN_FILENO , STDOUT_FILENO and STDERR_FILENO, but fd_kmsg=%d\n", fd_kmsg);
                ret = write(fd_kmsg, buf, op-buf);
            }
        }
        // p += snprintf(p, pe-p, "fd_kmsg=%d: ", fd_kmsg);
        va_start(ap, fmt);
        p += vsnprintf(p, pe-p, fmt, ap);
        va_end(ap);
        ret = write(fd_kmsg, buf, p-buf);
    }

    void list_dir(const char *d) {
        struct dirent *dp;
        std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(d), closedir);
        if (dir) {
            while ((dp = readdir(dir.get())) != NULL) {
                printf("%s%s%s", d, d[strlen(d)-1] == '/' ? "":"/", dp->d_name);
                // LOG(INFO) << d << "/" << dp->d_name;
            }
        }
    }
} // mboot
} // android
