/*
 * Copyright (C) 2019 UNISOC Communications Inc.
 */

#include "mboot.h"
#include <android-base/logging.h>

using namespace std::literals;

namespace android {
namespace mboot {
    bool IsMboot(void) {
        return access("/mboot", R_OK) == 0;
    }

    void console(void) {
        if (!IsMboot())
            return;
        if (getenv("mconsole")) {
            printf("mconsole is %s\n", getenv("mconsole"));
            return;
        }
        mknod("/dev/console", S_IFCHR | 0666, makedev(1, 5)); // initramfs built-in mknod /dev/console c 5 1 dev node
        int fd = open("/dev/console", O_RDWR | O_NOCTTY); // O_NOCTTY -- there is no control terminal to maintain shareing console device with others
        if (fd == -1) fd = open("/dev/null", O_RDWR);
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);
        printf("mboot mode\n");
        setenv("mconsole", "on", 1);
    }

    void spath(void) {
        if (!IsMboot())
            return;
        std::string path = getenv("PATH");
        setenv("PATH2", path.c_str(), 1);
        // printf("PATH=%s\n", path.c_str());
    }

    void mdb(const char *cmd, const char *env_name, const char *env_value) {
        if (!IsMboot())
            return;
        pid_t child_pid = fork();
        if (child_pid == 0) {
            setsid();
            std::string pid = std::to_string(getpid());
            setenv("mdbpid", pid.c_str(), 1);
            if (env_name)
                setenv(env_name, env_value, 1);
            const char *ta[3];
            android::mboot::spath();
            #if 1
            // printf("%s : %d\n", __func__, __LINE__);
            std::string path = getenv("PATH2");
            printf("PATH=%s\n", path.c_str());
            #endif
            // ta[0] = "/sbin/env.sh";
            // ta[1] = nullptr;
            // execv(ta[0], const_cast<char**>(ta));
            ta[0] = "/msystem/bin/busybox"; // kill -15 to reboot
            ta[1] = cmd;
            ta[2] = nullptr;
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

    void list_dir(const char *d) {
        struct dirent *dp;
        std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(d), closedir);
        if (dir) {
            while ((dp = readdir(dir.get())) != NULL)
                LOG(INFO) << d << "/" << dp->d_name;
        }
    }
} // mboot
} // android
