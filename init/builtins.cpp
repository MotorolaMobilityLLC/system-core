/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/loop.h>
#include <ext4_crypt_init_extensions.h>

#include <selinux/selinux.h>
#include <selinux/label.h>

#include <fs_mgr.h>
#include <base/stringprintf.h>
#include <cutils/partition_utils.h>
#include <cutils/android_reboot.h>
#include <logwrap/logwrap.h>
#include <private/android_filesystem_config.h>

#include "action.h"
#include "devices.h"
#include "init.h"
#include "init_parser.h"
#include "keywords.h"
#include "log.h"
#include "property_service.h"
#include "service.h"
#include "util.h"

#define chmod DO_NOT_USE_CHMOD_USE_FCHMODAT_SYMLINK_NOFOLLOW
#define UNMOUNT_CHECK_MS 5000
#define UNMOUNT_CHECK_TIMES 10

// System call provided by bionic but not in any header file.
extern "C" int init_module(void *, unsigned long, const char *);

static int insmod(const char *filename, const char *options)
{
    std::string module;
    if (!read_file(filename, &module)) {
        return -1;
    }

    // TODO: use finit_module for >= 3.8 kernels.
    return init_module(&module[0], module.size(), options);
}

static int __ifupdown(const char *interface, int up)
{
    struct ifreq ifr;
    int s, ret;

    strlcpy(ifr.ifr_name, interface, IFNAMSIZ);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return -1;

    ret = ioctl(s, SIOCGIFFLAGS, &ifr);
    if (ret < 0) {
        goto done;
    }

    if (up)
        ifr.ifr_flags |= IFF_UP;
    else
        ifr.ifr_flags &= ~IFF_UP;

    ret = ioctl(s, SIOCSIFFLAGS, &ifr);

done:
    close(s);
    return ret;
}

static void unmount_and_fsck(const struct mntent *entry)
{
    if (strcmp(entry->mnt_type, "f2fs") && strcmp(entry->mnt_type, "ext4"))
        return;

    /* First, lazily unmount the directory. This unmount request finishes when
     * all processes that open a file or directory in |entry->mnt_dir| exit.
     */
    TEMP_FAILURE_RETRY(umount2(entry->mnt_dir, MNT_DETACH));

    /* Next, kill all processes except init, kthreadd, and kthreadd's
     * children to finish the lazy unmount. Killing all processes here is okay
     * because this callback function is only called right before reboot().
     * It might be cleaner to selectively kill processes that actually use
     * |entry->mnt_dir| rather than killing all, probably by reusing a function
     * like killProcessesWithOpenFiles() in vold/, but the selinux policy does
     * not allow init to scan /proc/<pid> files which the utility function
     * heavily relies on. The policy does not allow the process to execute
     * killall/pkill binaries either. Note that some processes might
     * automatically restart after kill(), but that is not really a problem
     * because |entry->mnt_dir| is no longer visible to such new processes.
     */
    ServiceManager::GetInstance().ForEachService([] (Service* s) { s->Stop(); });
    TEMP_FAILURE_RETRY(kill(-1, SIGKILL));

    int count = 0;
    while (count++ < UNMOUNT_CHECK_TIMES) {
        int fd = TEMP_FAILURE_RETRY(open(entry->mnt_fsname, O_RDONLY | O_EXCL));
        if (fd >= 0) {
            /* |entry->mnt_dir| has sucessfully been unmounted. */
            close(fd);
            break;
        } else if (errno == EBUSY) {
            /* Some processes using |entry->mnt_dir| are still alive. Wait for a
             * while then retry.
             */
            TEMP_FAILURE_RETRY(
                usleep(UNMOUNT_CHECK_MS * 1000 / UNMOUNT_CHECK_TIMES));
            continue;
        } else {
            /* Cannot open the device. Give up. */
            return;
        }
    }

    int st;
    if (!strcmp(entry->mnt_type, "f2fs")) {
        const char *f2fs_argv[] = {
            "/system/bin/fsck.f2fs", "-f", entry->mnt_fsname,
        };
        android_fork_execvp_ext(ARRAY_SIZE(f2fs_argv), (char **)f2fs_argv,
                                &st, true, LOG_KLOG, true, NULL, NULL, 0);
    } else if (!strcmp(entry->mnt_type, "ext4")) {
        const char *ext4_argv[] = {
            "/system/bin/e2fsck", "-f", "-y", entry->mnt_fsname,
        };
        android_fork_execvp_ext(ARRAY_SIZE(ext4_argv), (char **)ext4_argv,
                                &st, true, LOG_KLOG, true, NULL, NULL, 0);
    }
}

int do_class_start(const std::vector<std::string>& args)
{
        /* Starting a class does not start services
         * which are explicitly disabled.  They must
         * be started individually.
         */
    ServiceManager::GetInstance().
        ForEachServiceInClass(args[1], [] (Service* s) { s->StartIfNotDisabled(); });
    return 0;
}

int do_class_stop(const std::vector<std::string>& args)
{
    ServiceManager::GetInstance().
        ForEachServiceInClass(args[1], [] (Service* s) { s->Stop(); });
    return 0;
}

int do_class_reset(const std::vector<std::string>& args)
{
    ServiceManager::GetInstance().
        ForEachServiceInClass(args[1], [] (Service* s) { s->Reset(); });
    return 0;
}

int do_domainname(const std::vector<std::string>& args)
{
    return write_file("/proc/sys/kernel/domainname", args[1].c_str());
}

int do_enable(const std::vector<std::string>& args)
{
    Service* svc = ServiceManager::GetInstance().FindServiceByName(args[1]);
    if (!svc) {
        return -1;
    }
    return svc->Enable();
}

int do_exec(const std::vector<std::string>& args) {
    Service* svc = ServiceManager::GetInstance().MakeExecOneshotService(args);
    if (!svc) {
        return -1;
    }
    if (!svc->Start()) {
        return -1;
    }
    waiting_for_exec = true;
    return 0;
}

int do_export(const std::vector<std::string>& args)
{
    return add_environment(args[1].c_str(), args[2].c_str());
}

int do_hostname(const std::vector<std::string>& args)
{
    return write_file("/proc/sys/kernel/hostname", args[1].c_str());
}

int do_ifup(const std::vector<std::string>& args)
{
    return __ifupdown(args[1].c_str(), 1);
}

int do_insmod(const std::vector<std::string>& args)
{
    std::string options;

    if (args.size() > 2) {
        options += args[2];
        for (std::size_t i = 3; i < args.size(); ++i) {
            options += ' ';
            options += args[i];
        }
    }

    return insmod(args[1].c_str(), options.c_str());
}

int do_mkdir(const std::vector<std::string>& args)
{
    mode_t mode = 0755;
    int ret;

    /* mkdir <path> [mode] [owner] [group] */

    if (args.size() >= 3) {
        mode = std::stoul(args[2], 0, 8);
    }

    ret = make_dir(args[1].c_str(), mode);
    /* chmod in case the directory already exists */
    if (ret == -1 && errno == EEXIST) {
        ret = fchmodat(AT_FDCWD, args[1].c_str(), mode, AT_SYMLINK_NOFOLLOW);
    }
    if (ret == -1) {
        return -errno;
    }

    if (args.size() >= 4) {
        uid_t uid = decode_uid(args[3].c_str());
        gid_t gid = -1;

        if (args.size() == 5) {
            gid = decode_uid(args[4].c_str());
        }

        if (lchown(args[1].c_str(), uid, gid) == -1) {
            return -errno;
        }

        /* chown may have cleared S_ISUID and S_ISGID, chmod again */
        if (mode & (S_ISUID | S_ISGID)) {
            ret = fchmodat(AT_FDCWD, args[1].c_str(), mode, AT_SYMLINK_NOFOLLOW);
            if (ret == -1) {
                return -errno;
            }
        }
    }

    return e4crypt_set_directory_policy(args[1].c_str());
}

static struct {
    const char *name;
    unsigned flag;
} mount_flags[] = {
    { "noatime",    MS_NOATIME },
    { "noexec",     MS_NOEXEC },
    { "nosuid",     MS_NOSUID },
    { "nodev",      MS_NODEV },
    { "nodiratime", MS_NODIRATIME },
    { "ro",         MS_RDONLY },
    { "rw",         0 },
    { "remount",    MS_REMOUNT },
    { "bind",       MS_BIND },
    { "rec",        MS_REC },
    { "unbindable", MS_UNBINDABLE },
    { "private",    MS_PRIVATE },
    { "slave",      MS_SLAVE },
    { "shared",     MS_SHARED },
    { "defaults",   0 },
    { 0,            0 },
};

#define DATA_MNT_POINT "/data"

/* mount <type> <device> <path> <flags ...> <options> */
int do_mount(const std::vector<std::string>& args)
{
    char tmp[64];
    const char *source, *target, *system;
    const char *options = NULL;
    unsigned flags = 0;
    std::size_t na = 0;
    int n, i;
    int wait = 0;

    for (na = 4; na < args.size(); na++) {
        for (i = 0; mount_flags[i].name; i++) {
            if (!args[na].compare(mount_flags[i].name)) {
                flags |= mount_flags[i].flag;
                break;
            }
        }

        if (!mount_flags[i].name) {
            if (!args[na].compare("wait"))
                wait = 1;
            /* if our last argument isn't a flag, wolf it up as an option string */
            else if (na + 1 == args.size())
                options = args[na].c_str();
        }
    }

    system = args[1].c_str();
    source = args[2].c_str();
    target = args[3].c_str();

    if (!strncmp(source, "mtd@", 4)) {
        n = mtd_name_to_number(source + 4);
        if (n < 0) {
            return -1;
        }

        snprintf(tmp, sizeof(tmp), "/dev/block/mtdblock%d", n);

        if (wait)
            wait_for_file(tmp, COMMAND_RETRY_TIMEOUT);
        if (mount(tmp, target, system, flags, options) < 0) {
            return -1;
        }

        goto exit_success;
    } else if (!strncmp(source, "loop@", 5)) {
        int mode, loop, fd;
        struct loop_info info;

        mode = (flags & MS_RDONLY) ? O_RDONLY : O_RDWR;
        fd = open(source + 5, mode | O_CLOEXEC);
        if (fd < 0) {
            return -1;
        }

        for (n = 0; ; n++) {
            snprintf(tmp, sizeof(tmp), "/dev/block/loop%d", n);
            loop = open(tmp, mode | O_CLOEXEC);
            if (loop < 0) {
                close(fd);
                return -1;
            }

            /* if it is a blank loop device */
            if (ioctl(loop, LOOP_GET_STATUS, &info) < 0 && errno == ENXIO) {
                /* if it becomes our loop device */
                if (ioctl(loop, LOOP_SET_FD, fd) >= 0) {
                    close(fd);

                    if (mount(tmp, target, system, flags, options) < 0) {
                        ioctl(loop, LOOP_CLR_FD, 0);
                        close(loop);
                        return -1;
                    }

                    close(loop);
                    goto exit_success;
                }
            }

            close(loop);
        }

        close(fd);
        ERROR("out of loopback devices");
        return -1;
    } else {
        if (wait)
            wait_for_file(source, COMMAND_RETRY_TIMEOUT);
        if (mount(source, target, system, flags, options) < 0) {
            return -1;
        }

    }

exit_success:
    return 0;

}

static int wipe_data_via_recovery()
{
    mkdir("/cache/recovery", 0700);
    int fd = open("/cache/recovery/command", O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0600);
    if (fd >= 0) {
        write(fd, "--wipe_data\n", strlen("--wipe_data\n") + 1);
        write(fd, "--reason=wipe_data_via_recovery\n", strlen("--reason=wipe_data_via_recovery\n") + 1);
        close(fd);
    } else {
        ERROR("could not open /cache/recovery/command\n");
        return -1;
    }
    android_reboot(ANDROID_RB_RESTART2, 0, "recovery");
    while (1) { pause(); }  // never reached
}

void import_late()
{
    static const std::vector<std::string> init_directories = {
        "/system/etc/init",
        "/vendor/etc/init",
        "/odm/etc/init"
    };

    for (const auto& dir : init_directories) {
        init_parse_config(dir.c_str());
    }
}

/*
 * This function might request a reboot, in which case it will
 * not return.
 */
int do_mount_all(const std::vector<std::string>& args)
{
    pid_t pid;
    int ret = -1;
    int child_ret = -1;
    int status;
    struct fstab *fstab;

    if (args.size() != 2) {
        return -1;
    }
    const char* fstabfile = args[1].c_str();
    /*
     * Call fs_mgr_mount_all() to mount all filesystems.  We fork(2) and
     * do the call in the child to provide protection to the main init
     * process if anything goes wrong (crash or memory leak), and wait for
     * the child to finish in the parent.
     */
    pid = fork();
    if (pid > 0) {
        /* Parent.  Wait for the child to return */
        int wp_ret = TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
        if (wp_ret < 0) {
            /* Unexpected error code. We will continue anyway. */
            NOTICE("waitpid failed rc=%d: %s\n", wp_ret, strerror(errno));
        }

        if (WIFEXITED(status)) {
            ret = WEXITSTATUS(status);
        } else {
            ret = -1;
        }
    } else if (pid == 0) {
        /* child, call fs_mgr_mount_all() */
        klog_set_level(6);  /* So we can see what fs_mgr_mount_all() does */
        fstab = fs_mgr_read_fstab(fstabfile);
        child_ret = fs_mgr_mount_all(fstab);
        fs_mgr_free_fstab(fstab);
        if (child_ret == -1) {
            ERROR("fs_mgr_mount_all returned an error\n");
        }
        _exit(child_ret);
    } else {
        /* fork failed, return an error */
        return -1;
    }

    import_late();

    if (ret == FS_MGR_MNTALL_DEV_NEEDS_ENCRYPTION) {
        property_set("vold.decrypt", "trigger_encryption");
    } else if (ret == FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED) {
        property_set("ro.crypto.state", "encrypted");
        property_set("ro.crypto.type", "block");
        property_set("vold.decrypt", "trigger_default_encryption");
    } else if (ret == FS_MGR_MNTALL_DEV_NOT_ENCRYPTED) {
        property_set("ro.crypto.state", "unencrypted");
        /* If fs_mgr determined this is an unencrypted device, then trigger
         * that action.
         */
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
    } else if (ret == FS_MGR_MNTALL_DEV_NEEDS_RECOVERY) {
        /* Setup a wipe via recovery, and reboot into recovery */
        ERROR("fs_mgr_mount_all suggested recovery, so wiping data via recovery.\n");
        ret = wipe_data_via_recovery();
        /* If reboot worked, there is no return. */
    } else if (ret == FS_MGR_MNTALL_DEV_DEFAULT_FILE_ENCRYPTED) {
        if (e4crypt_install_keyring()) {
            return -1;
        }
        property_set("ro.crypto.state", "encrypted");
        property_set("ro.crypto.type", "file");

        // Although encrypted, we have device key, so we do not need to
        // do anything different from the nonencrypted case.
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
    } else if (ret == FS_MGR_MNTALL_DEV_NON_DEFAULT_FILE_ENCRYPTED) {
        if (e4crypt_install_keyring()) {
            return -1;
        }
        property_set("ro.crypto.state", "encrypted");
        property_set("ro.crypto.type", "file");
        property_set("vold.decrypt", "trigger_restart_min_framework");
    } else if (ret > 0) {
        ERROR("fs_mgr_mount_all returned unexpected error %d\n", ret);
    }
    /* else ... < 0: error */

    return ret;
}

int do_swapon_all(const std::vector<std::string>& args)
{
    struct fstab *fstab;
    int ret;

    fstab = fs_mgr_read_fstab(args[1].c_str());
    ret = fs_mgr_swapon_all(fstab);
    fs_mgr_free_fstab(fstab);

    return ret;
}

int do_setprop(const std::vector<std::string>& args)
{
    const char* name = args[1].c_str();
    const char* value = args[2].c_str();
    property_set(name, value);
    return 0;
}

int do_setrlimit(const std::vector<std::string>& args)
{
    struct rlimit limit;
    int resource;
    resource = std::stoi(args[1]);
    limit.rlim_cur = std::stoi(args[2]);
    limit.rlim_max = std::stoi(args[3]);
    return setrlimit(resource, &limit);
}

int do_start(const std::vector<std::string>& args)
{
    Service* svc = ServiceManager::GetInstance().FindServiceByName(args[1]);
    if (!svc) {
        ERROR("do_start: Service %s not found\n", args[1].c_str());
        return -1;
    }
    if (!svc->Start())
        return -1;
    return 0;
}

int do_stop(const std::vector<std::string>& args)
{
    Service* svc = ServiceManager::GetInstance().FindServiceByName(args[1]);
    if (!svc) {
        ERROR("do_stop: Service %s not found\n", args[1].c_str());
        return -1;
    }
    svc->Stop();
    return 0;
}

int do_restart(const std::vector<std::string>& args)
{
    Service* svc = ServiceManager::GetInstance().FindServiceByName(args[1]);
    if (!svc) {
        ERROR("do_restart: Service %s not found\n", args[1].c_str());
        return -1;
    }
    svc->Restart();
    return 0;
}

int do_powerctl(const std::vector<std::string>& args)
{
    const char* command = args[1].c_str();
    int len = 0;
    unsigned int cmd = 0;
    const char *reboot_target = "";
    void (*callback_on_ro_remount)(const struct mntent*) = NULL;

    if (strncmp(command, "shutdown", 8) == 0) {
        cmd = ANDROID_RB_POWEROFF;
        len = 8;
    } else if (strncmp(command, "reboot", 6) == 0) {
        cmd = ANDROID_RB_RESTART2;
        len = 6;
    } else {
        ERROR("powerctl: unrecognized command '%s'\n", command);
        return -EINVAL;
    }

    if (command[len] == ',') {
        if (cmd == ANDROID_RB_POWEROFF &&
            !strcmp(&command[len + 1], "userrequested")) {
            // The shutdown reason is PowerManager.SHUTDOWN_USER_REQUESTED.
            // Run fsck once the file system is remounted in read-only mode.
            callback_on_ro_remount = unmount_and_fsck;
        } else if (cmd == ANDROID_RB_RESTART2) {
            reboot_target = &command[len + 1];
        }
    } else if (command[len] != '\0') {
        ERROR("powerctl: unrecognized reboot target '%s'\n", &command[len]);
        return -EINVAL;
    }

    return android_reboot_with_callback(cmd, 0, reboot_target,
                                        callback_on_ro_remount);
}

int do_trigger(const std::vector<std::string>& args)
{
    ActionManager::GetInstance().QueueEventTrigger(args[1]);
    return 0;
}

int do_symlink(const std::vector<std::string>& args)
{
    return symlink(args[1].c_str(), args[2].c_str());
}

int do_rm(const std::vector<std::string>& args)
{
    return unlink(args[1].c_str());
}

int do_rmdir(const std::vector<std::string>& args)
{
    return rmdir(args[1].c_str());
}

int do_sysclktz(const std::vector<std::string>& args)
{
    struct timezone tz;

    if (args.size() != 2)
        return -1;

    memset(&tz, 0, sizeof(tz));
    tz.tz_minuteswest = std::stoi(args[1]);
    if (settimeofday(NULL, &tz))
        return -1;
    return 0;
}

int do_verity_load_state(const std::vector<std::string>& args) {
    int mode = -1;
    int rc = fs_mgr_load_verity_state(&mode);
    if (rc == 0 && mode == VERITY_MODE_LOGGING) {
        ActionManager::GetInstance().QueueEventTrigger("verity-logging");
    }
    return rc;
}

static void verity_update_property(fstab_rec *fstab, const char *mount_point, int mode, int status) {
    property_set(android::base::StringPrintf("partition.%s.verified", mount_point).c_str(),
                 android::base::StringPrintf("%d", mode).c_str());
}

int do_verity_update_state(const std::vector<std::string>& args) {
    return fs_mgr_update_verity_state(verity_update_property);
}

int do_write(const std::vector<std::string>& args)
{
    const char* path = args[1].c_str();
    const char* value = args[2].c_str();
    return write_file(path, value);
}

int do_copy(const std::vector<std::string>& args)
{
    char *buffer = NULL;
    int rc = 0;
    int fd1 = -1, fd2 = -1;
    struct stat info;
    int brtw, brtr;
    char *p;

    if (args.size() != 3)
        return -1;

    if (stat(args[1].c_str(), &info) < 0)
        return -1;

    if ((fd1 = open(args[1].c_str(), O_RDONLY|O_CLOEXEC)) < 0)
        goto out_err;

    if ((fd2 = open(args[2].c_str(), O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0660)) < 0)
        goto out_err;

    if (!(buffer = (char*) malloc(info.st_size)))
        goto out_err;

    p = buffer;
    brtr = info.st_size;
    while(brtr) {
        rc = read(fd1, p, brtr);
        if (rc < 0)
            goto out_err;
        if (rc == 0)
            break;
        p += rc;
        brtr -= rc;
    }

    p = buffer;
    brtw = info.st_size;
    while(brtw) {
        rc = write(fd2, p, brtw);
        if (rc < 0)
            goto out_err;
        if (rc == 0)
            break;
        p += rc;
        brtw -= rc;
    }

    rc = 0;
    goto out;
out_err:
    rc = -1;
out:
    if (buffer)
        free(buffer);
    if (fd1 >= 0)
        close(fd1);
    if (fd2 >= 0)
        close(fd2);
    return rc;
}

int do_chown(const std::vector<std::string>& args) {
    /* GID is optional. */
    if (args.size() == 3) {
        if (lchown(args[2].c_str(), decode_uid(args[1].c_str()), -1) == -1)
            return -errno;
    } else if (args.size() == 4) {
        if (lchown(args[3].c_str(), decode_uid(args[1].c_str()),
                   decode_uid(args[2].c_str())) == -1)
            return -errno;
    } else {
        return -1;
    }
    return 0;
}

static mode_t get_mode(const char *s) {
    mode_t mode = 0;
    while (*s) {
        if (*s >= '0' && *s <= '7') {
            mode = (mode<<3) | (*s-'0');
        } else {
            return -1;
        }
        s++;
    }
    return mode;
}

int do_chmod(const std::vector<std::string>& args) {
    mode_t mode = get_mode(args[1].c_str());
    if (fchmodat(AT_FDCWD, args[2].c_str(), mode, AT_SYMLINK_NOFOLLOW) < 0) {
        return -errno;
    }
    return 0;
}

int do_restorecon(const std::vector<std::string>& args) {
    int ret = 0;

    for (auto it = std::next(args.begin()); it != args.end(); ++it) {
        if (restorecon(it->c_str()) < 0)
            ret = -errno;
    }
    return ret;
}

int do_restorecon_recursive(const std::vector<std::string>& args) {
    int ret = 0;

    for (auto it = std::next(args.begin()); it != args.end(); ++it) {
        if (restorecon_recursive(it->c_str()) < 0)
            ret = -errno;
    }
    return ret;
}

int do_loglevel(const std::vector<std::string>& args) {
    if (args.size() != 2) {
        ERROR("loglevel: missing argument\n");
        return -EINVAL;
    }

    int log_level = std::stoi(args[1]);
    if (log_level < KLOG_ERROR_LEVEL || log_level > KLOG_DEBUG_LEVEL) {
        ERROR("loglevel: invalid log level'%d'\n", log_level);
        return -EINVAL;
    }
    klog_set_level(log_level);
    return 0;
}

int do_load_persist_props(const std::vector<std::string>& args) {
    if (args.size() == 1) {
        load_persist_props();
        return 0;
    }
    return -1;
}

int do_load_all_props(const std::vector<std::string>& args) {
    if (args.size() == 1) {
        load_all_props();
        return 0;
    }
    return -1;
}

int do_wait(const std::vector<std::string>& args)
{
    if (args.size() == 2) {
        return wait_for_file(args[1].c_str(), COMMAND_RETRY_TIMEOUT);
    } else if (args.size() == 3) {
        return wait_for_file(args[1].c_str(), std::stoi(args[2]));
    } else
        return -1;
}

/*
 * Callback to make a directory from the ext4 code
 */
static int do_installkeys_ensure_dir_exists(const char* dir)
{
    if (make_dir(dir, 0700) && errno != EEXIST) {
        return -1;
    }

    return 0;
}

int do_installkey(const std::vector<std::string>& args)
{
    if (args.size() != 2) {
        return -1;
    }

    std::string prop_value = property_get("ro.crypto.type");
    if (prop_value != "file") {
        return 0;
    }

    return e4crypt_create_device_key(args[1].c_str(),
                                     do_installkeys_ensure_dir_exists);
}
