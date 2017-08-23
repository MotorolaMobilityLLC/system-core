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

#include "builtins.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <linux/loop.h>
#include <linux/module.h>
#include <mntent.h>
#include <net/if.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <ext4_utils/ext4_crypt.h>
#include <ext4_utils/ext4_crypt_init_extensions.h>
#include <fs_mgr.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/selinux.h>

#include "action.h"
#include "bootchart.h"
#include "init.h"
#include "parser.h"
#include "property_service.h"
#include "reboot.h"
#include "service.h"
#include "signal_handler.h"
#include "util.h"

using namespace std::literals::string_literals;

using android::base::unique_fd;

#define chmod DO_NOT_USE_CHMOD_USE_FCHMODAT_SYMLINK_NOFOLLOW

namespace android {
namespace init {

static constexpr std::chrono::nanoseconds kCommandRetryTimeout = 5s;

static Result<Success> reboot_into_recovery(const std::vector<std::string>& options) {
    std::string err;
    if (!write_bootloader_message(options, &err)) {
        return Error() << "Failed to set bootloader message: " << err;
    }
    property_set("sys.powerctl", "reboot,recovery");
    return Success();
}

template <typename F>
static void ForEachServiceInClass(const std::string& classname, F function) {
    for (const auto& service : ServiceList::GetInstance()) {
        if (service->classnames().count(classname)) std::invoke(function, service);
    }
}

static Result<Success> do_class_start(const std::vector<std::string>& args) {
    // Starting a class does not start services which are explicitly disabled.
    // They must  be started individually.
    ForEachServiceInClass(args[1], &Service::StartIfNotDisabled);
    return Success();
}

static Result<Success> do_class_stop(const std::vector<std::string>& args) {
    ForEachServiceInClass(args[1], &Service::Stop);
    return Success();
}

static Result<Success> do_class_reset(const std::vector<std::string>& args) {
    ForEachServiceInClass(args[1], &Service::Reset);
    return Success();
}

static Result<Success> do_class_restart(const std::vector<std::string>& args) {
    ForEachServiceInClass(args[1], &Service::Restart);
    return Success();
}

static Result<Success> do_domainname(const std::vector<std::string>& args) {
    if (auto result = WriteFile("/proc/sys/kernel/domainname", args[1]); !result) {
        return Error() << "Unable to write to /proc/sys/kernel/domainname: " << result.error();
    }
    return Success();
}

static Result<Success> do_enable(const std::vector<std::string>& args) {
    Service* svc = ServiceList::GetInstance().FindService(args[1]);
    if (!svc) return Error() << "Could not find service";

    if (auto result = svc->Enable(); !result) {
        return Error() << "Could not enable service: " << result.error();
    }

    return Success();
}

static Result<Success> do_exec(const std::vector<std::string>& args) {
    auto service = Service::MakeTemporaryOneshotService(args);
    if (!service) {
        return Error() << "Could not create exec service";
    }
    if (auto result = service->ExecStart(); !result) {
        return Error() << "Could not start exec service: " << result.error();
    }

    ServiceList::GetInstance().AddService(std::move(service));
    return Success();
}

static Result<Success> do_exec_start(const std::vector<std::string>& args) {
    Service* service = ServiceList::GetInstance().FindService(args[1]);
    if (!service) {
        return Error() << "Service not found";
    }

    if (auto result = service->ExecStart(); !result) {
        return Error() << "Could not start exec service: " << result.error();
    }

    return Success();
}

static Result<Success> do_export(const std::vector<std::string>& args) {
    if (setenv(args[1].c_str(), args[2].c_str(), 1) == -1) {
        return ErrnoError() << "setenv() failed";
    }
    return Success();
}

static Result<Success> do_hostname(const std::vector<std::string>& args) {
    if (auto result = WriteFile("/proc/sys/kernel/hostname", args[1]); !result) {
        return Error() << "Unable to write to /proc/sys/kernel/hostname: " << result.error();
    }
    return Success();
}

static Result<Success> do_ifup(const std::vector<std::string>& args) {
    struct ifreq ifr;

    strlcpy(ifr.ifr_name, args[1].c_str(), IFNAMSIZ);

    unique_fd s(TEMP_FAILURE_RETRY(socket(AF_INET, SOCK_DGRAM, 0)));
    if (s < 0) return ErrnoError() << "opening socket failed";

    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        return ErrnoError() << "ioctl(..., SIOCGIFFLAGS, ...) failed";
    }

    ifr.ifr_flags |= IFF_UP;

    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
        return ErrnoError() << "ioctl(..., SIOCSIFFLAGS, ...) failed";
    }

    return Success();
}

static Result<Success> do_insmod(const std::vector<std::string>& args) {
    int flags = 0;
    auto it = args.begin() + 1;

    if (!(*it).compare("-f")) {
        flags = MODULE_INIT_IGNORE_VERMAGIC | MODULE_INIT_IGNORE_MODVERSIONS;
        it++;
    }

    std::string filename = *it++;
    std::string options = android::base::Join(std::vector<std::string>(it, args.end()), ' ');

    unique_fd fd(TEMP_FAILURE_RETRY(open(filename.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) return ErrnoError() << "open(\"" << filename << "\") failed";

    int rc = syscall(__NR_finit_module, fd.get(), options.c_str(), flags);
    if (rc == -1) return ErrnoError() << "finit_module for \"" << filename << "\" failed";

    return Success();
}

// mkdir <path> [mode] [owner] [group]
static Result<Success> do_mkdir(const std::vector<std::string>& args) {
    mode_t mode = 0755;
    if (args.size() >= 3) {
        mode = std::strtoul(args[2].c_str(), 0, 8);
    }

    if (!make_dir(args[1], mode)) {
        /* chmod in case the directory already exists */
        if (errno == EEXIST) {
            if (fchmodat(AT_FDCWD, args[1].c_str(), mode, AT_SYMLINK_NOFOLLOW) == -1) {
                return ErrnoError() << "fchmodat() failed";
            }
        } else {
            return ErrnoError() << "mkdir() failed";
        }
    }

    if (args.size() >= 4) {
        auto uid = DecodeUid(args[3]);
        if (!uid) {
            return Error() << "Unable to decode UID for '" << args[3] << "': " << uid.error();
        }
        Result<gid_t> gid = -1;

        if (args.size() == 5) {
            gid = DecodeUid(args[4]);
            if (!gid) {
                return Error() << "Unable to decode GID for '" << args[3] << "': " << gid.error();
            }
        }

        if (lchown(args[1].c_str(), *uid, *gid) == -1) {
            return ErrnoError() << "lchown failed";
        }

        /* chown may have cleared S_ISUID and S_ISGID, chmod again */
        if (mode & (S_ISUID | S_ISGID)) {
            if (fchmodat(AT_FDCWD, args[1].c_str(), mode, AT_SYMLINK_NOFOLLOW) == -1) {
                return ErrnoError() << "fchmodat failed";
            }
        }
    }

    if (e4crypt_is_native()) {
        if (e4crypt_set_directory_policy(args[1].c_str())) {
            const std::vector<std::string> options = {
                "--prompt_and_wipe_data",
                "--reason=set_policy_failed:"s + args[1]};
            reboot_into_recovery(options);
            return Error() << "reboot into recovery failed";
        }
    }
    return Success();
}

/* umount <path> */
static Result<Success> do_umount(const std::vector<std::string>& args) {
    if (umount(args[1].c_str()) < 0) {
        return ErrnoError() << "umount() failed";
    }
    return Success();
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
static Result<Success> do_mount(const std::vector<std::string>& args) {
    const char* options = nullptr;
    unsigned flags = 0;
    bool wait = false;

    for (size_t na = 4; na < args.size(); na++) {
        size_t i;
        for (i = 0; mount_flags[i].name; i++) {
            if (!args[na].compare(mount_flags[i].name)) {
                flags |= mount_flags[i].flag;
                break;
            }
        }

        if (!mount_flags[i].name) {
            if (!args[na].compare("wait")) {
                wait = true;
                // If our last argument isn't a flag, wolf it up as an option string.
            } else if (na + 1 == args.size()) {
                options = args[na].c_str();
            }
        }
    }

    const char* system = args[1].c_str();
    const char* source = args[2].c_str();
    const char* target = args[3].c_str();

    if (android::base::StartsWith(source, "loop@")) {
        int mode = (flags & MS_RDONLY) ? O_RDONLY : O_RDWR;
        unique_fd fd(TEMP_FAILURE_RETRY(open(source + 5, mode | O_CLOEXEC)));
        if (fd < 0) return ErrnoError() << "open(" << source + 5 << ", " << mode << ") failed";

        for (size_t n = 0;; n++) {
            std::string tmp = android::base::StringPrintf("/dev/block/loop%zu", n);
            unique_fd loop(TEMP_FAILURE_RETRY(open(tmp.c_str(), mode | O_CLOEXEC)));
            if (loop < 0) return ErrnoError() << "open(" << tmp << ", " << mode << ") failed";

            loop_info info;
            /* if it is a blank loop device */
            if (ioctl(loop, LOOP_GET_STATUS, &info) < 0 && errno == ENXIO) {
                /* if it becomes our loop device */
                if (ioctl(loop, LOOP_SET_FD, fd.get()) >= 0) {
                    if (mount(tmp.c_str(), target, system, flags, options) < 0) {
                        ioctl(loop, LOOP_CLR_FD, 0);
                        return ErrnoError() << "mount() failed";
                    }
                    return Success();
                }
            }
        }

        return Error() << "out of loopback devices";
    } else {
        if (wait)
            wait_for_file(source, kCommandRetryTimeout);
        if (mount(source, target, system, flags, options) < 0) {
            return ErrnoError() << "mount() failed";
        }

    }

    return Success();
}

/* Imports .rc files from the specified paths. Default ones are applied if none is given.
 *
 * start_index: index of the first path in the args list
 */
static void import_late(const std::vector<std::string>& args, size_t start_index, size_t end_index) {
    auto& action_manager = ActionManager::GetInstance();
    auto& service_list = ServiceList::GetInstance();
    Parser parser = CreateParser(action_manager, service_list);
    if (end_index <= start_index) {
        // Fallbacks for partitions on which early mount isn't enabled.
        for (const auto& path : late_import_paths) {
            parser.ParseConfig(path);
        }
        late_import_paths.clear();
    } else {
        for (size_t i = start_index; i < end_index; ++i) {
            parser.ParseConfig(args[i]);
        }
    }

    // Turning this on and letting the INFO logging be discarded adds 0.2s to
    // Nexus 9 boot time, so it's disabled by default.
    if (false) DumpState();
}

/* mount_fstab
 *
 *  Call fs_mgr_mount_all() to mount the given fstab
 */
static Result<int> mount_fstab(const char* fstabfile, int mount_mode) {
    /*
     * Call fs_mgr_mount_all() to mount all filesystems.  We fork(2) and
     * do the call in the child to provide protection to the main init
     * process if anything goes wrong (crash or memory leak), and wait for
     * the child to finish in the parent.
     */
    pid_t pid = fork();
    if (pid > 0) {
        /* Parent.  Wait for the child to return */
        int status;
        int wp_ret = TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
        if (wp_ret == -1) {
            // Unexpected error code. We will continue anyway.
            PLOG(WARNING) << "waitpid failed";
        }

        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else {
            return Error() << "child aborted";
        }
    } else if (pid == 0) {
        /* child, call fs_mgr_mount_all() */

        // So we can always see what fs_mgr_mount_all() does.
        // Only needed if someone explicitly changes the default log level in their init.rc.
        android::base::ScopedLogSeverity info(android::base::INFO);

        struct fstab* fstab = fs_mgr_read_fstab(fstabfile);
        int child_ret = fs_mgr_mount_all(fstab, mount_mode);
        fs_mgr_free_fstab(fstab);
        if (child_ret == -1) {
            PLOG(ERROR) << "fs_mgr_mount_all returned an error";
        }
        _exit(child_ret);
    } else {
        return Error() << "fork() failed";
    }
}

/* Queue event based on fs_mgr return code.
 *
 * code: return code of fs_mgr_mount_all
 *
 * This function might request a reboot, in which case it will
 * not return.
 *
 * return code is processed based on input code
 */
static Result<Success> queue_fs_event(int code) {
    if (code == FS_MGR_MNTALL_DEV_NEEDS_ENCRYPTION) {
        ActionManager::GetInstance().QueueEventTrigger("encrypt");
        return Success();
    } else if (code == FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED) {
        property_set("ro.crypto.state", "encrypted");
        property_set("ro.crypto.type", "block");
        ActionManager::GetInstance().QueueEventTrigger("defaultcrypto");
        return Success();
    } else if (code == FS_MGR_MNTALL_DEV_NOT_ENCRYPTED) {
        property_set("ro.crypto.state", "unencrypted");
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
        return Success();
    } else if (code == FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE) {
        property_set("ro.crypto.state", "unsupported");
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
        return Success();
    } else if (code == FS_MGR_MNTALL_DEV_NEEDS_RECOVERY) {
        /* Setup a wipe via recovery, and reboot into recovery */
        PLOG(ERROR) << "fs_mgr_mount_all suggested recovery, so wiping data via recovery.";
        const std::vector<std::string> options = {"--wipe_data", "--reason=fs_mgr_mount_all" };
        reboot_into_recovery(options);
        return Error() << "reboot_into_recovery() failed";
        /* If reboot worked, there is no return. */
    } else if (code == FS_MGR_MNTALL_DEV_FILE_ENCRYPTED) {
        if (e4crypt_install_keyring()) {
            return Error() << "e4crypt_install_keyring() failed";
        }
        property_set("ro.crypto.state", "encrypted");
        property_set("ro.crypto.type", "file");

        // Although encrypted, we have device key, so we do not need to
        // do anything different from the nonencrypted case.
        ActionManager::GetInstance().QueueEventTrigger("nonencrypted");
        return Success();
    } else if (code > 0) {
        Error() << "fs_mgr_mount_all() returned unexpected error " << code;
    }
    /* else ... < 0: error */

    return Error() << "Invalid code: " << code;
}

/* mount_all <fstab> [ <path> ]* [--<options>]*
 *
 * This function might request a reboot, in which case it will
 * not return.
 */
static Result<Success> do_mount_all(const std::vector<std::string>& args) {
    std::size_t na = 0;
    bool import_rc = true;
    bool queue_event = true;
    int mount_mode = MOUNT_MODE_DEFAULT;
    const char* fstabfile = args[1].c_str();
    std::size_t path_arg_end = args.size();
    const char* prop_post_fix = "default";

    for (na = args.size() - 1; na > 1; --na) {
        if (args[na] == "--early") {
            path_arg_end = na;
            queue_event = false;
            mount_mode = MOUNT_MODE_EARLY;
            prop_post_fix = "early";
        } else if (args[na] == "--late") {
            path_arg_end = na;
            import_rc = false;
            mount_mode = MOUNT_MODE_LATE;
            prop_post_fix = "late";
        }
    }

    std::string prop_name = "ro.boottime.init.mount_all."s + prop_post_fix;
    android::base::Timer t;
    auto mount_fstab_return_code = mount_fstab(fstabfile, mount_mode);
    if (!mount_fstab_return_code) {
        return Error() << "mount_fstab() failed " << mount_fstab_return_code.error();
    }
    property_set(prop_name, std::to_string(t.duration().count()));

    if (import_rc) {
        /* Paths of .rc files are specified at the 2nd argument and beyond */
        import_late(args, 2, path_arg_end);
    }

    if (queue_event) {
        /* queue_fs_event will queue event based on mount_fstab return code
         * and return processed return code*/
        auto queue_fs_result = queue_fs_event(*mount_fstab_return_code);
        if (!queue_fs_result) {
            return Error() << "queue_fs_event() failed: " << queue_fs_result.error();
        }
    }

    return Success();
}

static Result<Success> do_swapon_all(const std::vector<std::string>& args) {
    struct fstab *fstab;
    int ret;

    fstab = fs_mgr_read_fstab(args[1].c_str());
    ret = fs_mgr_swapon_all(fstab);
    fs_mgr_free_fstab(fstab);

    if (ret != 0) return Error() << "fs_mgr_swapon_all() failed";
    return Success();
}

static Result<Success> do_setprop(const std::vector<std::string>& args) {
    property_set(args[1], args[2]);
    return Success();
}

static Result<Success> do_setrlimit(const std::vector<std::string>& args) {
    int resource;
    if (!android::base::ParseInt(args[1], &resource)) {
        return Error() << "unable to parse resource, " << args[1];
    }

    struct rlimit limit;
    if (!android::base::ParseUint(args[2], &limit.rlim_cur)) {
        return Error() << "unable to parse rlim_cur, " << args[2];
    }
    if (!android::base::ParseUint(args[3], &limit.rlim_max)) {
        return Error() << "unable to parse rlim_max, " << args[3];
    }

    if (setrlimit(resource, &limit) == -1) {
        return ErrnoError() << "setrlimit failed";
    }
    return Success();
}

static Result<Success> do_start(const std::vector<std::string>& args) {
    Service* svc = ServiceList::GetInstance().FindService(args[1]);
    if (!svc) return Error() << "service " << args[1] << " not found";
    if (auto result = svc->Start(); !result) {
        return Error() << "Could not start service: " << result.error();
    }
    return Success();
}

static Result<Success> do_stop(const std::vector<std::string>& args) {
    Service* svc = ServiceList::GetInstance().FindService(args[1]);
    if (!svc) return Error() << "service " << args[1] << " not found";
    svc->Stop();
    return Success();
}

static Result<Success> do_restart(const std::vector<std::string>& args) {
    Service* svc = ServiceList::GetInstance().FindService(args[1]);
    if (!svc) return Error() << "service " << args[1] << " not found";
    svc->Restart();
    return Success();
}

static Result<Success> do_trigger(const std::vector<std::string>& args) {
    ActionManager::GetInstance().QueueEventTrigger(args[1]);
    return Success();
}

static Result<Success> do_symlink(const std::vector<std::string>& args) {
    if (symlink(args[1].c_str(), args[2].c_str()) < 0) {
        // The symlink builtin is often used to create symlinks for older devices to be backwards
        // compatible with new paths, therefore we skip reporting this error.
        if (errno == EEXIST && android::base::GetMinimumLogSeverity() > android::base::DEBUG) {
            return Success();
        }
        return ErrnoError() << "symlink() failed";
    }
    return Success();
}

static Result<Success> do_rm(const std::vector<std::string>& args) {
    if (unlink(args[1].c_str()) < 0) {
        return ErrnoError() << "unlink() failed";
    }
    return Success();
}

static Result<Success> do_rmdir(const std::vector<std::string>& args) {
    if (rmdir(args[1].c_str()) < 0) {
        return ErrnoError() << "rmdir() failed";
    }
    return Success();
}

static Result<Success> do_sysclktz(const std::vector<std::string>& args) {
    struct timezone tz = {};
    if (!android::base::ParseInt(args[1], &tz.tz_minuteswest)) {
        return Error() << "Unable to parse mins_west_of_gmt";
    }

    if (settimeofday(nullptr, &tz) == -1) {
        return ErrnoError() << "settimeofday() failed";
    }
    return Success();
}

static Result<Success> do_verity_load_state(const std::vector<std::string>& args) {
    int mode = -1;
    bool loaded = fs_mgr_load_verity_state(&mode);
    if (loaded && mode != VERITY_MODE_DEFAULT) {
        ActionManager::GetInstance().QueueEventTrigger("verity-logging");
    }
    if (!loaded) return Error() << "Could not load verity state";

    return Success();
}

static void verity_update_property(fstab_rec *fstab, const char *mount_point,
                                   int mode, int status) {
    property_set("partition."s + mount_point + ".verified", std::to_string(mode));
}

static Result<Success> do_verity_update_state(const std::vector<std::string>& args) {
    if (!fs_mgr_update_verity_state(verity_update_property)) {
        return Error() << "fs_mgr_update_verity_state() failed";
    }
    return Success();
}

static Result<Success> do_write(const std::vector<std::string>& args) {
    if (auto result = WriteFile(args[1], args[2]); !result) {
        return Error() << "Unable to write to file '" << args[1] << "': " << result.error();
    }

    return Success();
}

static Result<Success> do_readahead(const std::vector<std::string>& args) {
    struct stat sb;

    if (stat(args[1].c_str(), &sb)) {
        return ErrnoError() << "Error opening " << args[1];
    }

    // We will do readahead in a forked process in order not to block init
    // since it may block while it reads the
    // filesystem metadata needed to locate the requested blocks.  This
    // occurs frequently with ext[234] on large files using indirect blocks
    // instead of extents, giving the appearance that the call blocks until
    // the requested data has been read.
    pid_t pid = fork();
    if (pid == 0) {
        android::base::Timer t;
        if (S_ISREG(sb.st_mode)) {
            android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(args[1].c_str(), O_RDONLY)));
            if (fd == -1) {
                PLOG(ERROR) << "Error opening file: " << args[1];
                _exit(EXIT_FAILURE);
            }
            if (readahead(fd, 0, std::numeric_limits<size_t>::max())) {
                PLOG(ERROR) << "Error readahead file: " << args[1];
                _exit(EXIT_FAILURE);
            }
        } else if (S_ISDIR(sb.st_mode)) {
            char* paths[] = {const_cast<char*>(args[1].data()), nullptr};
            std::unique_ptr<FTS, decltype(&fts_close)> fts(
                fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR | FTS_XDEV, nullptr), fts_close);
            if (!fts) {
                PLOG(ERROR) << "Error opening directory: " << args[1];
                _exit(EXIT_FAILURE);
            }
            // Traverse the entire hierarchy and do readahead
            for (FTSENT* ftsent = fts_read(fts.get()); ftsent != nullptr;
                 ftsent = fts_read(fts.get())) {
                if (ftsent->fts_info & FTS_F) {
                    android::base::unique_fd fd(
                        TEMP_FAILURE_RETRY(open(ftsent->fts_accpath, O_RDONLY)));
                    if (fd == -1) {
                        PLOG(ERROR) << "Error opening file: " << args[1];
                        continue;
                    }
                    if (readahead(fd, 0, std::numeric_limits<size_t>::max())) {
                        PLOG(ERROR) << "Unable to readahead on file: " << ftsent->fts_accpath;
                    }
                }
            }
        }
        LOG(INFO) << "Readahead " << args[1] << " took " << t;
        _exit(0);
    } else if (pid < 0) {
        return ErrnoError() << "Fork failed";
    }
    return Success();
}

static Result<Success> do_copy(const std::vector<std::string>& args) {
    auto file_contents = ReadFile(args[1]);
    if (!file_contents) {
        return Error() << "Could not read input file '" << args[1] << "': " << file_contents.error();
    }
    if (auto result = WriteFile(args[2], *file_contents); !result) {
        return Error() << "Could not write to output file '" << args[2] << "': " << result.error();
    }

    return Success();
}

static Result<Success> do_chown(const std::vector<std::string>& args) {
    auto uid = DecodeUid(args[1]);
    if (!uid) {
        return Error() << "Unable to decode UID for '" << args[1] << "': " << uid.error();
    }

    // GID is optional and pushes the index of path out by one if specified.
    const std::string& path = (args.size() == 4) ? args[3] : args[2];
    Result<gid_t> gid = -1;

    if (args.size() == 4) {
        gid = DecodeUid(args[2]);
        if (!gid) {
            return Error() << "Unable to decode GID for '" << args[2] << "': " << gid.error();
        }
    }

    if (lchown(path.c_str(), *uid, *gid) == -1) {
        return ErrnoError() << "lchown() failed";
    }

    return Success();
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

static Result<Success> do_chmod(const std::vector<std::string>& args) {
    mode_t mode = get_mode(args[1].c_str());
    if (fchmodat(AT_FDCWD, args[2].c_str(), mode, AT_SYMLINK_NOFOLLOW) < 0) {
        return ErrnoError() << "fchmodat() failed";
    }
    return Success();
}

static Result<Success> do_restorecon(const std::vector<std::string>& args) {
    int ret = 0;

    struct flag_type {const char* name; int value;};
    static const flag_type flags[] = {
        {"--recursive", SELINUX_ANDROID_RESTORECON_RECURSE},
        {"--skip-ce", SELINUX_ANDROID_RESTORECON_SKIPCE},
        {"--cross-filesystems", SELINUX_ANDROID_RESTORECON_CROSS_FILESYSTEMS},
        {0, 0}
    };

    int flag = 0;

    bool in_flags = true;
    for (size_t i = 1; i < args.size(); ++i) {
        if (android::base::StartsWith(args[i], "--")) {
            if (!in_flags) {
                return Error() << "flags must precede paths";
            }
            bool found = false;
            for (size_t j = 0; flags[j].name; ++j) {
                if (args[i] == flags[j].name) {
                    flag |= flags[j].value;
                    found = true;
                    break;
                }
            }
            if (!found) {
                return Error() << "bad flag " << args[i];
            }
        } else {
            in_flags = false;
            if (selinux_android_restorecon(args[i].c_str(), flag) < 0) {
                ret = errno;
            }
        }
    }

    if (ret) return ErrnoError() << "selinux_android_restorecon() failed";
    return Success();
}

static Result<Success> do_restorecon_recursive(const std::vector<std::string>& args) {
    std::vector<std::string> non_const_args(args);
    non_const_args.insert(std::next(non_const_args.begin()), "--recursive");
    return do_restorecon(non_const_args);
}

static Result<Success> do_loglevel(const std::vector<std::string>& args) {
    // TODO: support names instead/as well?
    int log_level = -1;
    android::base::ParseInt(args[1], &log_level);
    android::base::LogSeverity severity;
    switch (log_level) {
        case 7: severity = android::base::DEBUG; break;
        case 6: severity = android::base::INFO; break;
        case 5:
        case 4: severity = android::base::WARNING; break;
        case 3: severity = android::base::ERROR; break;
        case 2:
        case 1:
        case 0: severity = android::base::FATAL; break;
        default:
            return Error() << "invalid log level " << log_level;
    }
    android::base::SetMinimumLogSeverity(severity);
    return Success();
}

static Result<Success> do_load_persist_props(const std::vector<std::string>& args) {
    load_persist_props();
    return Success();
}

static Result<Success> do_load_system_props(const std::vector<std::string>& args) {
    load_system_props();
    return Success();
}

static Result<Success> do_wait(const std::vector<std::string>& args) {
    auto timeout = kCommandRetryTimeout;
    if (args.size() == 3) {
        int timeout_int;
        if (!android::base::ParseInt(args[2], &timeout_int)) {
            return Error() << "failed to parse timeout";
        }
        timeout = std::chrono::seconds(timeout_int);
    }

    if (wait_for_file(args[1].c_str(), timeout) != 0) {
        return Error() << "wait_for_file() failed";
    }

    return Success();
}

static Result<Success> do_wait_for_prop(const std::vector<std::string>& args) {
    const char* name = args[1].c_str();
    const char* value = args[2].c_str();
    size_t value_len = strlen(value);

    if (!is_legal_property_name(name)) {
        return Error() << "is_legal_property_name(" << name << ") failed";
    }
    if (value_len >= PROP_VALUE_MAX) {
        return Error() << "value too long";
    }
    if (!start_waiting_for_property(name, value)) {
        return Error() << "already waiting for a property";
    }
    return Success();
}

static bool is_file_crypto() {
    return android::base::GetProperty("ro.crypto.type", "") == "file";
}

static Result<Success> do_installkey(const std::vector<std::string>& args) {
    if (!is_file_crypto()) return Success();

    auto unencrypted_dir = args[1] + e4crypt_unencrypted_folder;
    if (!make_dir(unencrypted_dir, 0700) && errno != EEXIST) {
        return ErrnoError() << "Failed to create " << unencrypted_dir;
    }
    std::vector<std::string> exec_args = {"exec", "/system/bin/vdc", "--wait", "cryptfs",
                                          "enablefilecrypto"};
    return do_exec(exec_args);
}

static Result<Success> do_init_user0(const std::vector<std::string>& args) {
    std::vector<std::string> exec_args = {"exec", "/system/bin/vdc", "--wait", "cryptfs",
                                          "init_user0"};
    return do_exec(exec_args);
}

const BuiltinFunctionMap::Map& BuiltinFunctionMap::map() const {
    constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
    // clang-format off
    static const Map builtin_functions = {
        {"bootchart",               {1,     1,    do_bootchart}},
        {"chmod",                   {2,     2,    do_chmod}},
        {"chown",                   {2,     3,    do_chown}},
        {"class_reset",             {1,     1,    do_class_reset}},
        {"class_restart",           {1,     1,    do_class_restart}},
        {"class_start",             {1,     1,    do_class_start}},
        {"class_stop",              {1,     1,    do_class_stop}},
        {"copy",                    {2,     2,    do_copy}},
        {"domainname",              {1,     1,    do_domainname}},
        {"enable",                  {1,     1,    do_enable}},
        {"exec",                    {1,     kMax, do_exec}},
        {"exec_start",              {1,     1,    do_exec_start}},
        {"export",                  {2,     2,    do_export}},
        {"hostname",                {1,     1,    do_hostname}},
        {"ifup",                    {1,     1,    do_ifup}},
        {"init_user0",              {0,     0,    do_init_user0}},
        {"insmod",                  {1,     kMax, do_insmod}},
        {"installkey",              {1,     1,    do_installkey}},
        {"load_persist_props",      {0,     0,    do_load_persist_props}},
        {"load_system_props",       {0,     0,    do_load_system_props}},
        {"loglevel",                {1,     1,    do_loglevel}},
        {"mkdir",                   {1,     4,    do_mkdir}},
        {"mount_all",               {1,     kMax, do_mount_all}},
        {"mount",                   {3,     kMax, do_mount}},
        {"umount",                  {1,     1,    do_umount}},
        {"readahead",               {1,     1,    do_readahead}},
        {"restart",                 {1,     1,    do_restart}},
        {"restorecon",              {1,     kMax, do_restorecon}},
        {"restorecon_recursive",    {1,     kMax, do_restorecon_recursive}},
        {"rm",                      {1,     1,    do_rm}},
        {"rmdir",                   {1,     1,    do_rmdir}},
        {"setprop",                 {2,     2,    do_setprop}},
        {"setrlimit",               {3,     3,    do_setrlimit}},
        {"start",                   {1,     1,    do_start}},
        {"stop",                    {1,     1,    do_stop}},
        {"swapon_all",              {1,     1,    do_swapon_all}},
        {"symlink",                 {2,     2,    do_symlink}},
        {"sysclktz",                {1,     1,    do_sysclktz}},
        {"trigger",                 {1,     1,    do_trigger}},
        {"verity_load_state",       {0,     0,    do_verity_load_state}},
        {"verity_update_state",     {0,     0,    do_verity_update_state}},
        {"wait",                    {1,     2,    do_wait}},
        {"wait_for_prop",           {2,     2,    do_wait_for_prop}},
        {"write",                   {2,     2,    do_write}},
    };
    // clang-format on
    return builtin_functions;
}

}  // namespace init
}  // namespace android
