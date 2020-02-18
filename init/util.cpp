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

#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <selinux/android.h>

#if defined(__ANDROID__)
#include <android/api-level.h>
#include <sys/system_properties.h>

#include "reboot_utils.h"
#include "selabel.h"
#include "selinux.h"
#else
#include "host_init_stubs.h"
#endif

#ifdef MTK_LOG
#if defined(__linux__)
#include <sys/uio.h>
#endif

#include <queue>
#include <android-base/stringprintf.h>
#include <android-base/chrono_utils.h>
#include <android-base/parseint.h>
using android::base::StringPrintf;
#endif

using android::base::boot_clock;
using android::base::StartsWith;
using namespace std::literals::string_literals;

namespace android {
namespace init {

const std::string kDefaultAndroidDtDir("/proc/device-tree/firmware/android/");

void (*trigger_shutdown)(const std::string& command) = nullptr;

// DecodeUid() - decodes and returns the given string, which can be either the
// numeric or name representation, into the integer uid or gid.
Result<uid_t> DecodeUid(const std::string& name) {
    if (isalpha(name[0])) {
        passwd* pwd = getpwnam(name.c_str());
        if (!pwd) return ErrnoError() << "getpwnam failed";

        return pwd->pw_uid;
    }

    errno = 0;
    uid_t result = static_cast<uid_t>(strtoul(name.c_str(), 0, 0));
    if (errno) return ErrnoError() << "strtoul failed";

    return result;
}

/*
 * CreateSocket - creates a Unix domain socket in ANDROID_SOCKET_DIR
 * ("/dev/socket") as dictated in init.rc. This socket is inherited by the
 * daemon. We communicate the file descriptor's value via the environment
 * variable ANDROID_SOCKET_ENV_PREFIX<name> ("ANDROID_SOCKET_foo").
 */
Result<int> CreateSocket(const std::string& name, int type, bool passcred, mode_t perm, uid_t uid,
                         gid_t gid, const std::string& socketcon) {
    if (!socketcon.empty()) {
        if (setsockcreatecon(socketcon.c_str()) == -1) {
            return ErrnoError() << "setsockcreatecon(\"" << socketcon << "\") failed";
        }
    }

    android::base::unique_fd fd(socket(PF_UNIX, type, 0));
    if (fd < 0) {
        return ErrnoError() << "Failed to open socket '" << name << "'";
    }

    if (!socketcon.empty()) setsockcreatecon(nullptr);

    struct sockaddr_un addr;
    memset(&addr, 0 , sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), ANDROID_SOCKET_DIR "/%s", name.c_str());

    if ((unlink(addr.sun_path) != 0) && (errno != ENOENT)) {
        return ErrnoError() << "Failed to unlink old socket '" << name << "'";
    }

    std::string secontext;
    if (SelabelLookupFileContext(addr.sun_path, S_IFSOCK, &secontext) && !secontext.empty()) {
        setfscreatecon(secontext.c_str());
    }

    if (passcred) {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on))) {
            return ErrnoError() << "Failed to set SO_PASSCRED '" << name << "'";
        }
    }

    int ret = bind(fd, (struct sockaddr *) &addr, sizeof (addr));
    int savederrno = errno;

    if (!secontext.empty()) {
        setfscreatecon(nullptr);
    }

    auto guard = android::base::make_scope_guard([&addr] { unlink(addr.sun_path); });

    if (ret) {
        errno = savederrno;
        return ErrnoError() << "Failed to bind socket '" << name << "'";
    }

    if (lchown(addr.sun_path, uid, gid)) {
        return ErrnoError() << "Failed to lchown socket '" << addr.sun_path << "'";
    }
    if (fchmodat(AT_FDCWD, addr.sun_path, perm, AT_SYMLINK_NOFOLLOW)) {
        return ErrnoError() << "Failed to fchmodat socket '" << addr.sun_path << "'";
    }

    LOG(INFO) << "Created socket '" << addr.sun_path << "'"
              << ", mode " << std::oct << perm << std::dec
              << ", user " << uid
              << ", group " << gid;

    guard.Disable();
    return fd.release();
}

Result<std::string> ReadFile(const std::string& path) {
    android::base::unique_fd fd(
        TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) {
        return ErrnoError() << "open() failed";
    }

    // For security reasons, disallow world-writable
    // or group-writable files.
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        return ErrnoError() << "fstat failed()";
    }
    if ((sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return Error() << "Skipping insecure file";
    }

    std::string content;
    if (!android::base::ReadFdToString(fd, &content)) {
        return ErrnoError() << "Unable to read file contents";
    }
    return content;
}

static int OpenFile(const std::string& path, int flags, mode_t mode) {
    std::string secontext;
    if (SelabelLookupFileContext(path, mode, &secontext) && !secontext.empty()) {
        setfscreatecon(secontext.c_str());
    }

    int rc = open(path.c_str(), flags, mode);

    if (!secontext.empty()) {
        int save_errno = errno;
        setfscreatecon(nullptr);
        errno = save_errno;
    }

    return rc;
}

Result<void> WriteFile(const std::string& path, const std::string& content) {
    android::base::unique_fd fd(TEMP_FAILURE_RETRY(
        OpenFile(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC | O_CLOEXEC, 0600)));
    if (fd == -1) {
        return ErrnoError() << "open() failed";
    }
    if (!android::base::WriteStringToFd(content, fd)) {
        return ErrnoError() << "Unable to write file contents";
    }
    return {};
}

bool mkdir_recursive(const std::string& path, mode_t mode) {
    std::string::size_type slash = 0;
    while ((slash = path.find('/', slash + 1)) != std::string::npos) {
        auto directory = path.substr(0, slash);
        struct stat info;
        if (stat(directory.c_str(), &info) != 0) {
            auto ret = make_dir(directory, mode);
            if (!ret && errno != EEXIST) return false;
        }
    }
    auto ret = make_dir(path, mode);
    if (!ret && errno != EEXIST) return false;
    return true;
}

int wait_for_file(const char* filename, std::chrono::nanoseconds timeout) {
    android::base::Timer t;
    while (t.duration() < timeout) {
        struct stat sb;
        if (stat(filename, &sb) != -1) {
            LOG(INFO) << "wait for '" << filename << "' took " << t;
            return 0;
        }
        std::this_thread::sleep_for(10ms);
    }
    LOG(WARNING) << "wait for '" << filename << "' timed out and took " << t;
    return -1;
}

void ImportKernelCmdline(const std::function<void(const std::string&, const std::string&)>& fn) {
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);

    for (const auto& entry : android::base::Split(android::base::Trim(cmdline), " ")) {
        std::vector<std::string> pieces = android::base::Split(entry, "=");
        if (pieces.size() == 2) {
            fn(pieces[0], pieces[1]);
        }
    }
}

bool make_dir(const std::string& path, mode_t mode) {
    std::string secontext;
    if (SelabelLookupFileContext(path, mode, &secontext) && !secontext.empty()) {
        setfscreatecon(secontext.c_str());
    }

    int rc = mkdir(path.c_str(), mode);

    if (!secontext.empty()) {
        int save_errno = errno;
        setfscreatecon(nullptr);
        errno = save_errno;
    }

    return rc == 0;
}

/*
 * Returns true is pathname is a directory
 */
bool is_dir(const char* pathname) {
    struct stat info;
    if (stat(pathname, &info) == -1) {
        return false;
    }
    return S_ISDIR(info.st_mode);
}

Result<std::string> ExpandProps(const std::string& src) {
    const char* src_ptr = src.c_str();

    std::string dst;

    /* - variables can either be $x.y or ${x.y}, in case they are only part
     *   of the string.
     * - will accept $$ as a literal $.
     * - no nested property expansion, i.e. ${foo.${bar}} is not supported,
     *   bad things will happen
     * - ${x.y:-default} will return default value if property empty.
     */
    while (*src_ptr) {
        const char* c;

        c = strchr(src_ptr, '$');
        if (!c) {
            dst.append(src_ptr);
            return dst;
        }

        dst.append(src_ptr, c);
        c++;

        if (*c == '$') {
            dst.push_back(*(c++));
            src_ptr = c;
            continue;
        } else if (*c == '\0') {
            return dst;
        }

        std::string prop_name;
        std::string def_val;
        if (*c == '{') {
            c++;
            const char* end = strchr(c, '}');
            if (!end) {
                // failed to find closing brace, abort.
                return Error() << "unexpected end of string in '" << src << "', looking for }";
            }
            prop_name = std::string(c, end);
            c = end + 1;
            size_t def = prop_name.find(":-");
            if (def < prop_name.size()) {
                def_val = prop_name.substr(def + 2);
                prop_name = prop_name.substr(0, def);
            }
        } else {
            prop_name = c;
            if (SelinuxGetVendorAndroidVersion() >= __ANDROID_API_R__) {
                return Error() << "using deprecated syntax for specifying property '" << c
                               << "', use ${name} instead";
            } else {
                LOG(ERROR) << "using deprecated syntax for specifying property '" << c
                           << "', use ${name} instead";
            }
            c += prop_name.size();
        }

        if (prop_name.empty()) {
            return Error() << "invalid zero-length property name in '" << src << "'";
        }

        std::string prop_val = android::base::GetProperty(prop_name, "");
        if (prop_val.empty()) {
            if (def_val.empty()) {
                return Error() << "property '" << prop_name << "' doesn't exist while expanding '"
                               << src << "'";
            }
            prop_val = def_val;
        }

        dst.append(prop_val);
        src_ptr = c;
    }

    return dst;
}

static std::string init_android_dt_dir() {
    // Use the standard procfs-based path by default
    std::string android_dt_dir = kDefaultAndroidDtDir;
    // The platform may specify a custom Android DT path in kernel cmdline
    ImportKernelCmdline([&](const std::string& key, const std::string& value) {
        if (key == "androidboot.android_dt_dir") {
            android_dt_dir = value;
        }
    });
    LOG(INFO) << "Using Android DT directory " << android_dt_dir;
    return android_dt_dir;
}

// FIXME: The same logic is duplicated in system/core/fs_mgr/
const std::string& get_android_dt_dir() {
    // Set once and saves time for subsequent calls to this function
    static const std::string kAndroidDtDir = init_android_dt_dir();
    return kAndroidDtDir;
}

// Reads the content of device tree file under the platform's Android DT directory.
// Returns true if the read is success, false otherwise.
bool read_android_dt_file(const std::string& sub_path, std::string* dt_content) {
    const std::string file_name = get_android_dt_dir() + sub_path;
    if (android::base::ReadFileToString(file_name, dt_content)) {
        if (!dt_content->empty()) {
            dt_content->pop_back();  // Trims the trailing '\0' out.
            return true;
        }
    }
    return false;
}

bool is_android_dt_value_expected(const std::string& sub_path, const std::string& expected_content) {
    std::string dt_content;
    if (read_android_dt_file(sub_path, &dt_content)) {
        if (dt_content == expected_content) {
            return true;
        }
    }
    return false;
}

bool IsLegalPropertyName(const std::string& name) {
    size_t namelen = name.size();

    if (namelen < 1) return false;
    if (name[0] == '.') return false;
    if (name[namelen - 1] == '.') return false;

    /* Only allow alphanumeric, plus '.', '-', '@', ':', or '_' */
    /* Don't allow ".." to appear in a property name */
    for (size_t i = 0; i < namelen; i++) {
        if (name[i] == '.') {
            // i=0 is guaranteed to never have a dot. See above.
            if (name[i - 1] == '.') return false;
            continue;
        }
        if (name[i] == '_' || name[i] == '-' || name[i] == '@' || name[i] == ':') continue;
        if (name[i] >= 'a' && name[i] <= 'z') continue;
        if (name[i] >= 'A' && name[i] <= 'Z') continue;
        if (name[i] >= '0' && name[i] <= '9') continue;
        return false;
    }

    return true;
}

Result<void> IsLegalPropertyValue(const std::string& name, const std::string& value) {
    if (value.size() >= PROP_VALUE_MAX && !StartsWith(name, "ro.")) {
        return Error() << "Property value too long";
    }

    if (mbstowcs(nullptr, value.data(), 0) == static_cast<std::size_t>(-1)) {
        return Error() << "Value is not a UTF8 encoded string";
    }

    return {};
}

static FscryptAction FscryptInferAction(const std::string& dir) {
    const std::string prefix = "/data/";

    if (!android::base::StartsWith(dir, prefix)) {
        return FscryptAction::kNone;
    }

    // Special-case /data/media/obb per b/64566063
    if (dir == "/data/media/obb") {
        // Try to set policy on this directory, but if it is non-empty this may fail.
        return FscryptAction::kAttempt;
    }

    // Only set policy on first level /data directories
    // To make this less restrictive, consider using a policy file.
    // However this is overkill for as long as the policy is simply
    // to apply a global policy to all /data folders created via makedir
    if (dir.find_first_of('/', prefix.size()) != std::string::npos) {
        return FscryptAction::kNone;
    }

    // Special case various directories that must not be encrypted,
    // often because their subdirectories must be encrypted.
    // This isn't a nice way to do this, see b/26641735
    std::vector<std::string> directories_to_exclude = {
            "lost+found", "system_ce", "system_de", "misc_ce",     "misc_de",
            "vendor_ce",  "vendor_de", "media",     "data",        "user",
            "user_de",    "apex",      "preloads",  "app-staging", "gsi",
    };
    for (const auto& d : directories_to_exclude) {
        if ((prefix + d) == dir) {
            return FscryptAction::kNone;
        }
    }
    // Empty these directories if policy setting fails.
    std::vector<std::string> wipe_on_failure = {
            "rollback", "rollback-observer",  // b/139193659
    };
    for (const auto& d : wipe_on_failure) {
        if ((prefix + d) == dir) {
            return FscryptAction::kDeleteIfNecessary;
        }
    }
    return FscryptAction::kRequire;
}

Result<MkdirOptions> ParseMkdir(const std::vector<std::string>& args) {
    mode_t mode = 0755;
    Result<uid_t> uid = -1;
    Result<gid_t> gid = -1;
    FscryptAction fscrypt_inferred_action = FscryptInferAction(args[1]);
    FscryptAction fscrypt_action = fscrypt_inferred_action;
    std::string ref_option = "ref";
    bool set_option_encryption = false;
    bool set_option_key = false;

    for (size_t i = 2; i < args.size(); i++) {
        switch (i) {
            case 2:
                mode = std::strtoul(args[2].c_str(), 0, 8);
                break;
            case 3:
                uid = DecodeUid(args[3]);
                if (!uid.ok()) {
                    return Error()
                           << "Unable to decode UID for '" << args[3] << "': " << uid.error();
                }
                break;
            case 4:
                gid = DecodeUid(args[4]);
                if (!gid.ok()) {
                    return Error()
                           << "Unable to decode GID for '" << args[4] << "': " << gid.error();
                }
                break;
            default:
                auto parts = android::base::Split(args[i], "=");
                if (parts.size() != 2) {
                    return Error() << "Can't parse option: '" << args[i] << "'";
                }
                auto optname = parts[0];
                auto optval = parts[1];
                if (optname == "encryption") {
                    if (set_option_encryption) {
                        return Error() << "Duplicated option: '" << optname << "'";
                    }
                    if (optval == "Require") {
                        fscrypt_action = FscryptAction::kRequire;
                    } else if (optval == "None") {
                        fscrypt_action = FscryptAction::kNone;
                    } else if (optval == "Attempt") {
                        fscrypt_action = FscryptAction::kAttempt;
                    } else if (optval == "DeleteIfNecessary") {
                        fscrypt_action = FscryptAction::kDeleteIfNecessary;
                    } else {
                        return Error() << "Unknown encryption option: '" << optval << "'";
                    }
                    set_option_encryption = true;
                } else if (optname == "key") {
                    if (set_option_key) {
                        return Error() << "Duplicated option: '" << optname << "'";
                    }
                    if (optval == "ref" || optval == "per_boot_ref") {
                        ref_option = optval;
                    } else {
                        return Error() << "Unknown key option: '" << optval << "'";
                    }
                    set_option_key = true;
                } else {
                    return Error() << "Unknown option: '" << args[i] << "'";
                }
        }
    }
    if (set_option_key && fscrypt_action == FscryptAction::kNone) {
        return Error() << "Key option set but encryption action is none";
    }
    const std::string prefix = "/data/";
    if (StartsWith(args[1], prefix) &&
        args[1].find_first_of('/', prefix.size()) == std::string::npos) {
        if (!set_option_encryption) {
            LOG(WARNING) << "Top-level directory needs encryption action, eg mkdir " << args[1]
                         << " <mode> <uid> <gid> encryption=Require";
        }
        if (fscrypt_action == FscryptAction::kNone) {
            LOG(INFO) << "Not setting encryption policy on: " << args[1];
        }
    }
    if (fscrypt_action != fscrypt_inferred_action) {
        LOG(WARNING) << "Inferred action different from explicit one, expected "
                     << static_cast<int>(fscrypt_inferred_action) << " but got "
                     << static_cast<int>(fscrypt_action);
    }

    return MkdirOptions{args[1], mode, *uid, *gid, fscrypt_action, ref_option};
}

Result<std::pair<int, std::vector<std::string>>> ParseRestorecon(
        const std::vector<std::string>& args) {
    struct flag_type {
        const char* name;
        int value;
    };
    static const flag_type flags[] = {
            {"--recursive", SELINUX_ANDROID_RESTORECON_RECURSE},
            {"--skip-ce", SELINUX_ANDROID_RESTORECON_SKIPCE},
            {"--cross-filesystems", SELINUX_ANDROID_RESTORECON_CROSS_FILESYSTEMS},
            {0, 0}};

    int flag = 0;
    std::vector<std::string> paths;

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
            paths.emplace_back(args[i]);
        }
    }
    return std::pair(flag, paths);
}

static void InitAborter(const char* abort_message) {
    // When init forks, it continues to use this aborter for LOG(FATAL), but we want children to
    // simply abort instead of trying to reboot the system.
    if (getpid() != 1) {
        android::base::DefaultAborter(abort_message);
        return;
    }

    InitFatalReboot(SIGABRT);
}

// The kernel opens /dev/console and uses that fd for stdin/stdout/stderr if there is a serial
// console enabled and no initramfs, otherwise it does not provide any fds for stdin/stdout/stderr.
// SetStdioToDevNull() is used to close these existing fds if they exist and replace them with
// /dev/null regardless.
//
// In the case that these fds are provided by the kernel, the exec of second stage init causes an
// SELinux denial as it does not have access to /dev/console.  In the case that they are not
// provided, exec of any further process is potentially dangerous as the first fd's opened by that
// process will take the stdin/stdout/stderr fileno's, which can cause issues if printf(), etc is
// then used by that process.
//
// Lastly, simply calling SetStdioToDevNull() in first stage init is not enough, since first
// stage init still runs in kernel context, future child processes will not have permissions to
// access any fds that it opens, including the one opened below for /dev/null.  Therefore,
// SetStdioToDevNull() must be called again in second stage init.
void SetStdioToDevNull(char** argv) {
    // Make stdin/stdout/stderr all point to /dev/null.
    int fd = open("/dev/null", O_RDWR);  // NOLINT(android-cloexec-open)
    if (fd == -1) {
        int saved_errno = errno;
        android::base::InitLogging(argv, &android::base::KernelLogger, InitAborter);
        errno = saved_errno;
        PLOG(FATAL) << "Couldn't open /dev/null";
    }
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO) close(fd);
}

void InitKernelLogging(char** argv) {
    SetFatalRebootTarget();
    android::base::InitLogging(argv, &android::base::KernelLogger, InitAborter);
}

bool IsRecoveryMode() {
    return access("/system/bin/recovery", F_OK) == 0;
}

#ifdef MTK_LOG
#if defined(__linux__)
#define DEFAULT_RATELIMIT_INTERVALMS 5100
#define DEFAULT_RATELIMIT_BURST 9

#define __MAXLOGFD__ 2
static int klogfd[__MAXLOGFD__] = {-1};
static boot_clock::time_point log_time[__MAXLOGFD__];
static int log_printed[__MAXLOGFD__] = {0};
static int inited[__MAXLOGFD__] = {0};
static boot_clock::time_point *plog_time[__MAXLOGFD__] = {NULL};

#define _SPLIT_PROPSET_ 0
#define _SPLIT_OTHER_ 1

#define MTK_LOG_LINE_MAXCLEN 700
#define MTK_LOG_LINE_MAXTIME 200

struct PropSetLogInfo {
    boot_clock::time_point log_time;
    std::string log;
};

static std::queue<PropSetLogInfo> propsetlog_children;
static size_t propsetlog_len = 0;
static constexpr uint32_t kNanosecondsPerMicrosecond = 1e3;
static constexpr uint32_t kMicrosecondsPerSecond = 1e6;

static void _KernelLogger_split_final(int fd, int level,
                  const char* tag, const char* msg);
static int _GetSplitFD(int idx);

int PropSetLogReap(int force) {
    if (propsetlog_children.empty()) {
        return -1;
    }

    auto& log = propsetlog_children.front();
    auto duration = boot_clock::now() - log.log_time;
    auto duration_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    if (force ||
        propsetlog_len >= MTK_LOG_LINE_MAXCLEN ||
        duration_ms >= MTK_LOG_LINE_MAXTIME) {
        std::string reap_log("ReapLog");

        if (propsetlog_len >= MTK_LOG_LINE_MAXCLEN)
            reap_log.append("C");
        else if (force)
            reap_log.append("F");
        else
            reap_log.append("T");

        reap_log.append(" PropSet");

        while (!propsetlog_children.empty()) {
            auto& tmplog = propsetlog_children.front();

            reap_log.append(" ");
            reap_log.append(tmplog.log);

            propsetlog_children.pop();
        }

        reap_log.append(" Done");
        propsetlog_len = 0;

        int fklog_fd = _GetSplitFD(_SPLIT_PROPSET_);
        if (fklog_fd == -1) return -1;

        _KernelLogger_split_final(fklog_fd, 6, "init", reap_log.c_str());
    }
    else {
        return (MTK_LOG_LINE_MAXTIME - duration_ms);
    }

    return -1;
}

int PropSetHook(const char* msg) {
  int force = 0;
  int vRet = 0;

  if (android::base::StartsWith(msg, "PropSet ")) {

    struct PropSetLogInfo LogInfo;
    LogInfo.log_time = boot_clock::now();
    uint64_t log_us = LogInfo.log_time.time_since_epoch().count() / kNanosecondsPerMicrosecond;

    LogInfo.log.append(StringPrintf("%s%llu.%llu",
                       msg + 8,
                       (unsigned long long) (log_us / kMicrosecondsPerSecond),
                       (unsigned long long) (log_us % kMicrosecondsPerSecond)));

    propsetlog_len += LogInfo.log.length();
    propsetlog_children.push(LogInfo);

    vRet = 1;
  } else if (!propsetlog_children.empty()) {
    force = 1;
  }

  PropSetLogReap(force);

  return vRet;
}

#if defined(__linux__)
static int OpenKmsg() {
#if defined(__ANDROID__)
  // pick up 'file w /dev/kmsg' environment from daemon's init rc file
  const auto val = getenv("ANDROID_FILE__dev_kmsg");
  if (val != nullptr) {
    int fd;
    if (android::base::ParseInt(val, &fd, 0)) {
      auto flags = fcntl(fd, F_GETFL);
      if ((flags != -1) && ((flags & O_ACCMODE) == O_WRONLY)) return fd;
    }
  }
#endif
  return -1;
}
#endif

static int _GetSplitFD(int idx)
{
  if (!inited[idx]) {
    klogfd[idx] = TEMP_FAILURE_RETRY(open("/dev/kmsg", O_WRONLY | O_CLOEXEC));
    inited[idx] = 1;
  }

  if (plog_time[idx] == NULL) {
    log_time[idx] = boot_clock::now();
    plog_time[idx] = &log_time[idx];
  }

  auto exec_duration = boot_clock::now() - *plog_time[idx];
  auto exec_duration_ms =
         std::chrono::duration_cast<std::chrono::milliseconds>(exec_duration).count();

  if (exec_duration_ms >= DEFAULT_RATELIMIT_INTERVALMS) {
    *plog_time[idx] = boot_clock::now();
    log_printed[idx] = 0;
  }

  if (log_printed[idx] >= DEFAULT_RATELIMIT_BURST) {
    int newfd;
    newfd = TEMP_FAILURE_RETRY(open("/dev/kmsg", O_WRONLY | O_CLOEXEC));

    if (newfd >= 0) {
       close(klogfd[idx]);
       klogfd[idx] = newfd;
       *plog_time[idx] = boot_clock::now();
       log_printed[idx] = 0;
    }
  }

  log_printed[idx]++;

  return klogfd[idx];
}

void PropSetLogReset()
{
  log_printed[_SPLIT_OTHER_] = DEFAULT_RATELIMIT_BURST;
}

static void _KernelLogger_split_final(int fd, int level,
                  const char* tag, const char* msg) {

  // The kernel's printk buffer is only 1024 bytes.
  // TODO: should we automatically break up long lines into multiple lines?
  // Or we could log but with something like "..." at the end?
  char buf[1024];
  size_t size = snprintf(buf, sizeof(buf), "<%d>%s %d: %s\n", level, tag, fd, msg);
  if (size > sizeof(buf)) {
    size = snprintf(buf, sizeof(buf), "<%d>%s: %zu-byte message too long for printk\n",
                    level, tag, size);
  }

  iovec iov[1];
  iov[0].iov_base = buf;
  iov[0].iov_len = size;
  TEMP_FAILURE_RETRY(writev(fd, iov, 1));
}

void KernelLogger_split(android::base::LogId, android::base::LogSeverity severity,
                  const char* tag, const char*, unsigned int, const char* msg) {
  // clang-format off
  static constexpr int kLogSeverityToKernelLogLevel[] = {
      [android::base::VERBOSE] = 7,              // KERN_DEBUG (there is no verbose kernel log
                                                 //             level)
      [android::base::DEBUG] = 7,                // KERN_DEBUG
      [android::base::INFO] = 6,                 // KERN_INFO
      [android::base::WARNING] = 4,              // KERN_WARNING
      [android::base::ERROR] = 3,                // KERN_ERROR
      [android::base::FATAL_WITHOUT_ABORT] = 2,  // KERN_CRIT
      [android::base::FATAL] = 2,                // KERN_CRIT
  };
  // clang-format on
  static_assert(arraysize(kLogSeverityToKernelLogLevel) == android::base::FATAL + 1,
                "Mismatch in size of kLogSeverityToKernelLogLevel and values in LogSeverity");

  int fklog_fd;

  if (isPropServThrStart() == 0 || PropServThrGetTid() == gettid()) {
    if (PropSetHook(msg))
      return;
  }

  if (PropServThrGetTid() == gettid())
    fklog_fd = _GetSplitFD(_SPLIT_PROPSET_);
  else
    fklog_fd = _GetSplitFD(_SPLIT_OTHER_);

  if (fklog_fd == -1) return;

  int level = kLogSeverityToKernelLogLevel[severity];

  _KernelLogger_split_final(fklog_fd, level, tag, msg);
}
#endif // #if defined(__linux__)

void InitKernelLogging_split(char** argv) {
    if (OpenKmsg() != -1)
        return InitKernelLogging(argv);

    SetFatalRebootTarget();
    android::base::InitLogging(argv, KernelLogger_split, InitAborter);
}

#if 0
int selinux_klog_split_callback(int type, const char *fmt, ...) {
    android::base::LogSeverity severity = android::base::ERROR;
    if (type == SELINUX_WARNING) {
        severity = android::base::WARNING;
    } else if (type == SELINUX_INFO) {
        severity = android::base::INFO;
    }
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    _KernelLogger_split(android::base::MAIN, severity, "selinux", nullptr, 0, buf);
    return 0;
}
#endif // #if 0

// This function sets up SELinux logging to be written to kmsg, to match init's logging.
int SelinuxSetupKernelLogging_split_check() {
    return OpenKmsg();
}

static int PropServThrStart = 0;
static pid_t PropServThrTid = 0;

void SetPropServThrStart(int flag) {
    PropServThrStart = flag;
}

int isPropServThrStart(void) {
    return PropServThrStart;
}

void PropServThrSetTid(pid_t newtid) {
    PropServThrTid = newtid;
}

pid_t PropServThrGetTid(void) {
    return PropServThrTid;
}
#endif

#ifdef MTK_TRACE
static int marker_fd = -1;

static int OpenTrace(int force) {
    const char* m_path = "/sys/kernel/debug/tracing/trace_marker";

    if (marker_fd != -1 || !force)
        return marker_fd;

    marker_fd = open(m_path, O_WRONLY | O_CLOEXEC);

    return marker_fd;
}

void StartWriteTrace(const char* tracemsg, int pid) {
    int fd = OpenTrace(1);
    int _pid = pid ? pid : getpid();
    char msg[256];
    int ret;

    if (fd != -1) {
        snprintf (msg, 256, "B|%d|%s", _pid, tracemsg);
        ret = write(fd, msg, strlen(msg));
    }
}

void EndWriteTrace(int pid) {
    int fd = OpenTrace(0);
    int _pid = pid ? pid : getpid();
    char msg[256];
    int ret;

    if (fd != -1) {
        snprintf(msg, 256, "E|%d", _pid);
        ret = write(fd, msg, strlen(msg));
    }
}
#endif

}  // namespace init
}  // namespace android
