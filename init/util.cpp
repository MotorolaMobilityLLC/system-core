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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <map>
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
#include <fs_mgr.h>
#endif

#ifdef INIT_FULL_SOURCES
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

#include <mutex>
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

const std::string kDataDirPrefix("/data/");

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
Result<int> CreateSocket(const std::string& name, int type, bool passcred, bool should_listen,
                         mode_t perm, uid_t uid, gid_t gid, const std::string& socketcon) {
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
        if (setsockopt(fd.get(), SOL_SOCKET, SO_PASSCRED, &on, sizeof(on))) {
            return ErrnoError() << "Failed to set SO_PASSCRED '" << name << "'";
        }
    }

    int ret = bind(fd.get(), (struct sockaddr*)&addr, sizeof(addr));
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
    if (should_listen && listen(fd.get(), /* use OS maximum */ 1 << 30)) {
        return ErrnoError() << "Failed to listen on socket '" << addr.sun_path << "'";
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
    if (fstat(fd.get(), &sb) == -1) {
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

// Reads the content of device tree file under the platform's Android DT directory.
// Returns true if the read is success, false otherwise.
bool read_android_dt_file(const std::string& sub_path, std::string* dt_content) {
#if defined(__ANDROID__)
    const std::string file_name = android::fs_mgr::GetAndroidDtDir() + sub_path;
    if (android::base::ReadFileToString(file_name, dt_content)) {
        if (!dt_content->empty()) {
            dt_content->pop_back();  // Trims the trailing '\0' out.
            return true;
        }
    }
#endif
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

// Remove unnecessary slashes so that any later checks (e.g., the check for
// whether the path is a top-level directory in /data) don't get confused.
std::string CleanDirPath(const std::string& path) {
    std::string result;
    result.reserve(path.length());
    // Collapse duplicate slashes, e.g. //data//foo// => /data/foo/
    for (char c : path) {
        if (c != '/' || result.empty() || result.back() != '/') {
            result += c;
        }
    }
    // Remove trailing slash, e.g. /data/foo/ => /data/foo
    if (result.length() > 1 && result.back() == '/') {
        result.pop_back();
    }
    return result;
}

Result<MkdirOptions> ParseMkdir(const std::vector<std::string>& args) {
    std::string path = CleanDirPath(args[1]);
    const bool is_toplevel_data_dir =
            StartsWith(path, kDataDirPrefix) &&
            path.find_first_of('/', kDataDirPrefix.size()) == std::string::npos;
    FscryptAction fscrypt_action =
            is_toplevel_data_dir ? FscryptAction::kRequire : FscryptAction::kNone;
    mode_t mode = 0755;
    Result<uid_t> uid = -1;
    Result<gid_t> gid = -1;
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
    if (is_toplevel_data_dir) {
        if (!set_option_encryption) {
            LOG(WARNING) << "Top-level directory needs encryption action, eg mkdir " << path
                         << " <mode> <uid> <gid> encryption=Require";
        }
        if (fscrypt_action == FscryptAction::kNone) {
            LOG(INFO) << "Not setting encryption policy on: " << path;
        }
    }

    return MkdirOptions{path, mode, *uid, *gid, fscrypt_action, ref_option};
}

Result<MountAllOptions> ParseMountAll(const std::vector<std::string>& args) {
    bool compat_mode = false;
    bool import_rc = false;
    if (SelinuxGetVendorAndroidVersion() <= __ANDROID_API_Q__) {
        if (args.size() <= 1) {
            return Error() << "mount_all requires at least 1 argument";
        }
        compat_mode = true;
        import_rc = true;
    }

    std::size_t first_option_arg = args.size();
    enum mount_mode mode = MOUNT_MODE_DEFAULT;

    // If we are <= Q, then stop looking for non-fstab arguments at slot 2.
    // Otherwise, stop looking at slot 1 (as the fstab path argument is optional >= R).
    for (std::size_t na = args.size() - 1; na > (compat_mode ? 1 : 0); --na) {
        if (args[na] == "--early") {
            first_option_arg = na;
            mode = MOUNT_MODE_EARLY;
        } else if (args[na] == "--late") {
            first_option_arg = na;
            mode = MOUNT_MODE_LATE;
            import_rc = false;
        }
    }

    std::string fstab_path;
    if (first_option_arg > 1) {
        fstab_path = args[1];
    } else if (compat_mode) {
        return Error() << "mount_all argument 1 must be the fstab path";
    }

    std::vector<std::string> rc_paths;
    for (std::size_t na = 2; na < first_option_arg; ++na) {
        rc_paths.push_back(args[na]);
    }

    return MountAllOptions{rc_paths, fstab_path, mode, import_rc};
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
            {"--force", SELINUX_ANDROID_RESTORECON_FORCE},
            {"--data-data", SELINUX_ANDROID_RESTORECON_DATADATA},
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

Result<std::string> ParseSwaponAll(const std::vector<std::string>& args) {
    if (args.size() <= 1) {
        if (SelinuxGetVendorAndroidVersion() <= __ANDROID_API_Q__) {
            return Error() << "swapon_all requires at least 1 argument";
        }
        return {};
    }
    return args[1];
}

Result<std::string> ParseUmountAll(const std::vector<std::string>& args) {
    if (args.size() <= 1) {
        if (SelinuxGetVendorAndroidVersion() <= __ANDROID_API_Q__) {
            return Error() << "umount_all requires at least 1 argument";
        }
        return {};
    }
    return args[1];
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

// Check if default mount namespace is ready to be used with APEX modules
static bool is_default_mount_namespace_ready = false;

bool IsDefaultMountNamespaceReady() {
    return is_default_mount_namespace_ready;
}

void SetDefaultMountNamespaceReady() {
    is_default_mount_namespace_ready = true;
}

bool Has32BitAbi() {
    static bool has = !android::base::GetProperty("ro.product.cpu.abilist32", "").empty();
    return has;
}

std::string GetApexNameFromFileName(const std::string& path) {
    static const std::string kApexDir = "/apex/";
    if (StartsWith(path, kApexDir)) {
        auto begin = kApexDir.size();
        auto end = path.find('/', begin);
        return path.substr(begin, end - begin);
    }
    return "";
}

std::vector<std::string> FilterVersionedConfigs(const std::vector<std::string>& configs,
                                                int active_sdk) {
    std::vector<std::string> filtered_configs;

    std::map<std::string, std::pair<std::string, int>> script_map;
    for (const auto& c : configs) {
        int sdk = 0;
        const std::vector<std::string> parts = android::base::Split(c, ".");
        std::string base;
        if (parts.size() < 2) {
            continue;
        }

        // parts[size()-1], aka the suffix, should be "rc" or "#rc"
        // any other pattern gets discarded

        const auto& suffix = parts[parts.size() - 1];
        if (suffix == "rc") {
            sdk = 0;
        } else {
            char trailer[9] = {0};
            int r = sscanf(suffix.c_str(), "%d%8s", &sdk, trailer);
            if (r != 2) {
                continue;
            }
            if (strlen(trailer) > 2 || strcmp(trailer, "rc") != 0) {
                continue;
            }
        }

        if (sdk < 0 || sdk > active_sdk) {
            continue;
        }

        base = parts[0];
        for (unsigned int i = 1; i < parts.size() - 1; i++) {
            base = base + "." + parts[i];
        }

        // is this preferred over what we already have
        auto it = script_map.find(base);
        if (it == script_map.end() || it->second.second < sdk) {
            script_map[base] = std::make_pair(c, sdk);
        }
    }

    for (const auto& m : script_map) {
        filtered_configs.push_back(m.second.first);
    }
    return filtered_configs;
}

// Forks, executes the provided program in the child, and waits for the completion in the parent.
// Child's stderr is captured and logged using LOG(ERROR).
bool ForkExecveAndWaitForCompletion(const char* filename, char* const argv[]) {
    // Create a pipe used for redirecting child process's output.
    // * pipe_fds[0] is the FD the parent will use for reading.
    // * pipe_fds[1] is the FD the child will use for writing.
    int pipe_fds[2];
    if (pipe(pipe_fds) == -1) {
        PLOG(ERROR) << "Failed to create pipe";
        return false;
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        PLOG(ERROR) << "Failed to fork for " << filename;
        return false;
    }

    if (child_pid == 0) {
        // fork succeeded -- this is executing in the child process

        // Close the pipe FD not used by this process
        close(pipe_fds[0]);

        // Redirect stderr to the pipe FD provided by the parent
        if (TEMP_FAILURE_RETRY(dup2(pipe_fds[1], STDERR_FILENO)) == -1) {
            PLOG(ERROR) << "Failed to redirect stderr of " << filename;
            _exit(127);
            return false;
        }
        close(pipe_fds[1]);

        if (execv(filename, argv) == -1) {
            PLOG(ERROR) << "Failed to execve " << filename;
            return false;
        }
        // Unreachable because execve will have succeeded and replaced this code
        // with child process's code.
        _exit(127);
        return false;
    } else {
        // fork succeeded -- this is executing in the original/parent process

        // Close the pipe FD not used by this process
        close(pipe_fds[1]);

        // Log the redirected output of the child process.
        // It's unfortunate that there's no standard way to obtain an istream for a file descriptor.
        // As a result, we're buffering all output and logging it in one go at the end of the
        // invocation, instead of logging it as it comes in.
        const int child_out_fd = pipe_fds[0];
        std::string child_output;
        if (!android::base::ReadFdToString(child_out_fd, &child_output)) {
            PLOG(ERROR) << "Failed to capture full output of " << filename;
        }
        close(child_out_fd);
        if (!child_output.empty()) {
            // Log captured output, line by line, because LOG expects to be invoked for each line
            std::istringstream in(child_output);
            std::string line;
            while (std::getline(in, line)) {
                LOG(ERROR) << filename << ": " << line;
            }
        }

        // Wait for child to terminate
        int status;
        if (TEMP_FAILURE_RETRY(waitpid(child_pid, &status, 0)) != child_pid) {
            PLOG(ERROR) << "Failed to wait for " << filename;
            return false;
        }

        if (WIFEXITED(status)) {
            int status_code = WEXITSTATUS(status);
            if (status_code == 0) {
                return true;
            } else {
                LOG(ERROR) << filename << " exited with status " << status_code;
            }
        } else if (WIFSIGNALED(status)) {
            LOG(ERROR) << filename << " killed by signal " << WTERMSIG(status);
        } else if (WIFSTOPPED(status)) {
            LOG(ERROR) << filename << " stopped by signal " << WSTOPSIG(status);
        } else {
            LOG(ERROR) << "waitpid for " << filename << " returned unexpected status: " << status;
        }

        return false;
    }
}

#ifdef MTK_LOG
#if defined(__linux__)
#define DEFAULT_RATELIMIT_INTERVALMS 5000
#define DEFAULT_RATELIMIT_BURST 9

#define MTK_LOG_LINE_MAXCLEN 700
#define MTK_LOG_LINE_MAXTIME 200

struct PropSetLogInfo {
    boot_clock::time_point log_time;
    std::string log;
};

static std::queue<PropSetLogInfo> propsetlog_children;
static size_t propsetlog_len = 0;


static void _KernelLoggerLine_split_final(int fd, int level,
                  const char* tag, const char* msg, int length);

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

        android::base::unique_fd fklog_fd(TEMP_FAILURE_RETRY(open("/dev/kmsg", O_WRONLY | O_CLOEXEC)));
        if (fklog_fd.get() == -1) return -1;

        _KernelLoggerLine_split_final(fklog_fd.get(), 6, "init", reap_log.c_str(), reap_log.length());
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

    LogInfo.log.append(StringPrintf("%s%llu",
                       msg + 8,
                       std::chrono::duration_cast<std::chrono::milliseconds>(LogInfo.log_time.time_since_epoch()).count()));

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


#define _TOO_LONG_FIX_ 300

static void _KernelLoggerLine_split_final(int fd, int level,
                  const char* tag, const char* msg, int length) {

  // The kernel's printk buffer is only |1024 - PREFIX_MAX| bytes, where
  // PREFIX_MAX could be 48 or 32.
  // Reference: kernel/printk/printk.c
  static constexpr int LOG_LINE_MAX = 1024 - 48;
  char buf[LOG_LINE_MAX]  __attribute__((__uninitialized__));
  size_t size;
  size = snprintf(buf, sizeof(buf), "<%d>%s %d: %.*s\n", level, tag, fd, length, msg);

  if (size > sizeof(buf)) {
    size = snprintf(buf + _TOO_LONG_FIX_, sizeof(buf) - _TOO_LONG_FIX_, "../~/..%.*s\n",
      _TOO_LONG_FIX_, msg + (strlen(msg) - _TOO_LONG_FIX_)) + _TOO_LONG_FIX_;
  }

  TEMP_FAILURE_RETRY(write(fd, buf, std::min(size, sizeof(buf))));
}

// This splits the message up line by line, by calling log_function with a pointer to the start of
// each line and the size up to the newline character.  It sends size = -1 for the final line.
template <typename F, typename... Args>
static void SplitByLines(const char* msg, const F& log_function, Args&&... args) {
  const char* newline = strchr(msg, '\n');
  while (newline != nullptr) {
    log_function(msg, newline - msg, args...);
    msg = newline + 1;
    newline = strchr(msg, '\n');
  }

  log_function(msg, -1, args...);
}


static void KernelLoggerLine_split(const char* msg, int length, android::base::LogSeverity severity,
                          const char* tag) {
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

  android::base::unique_fd fklog_fd(TEMP_FAILURE_RETRY(open("/dev/kmsg", O_WRONLY | O_CLOEXEC)));
  if (fklog_fd.get() == -1) return;
  if (!isPropServThrStart()) {
    if (PropSetHook(msg))
      return;
  }
  if (PropServThrGetTid() == gettid()) {
    if (PropSetHook(msg))
      return;
  }

    int level = kLogSeverityToKernelLogLevel[severity];

    _KernelLoggerLine_split_final(fklog_fd.get(), level, tag, msg, length);

}

void KernelLogger_split(android::base::LogId, android::base::LogSeverity severity, const char* tag,
                  const char*, unsigned int, const char* full_message) {
  SplitByLines(full_message, KernelLoggerLine_split, severity, tag);
}
#endif // #if defined(__linux__)

void InitKernelLogging_split(char** argv) {
    if (OpenKmsg() != -1)
        return InitKernelLogging(argv);

    SetFatalRebootTarget();
    android::base::InitLogging(argv, KernelLogger_split, InitAborter);
}

// This function sets up SELinux logging to be written to kmsg, to match init's logging.
int SelinuxSetupKernelLogging_split_check() {
    return OpenKmsg();
}

static int PropServThrStart = 0;
static pid_t PropServThrTid = 0;
static int PersistPropServThrStart = 0;
static pid_t PersistPropServThrTid = 0;
static int SystemPropServThrStart = 0;
static pid_t SystemPropServThrTid = 0;


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

void SetPersistPropServThrStart(int flag) {
    PersistPropServThrStart = flag;
}
int isPersistPropServThrStart(void) {
    return PersistPropServThrStart;
}
void PersistPropServThrSetTid(pid_t newtid) {
    PersistPropServThrTid = newtid;
}
pid_t PersistPropServThrGetTid(void) {
    return PersistPropServThrTid;
}

void SetSystemPropServThrStart(int flag) {
    SystemPropServThrStart = flag;
}
int isSystemPropServThrStart(void) {
    return SystemPropServThrStart;
}
void SystemPropServThrSetTid(pid_t newtid) {
    SystemPropServThrTid = newtid;
}
pid_t SystemPropServThrGetTid(void) {
    return SystemPropServThrTid;
}
//Getwhileepduration Setwhiletime Getwhilepiggybacketed

static android::base::Timer _PropertyFlowTraceTimer;
static std::queue<std::string> _PropertyFlowTraceQueue;
static bool _isInPropertyFlowTrace = false;

static android::base::Timer _PersistPropertyFlowTraceTimer;
static std::queue<std::string> _PersistPropertyFlowTraceQueue;
static bool _isInPersistPropertyFlowTrace = false;

void StartPropertyFlowTraceLog(void) {
    android::base::Timer t;
    _PropertyFlowTraceTimer = t;

    while (!_PropertyFlowTraceQueue.empty())
        _PropertyFlowTraceQueue.pop();

    _isInPropertyFlowTrace = true;

    SnapshotPropertyFlowTraceLog("SPFTL");
}

void SnapshotPropertyFlowTraceLog(const std::string& log) {
    std::string s;

    if (!_isInPropertyFlowTrace)
        return;

    uint64_t nowms = std::chrono::duration_cast<std::chrono::milliseconds>(boot_clock::now().time_since_epoch()).count();

    s.append(log);
    s.append("[");
    s.append(StringPrintf("%llu", (unsigned long long) nowms));
    s.append("] ");

    _PropertyFlowTraceQueue.push(s);
}

void EndPropertyFlowTraceLog(void) {
    std::string s;
    auto duration = _PropertyFlowTraceTimer.duration();

    SnapshotPropertyFlowTraceLog("EPFTL");

    if (_isInPropertyFlowTrace && duration >= 2000ms) {
        s.append(StringPrintf("PropertyFlow took %llu ms, ", (unsigned long long) duration.count()));
        while (!_PropertyFlowTraceQueue.empty()) {
            s.append(_PropertyFlowTraceQueue.front());
            _PropertyFlowTraceQueue.pop();
        }

        LOG(INFO) << s;
    }

    while (!_PropertyFlowTraceQueue.empty())
        _PropertyFlowTraceQueue.pop();

    _isInPropertyFlowTrace = false;
}

void StartPersistPropertyFlowTraceLog(void) {
    android::base::Timer t;
    _PersistPropertyFlowTraceTimer = t;

    while (!_PersistPropertyFlowTraceQueue.empty())
        _PersistPropertyFlowTraceQueue.pop();

    _isInPersistPropertyFlowTrace = true;

    SnapshotPersistPropertyFlowTraceLog("SPFTL");
}

void SnapshotPersistPropertyFlowTraceLog(const std::string& log) {
    std::string s;

    if (!_isInPersistPropertyFlowTrace)
        return;

    uint64_t nowms = std::chrono::duration_cast<std::chrono::milliseconds>(boot_clock::now().time_since_epoch()).count();

    s.append(log);
    s.append("[");
    s.append(StringPrintf("%llu", (unsigned long long) nowms));
    s.append("] ");

    _PersistPropertyFlowTraceQueue.push(s);
}

void EndPersistPropertyFlowTraceLog(void) {
    std::string s;
    auto duration = _PersistPropertyFlowTraceTimer.duration();

    SnapshotPersistPropertyFlowTraceLog("EPFTL");

    if (_isInPersistPropertyFlowTrace && duration >= 2000ms) {
        s.append(StringPrintf("Persist PropertyFlow took %llu ms, ", (unsigned long long) duration.count()));
        while (!_PersistPropertyFlowTraceQueue.empty()) {
            s.append(_PersistPropertyFlowTraceQueue.front());
            _PersistPropertyFlowTraceQueue.pop();
        }

        LOG(INFO) << s;
    }

    while (!_PersistPropertyFlowTraceQueue.empty())
        _PersistPropertyFlowTraceQueue.pop();

    _isInPersistPropertyFlowTrace = false;
}

static int _mtklogdisableratelimit = 0;

void SetMTKLOGDISABLERATELIMIT(void) {
    _mtklogdisableratelimit = 1;
}

int GetMTKLOGDISABLERATELIMIT(void) {
    return _mtklogdisableratelimit;
}
#endif

#ifdef MTK_TRACE
static int marker_fd = -1;

static int OpenTrace(int force) {
    if (marker_fd != -1 || !force)
        return marker_fd;

    marker_fd = open("/sys/kernel/debug/tracing/trace_marker", O_WRONLY | O_CLOEXEC);
    if (marker_fd == -1)
        marker_fd = open("/sys/kernel/tracing/trace_marker", O_WRONLY | O_CLOEXEC);

    return marker_fd;
}

void StartWriteTrace(const char* tracemsg, int pid) {
    int fd = OpenTrace(1);
    int _pid = pid ? pid : getpid();
    char msg[256];
    //int ret;

    if (fd != -1) {
        snprintf(msg, 256, "B|%d|%s", _pid, tracemsg);
        //ret = write(fd, msg, strlen(msg));
        write(fd, msg, strlen(msg));
    }
}

void EndWriteTrace(int pid) {
    int fd = OpenTrace(0);
    int _pid = pid ? pid : getpid();
    char msg[256];
    //int ret;

    if (fd != -1) {
        snprintf(msg, 256, "E|%d", _pid);
        //ret = write(fd, msg, strlen(msg));
        write(fd, msg, strlen(msg));
    }
}
#endif

}  // namespace init
}  // namespace android
