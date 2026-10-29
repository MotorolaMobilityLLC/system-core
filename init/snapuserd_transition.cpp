/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "snapuserd_transition.h"

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <filesystem>
#include <string>
#include <string_view>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <fs_avb/fs_avb.h>
#include <fs_mgr.h>
#include <fs_mgr/file_wait.h>
#include <libsnapshot/snapshot.h>
#include <private/android_filesystem_config.h>
#include <procinfo/process_map.h>
#include <selinux/android.h>
#include <snapuserd/snapuserd_client.h>

#include "block_dev_initializer.h"
#include "lmkd_service.h"
#include "service_utils.h"
#include "util.h"

namespace android {
namespace init {

using namespace std::string_literals;

using android::base::unique_fd;
using android::snapshot::SnapshotManager;
using android::snapshot::SnapuserdClient;

static constexpr char kSnapuserdPath[] = "/system/bin/snapuserd";
static constexpr char kSnapuserdFirstStagePidVar[] = "FIRST_STAGE_SNAPUSERD_PID";
static constexpr char kSnapuserdFirstStageFdVar[] = "FIRST_STAGE_SNAPUSERD_FD";
static constexpr char kSnapuserdLabel[] = "u:object_r:snapuserd_exec:s0";
static constexpr char kSnapuserdSocketLabel[] = "u:object_r:snapuserd_socket:s0";

void LaunchFirstStageSnapuserd(bool use_ublk) {
    SocketDescriptor socket_desc;
    socket_desc.name = android::snapshot::kSnapuserdSocket;
    socket_desc.type = SOCK_STREAM;
    socket_desc.perm = 0660;
    socket_desc.uid = AID_SYSTEM;
    socket_desc.gid = AID_SYSTEM;

    // We specify a label here even though it technically is not needed. During
    // first_stage_mount there is no sepolicy loaded. Once sepolicy is loaded,
    // we bypass the socket entirely.
    auto socket = socket_desc.Create(kSnapuserdSocketLabel);
    if (!socket.ok()) {
        LOG(FATAL) << "Could not create snapuserd socket: " << socket.error();
    }

    pid_t pid = fork();
    if (pid < 0) {
        PLOG(FATAL) << "Cannot launch snapuserd; fork failed";
    }
    if (pid == 0) {
        socket->Publish();

        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(kSnapuserdPath));
        argv.push_back(const_cast<char*>("-user_snapshot"));
        if (use_ublk) {
            argv.push_back(const_cast<char*>("-ublk"));
        } else {
            // Lets add -noublk flag so we make the intent explicit
            // and don't depend on default flag value in snapuserd_daemon.cpp
            argv.push_back(const_cast<char*>("-noublk"));
        }
        argv.push_back(nullptr);

        if (execv(argv[0], argv.data()) < 0) {
            PLOG(FATAL) << "Cannot launch snapuserd; execv failed";
        }
        _exit(127);
    }

    auto client = SnapuserdClient::Connect(android::snapshot::kSnapuserdSocket, 10s);
    if (!client) {
        LOG(FATAL) << "Could not connect to first-stage snapuserd";
    }

    setenv(kSnapuserdFirstStagePidVar, std::to_string(pid).c_str(), 1);

    if (!client->RemoveTransitionedDaemonIndicator()) {
        LOG(ERROR) << "RemoveTransitionedDaemonIndicator failed";
    }

    LOG(INFO) << "Relaunched snapuserd with pid: " << pid;
}

std::optional<pid_t> GetSnapuserdFirstStagePid() {
    const char* pid_str = getenv(kSnapuserdFirstStagePidVar);
    if (!pid_str) {
        return {};
    }

    int pid = 0;
    if (!android::base::ParseInt(pid_str, &pid)) {
        LOG(FATAL) << "Could not parse pid in environment, " << kSnapuserdFirstStagePidVar << "="
                   << pid_str;
    }
    return {pid};
}

static void RelabelLink(const std::string& link) {
    selinux_android_restorecon(link.c_str(), 0);

    std::string path;
    if (android::base::Readlink(link, &path)) {
        selinux_android_restorecon(path.c_str(), 0);
    }
}

static void RelabelDeviceMapper() {
    selinux_android_restorecon("/dev/device-mapper", 0);

    std::error_code ec;
    for (auto& iter : std::filesystem::directory_iterator("/dev/block", ec)) {
        const auto& path = iter.path();
        if (android::base::StartsWith(path.string(), "/dev/block/dm-")) {
            selinux_android_restorecon(path.string().c_str(), 0);
        }
    }
}

static void RelabelUblkDevices() {
    // Relabel ublk block devices: ublkb*
    std::error_code ec;
    for (auto& iter : std::filesystem::directory_iterator("/dev/block", ec)) {
        const auto& path_str = iter.path().string();
        if (android::base::StartsWith(path_str, "/dev/block/ublkb")) {
            selinux_android_restorecon(path_str.c_str(), 0);
        }
    }
    if (ec) {
        LOG(WARNING) << "Error iterating /dev/block/ for ublkb* relabeling: " << ec.message();
    }
    // Relabel /dev/ublkc* control nodes
    for (auto& iter : std::filesystem::directory_iterator("/dev", ec)) {
        const auto& path_str = iter.path().string();
        if (android::base::StartsWith(path_str, "/dev/ublkc")) {
            selinux_android_restorecon(path_str.c_str(), 0);
        }
    }
    if (ec) {
        LOG(WARNING) << "Error iterating /dev for ublkc* relabeling: " << ec.message();
    }
    // Relabel the global ublk-control node
    selinux_android_restorecon("/dev/ublk-control", 0);
}

static std::optional<int> GetRamdiskSnapuserdFd() {
    const char* fd_str = getenv(kSnapuserdFirstStageFdVar);
    if (!fd_str) {
        return {};
    }

    int fd;
    if (!android::base::ParseInt(fd_str, &fd)) {
        LOG(FATAL) << "Could not parse fd in environment, " << kSnapuserdFirstStageFdVar << "="
                   << fd_str;
    }
    return {fd};
}

void RestoreconRamdiskSnapuserd(int fd) {
    if (fsetxattr(fd, XATTR_NAME_SELINUX, kSnapuserdLabel, strlen(kSnapuserdLabel) + 1, 0) < 0) {
        PLOG(FATAL) << "fsetxattr snapuserd failed";
    }
}

SnapuserdSelinuxHelper::SnapuserdSelinuxHelper(std::unique_ptr<SnapshotManager>&& sm, pid_t old_pid)
    : sm_(std::move(sm)), old_pid_(old_pid) {
    // Expected to handle dm-user, ublk char and block, dm-linear on top of
    // ublk block devices.
    sm_->SetUeventRegenCallback([this](const std::string& device) -> bool {
        if (android::base::StartsWith(device, "/dev/dm-user/")) {
            return block_dev_init_.InitDmUser(android::base::Basename(device));
        }
        if (android::base::StartsWith(device, "/dev/block/dm-")) {
            return block_dev_init_.InitDmDevice(device);
        }
        if (android::base::StartsWith(device, "/dev/block/ublkb")) {
            return block_dev_init_.InitDmDevice(device);
        }
        if (android::base::StartsWith(device, "/dev/ublk")) {
            return block_dev_init_.InitUblkMiscDevices(android::base::Basename(device));
        }
        return block_dev_init_.InitDevices({device});
    });
}

static void LockAllSystemPages() {
    bool ok = true;
    auto callback = [&](const android::procinfo::MapInfo& map) -> void {
        if (!ok || android::base::StartsWith(map.name, "/dev/") ||
            !android::base::StartsWith(map.name, "/")) {
            return;
        }
        auto start = reinterpret_cast<const void*>(map.start);
        uint64_t len = android::procinfo::MappedFileSize(map);
        if (!len) {
            return;
        }

        if (mlock(start, len) < 0) {
            PLOG(ERROR) << "\"" << map.name << "\": mlock(" << start << ", " << len
                        << ") failed: pgoff = " << map.pgoff;
            ok = false;
        }
    };

    if (!android::procinfo::ReadProcessMaps(getpid(), callback) || !ok) {
        LOG(FATAL) << "Could not process /proc/" << getpid() << "/maps file for init";
    }
}

void SnapuserdSelinuxHelper::StartTransition() {
    LOG(INFO) << "Starting SELinux transition of snapuserd";

    // The restorecon path reads from /system etc, so make sure any reads have
    // been cached before proceeding.
    auto handle = selinux_android_file_context_handle();
    if (!handle) {
        LOG(FATAL) << "Could not create SELinux file context handle";
    }
    selinux_android_set_sehandle(handle);

    // We cannot access /system after the transition, so make sure init is
    // pinned in memory.
    LockAllSystemPages();

    argv_.emplace_back("snapuserd");
    argv_.emplace_back("-no_socket");
    if (!sm_->PrepareSnapuserdArgsForSelinux(&argv_)) {
        LOG(FATAL) << "Could not perform selinux transition";
    }
    // Check if we are going to use ublk path and save it so
    // we can re-use decision than checking again.
    using_ublk_ = std::any_of(argv_.begin(), argv_.end(),
                              [](const std::string& arg) { return arg == "-ublk"; });
}

void SnapuserdSelinuxHelper::FinishTransition() {
    RelabelLink("/dev/block/by-name/super");
    RelabelDeviceMapper();

    selinux_android_restorecon("/dev/null", 0);
    selinux_android_restorecon("/dev/urandom", 0);
    selinux_android_restorecon("/dev/kmsg", 0);
    selinux_android_restorecon("/dev/dm-user", SELINUX_ANDROID_RESTORECON_RECURSE);
    if (using_ublk_) {
        RelabelUblkDevices();
    }
    RelaunchFirstStageSnapuserd();

    if (munlockall() < 0) {
        PLOG(ERROR) << "munlockall failed";
    }
}

/*
 * Before starting init second stage, we will wait
 * for snapuserd daemon to be up and running; bionic libc
 * may read /system/etc/selinux/plat_property_contexts file
 * before invoking main() function. This will happen if
 * init initializes property during second stage. Any access
 * to /system without snapuserd daemon will lead to a deadlock.
 *
 * Thus, we do a simple probe by reading system partition. This
 * read will eventually be serviced by daemon confirming that
 * daemon is up and running. Furthermore, we are still in the kernel
 * domain and sepolicy has not been enforced yet. Thus, access
 * to these device mapper block devices are ok even though
 * we may see audit logs.
 */
bool SnapuserdSelinuxHelper::TestSnapuserdIsReady() {
    // Wait for the daemon to be fully up. Daemon will write to path
    // /metadata/ota/daemon-alive-indicator only when all the threads
    // are ready and attached to dm-user.
    //
    // This check will fail for GRF devices with vendor on Android S.
    // snapuserd binary from Android S won't be able to communicate
    // and hence, we will fallback and issue I/O to verify
    // the presence of daemon.
    auto client = std::make_unique<SnapuserdClient>();
    if (!client->IsTransitionedDaemonReady()) {
        LOG(ERROR) << "IsTransitionedDaemonReady failed";
    }

    std::string dev = "/dev/block/mapper/system"s + fs_mgr_get_slot_suffix();
    android::base::unique_fd fd(open(dev.c_str(), O_RDONLY | O_DIRECT));
    if (fd < 0) {
        PLOG(ERROR) << "open " << dev << " failed";
        return false;
    }

    void* addr;
    ssize_t page_size = getpagesize();
    if (posix_memalign(&addr, page_size, page_size) < 0) {
        PLOG(ERROR) << "posix_memalign with page size " << page_size;
        return false;
    }

    std::unique_ptr<void, decltype(&::free)> buffer(addr, ::free);

    int iter = 0;
    while (iter < 10) {
        ssize_t n = TEMP_FAILURE_RETRY(pread(fd.get(), buffer.get(), page_size, 0));
        if (n < 0) {
            // Wait for sometime before retry
            std::this_thread::sleep_for(100ms);
        } else if (n == page_size) {
            return true;
        } else {
            LOG(ERROR) << "pread returned: " << n << " from: " << dev << " expected: " << page_size;
        }

        iter += 1;
    }

    return false;
}

static bool ReadMessageFromSocket(int sockfd, std::string* message) {
    message->clear();

    char buffer[4096];  // Adjust buffer size as needed

    ssize_t bytes_read = TEMP_FAILURE_RETRY(recv(sockfd, buffer, sizeof(buffer), 0));
    if (bytes_read < 0) {
        PLOG(ERROR) << "recv() failed";
        return false;
    } else if (bytes_read == 0) {
        LOG(INFO) << "recv() returned 0, peer closed connection";
        return false;
    }
    message->assign(buffer, bytes_read);
    return true;
}

void SnapuserdSelinuxHelper::ProcessSnapuserdUeventRequests(int request_fd) {
    std::string message;
    auto start_time = std::chrono::steady_clock::now();
    auto end_time = start_time + std::chrono::seconds(30);

    LOG(INFO) << "Processing UBLK device requests on fd: " << request_fd;
    // TODOUBLK: b/414812023
    // Consider LOG(FATAL) for early failure.
    while (std::chrono::steady_clock::now() < end_time) {
        if (!ReadMessageFromSocket(request_fd, &message)) {
            LOG(ERROR) << "Failed receiving message on request socketpair from fd: " << request_fd;
            break;
        }

        if (message.find("DONE") != std::string::npos) {
            LOG(INFO) << "Received DONE message from snapuserd for UBLK requests on fd: "
                      << request_fd;
            break;
        }

        if (!message.empty()) {
            LOG(INFO) << "Received UBLK device request: \"" << message
                      << "\" on fd: " << request_fd;
            auto timeout_ms = 500ms;
            if (android::base::StartsWith(message, "/dev/ublkc")) {
                block_dev_init_.InitUblkMiscDevices(android::base::Basename(message));
                android::fs_mgr::WaitForFile(message, timeout_ms);
            } else if (android::base::StartsWith(message, "/dev/block/ublk")) {
                block_dev_init_.InitDmDevice(message);
                android::fs_mgr::WaitForFile(message, timeout_ms);
            } else {
                LOG(WARNING) << "Received unknown UBLK device request: \"" << message
                             << "\" on fd: " << request_fd;
            }
        }
    }

    if (std::chrono::steady_clock::now() >= end_time && message.find("DONE") == std::string::npos) {
        LOG(ERROR) << "Timed out waiting for DONE message on UBLK request socketpair from fd: "
                   << request_fd;
    }
}

void SnapuserdSelinuxHelper::RelaunchFirstStageSnapuserd() {
    if (!sm_->DetachFirstStageSnapuserdForSelinux()) {
        LOG(FATAL) << "Could not perform selinux transition";
    }

    SignalFirstStageSnapuserd(old_pid_, SIGTERM);

    auto fd = GetRamdiskSnapuserdFd();
    if (!fd) {
        LOG(FATAL) << "Environment variable " << kSnapuserdFirstStageFdVar << " was not set!";
    }
    unsetenv(kSnapuserdFirstStageFdVar);

    RestoreconRamdiskSnapuserd(fd.value());
    int sockets[2] = {-1, -1};

    if (using_ublk_) {
        // Create a socket pair for snapuserd to request udev event assistance from init.
        // In early boot stages, ueventd might not be ready, so init helps create devices.
        // Snapuserd sends device paths it needs; "DONE" signals completion.

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
            PLOG(FATAL) << "socketpair failed";
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        if (using_ublk_) {
            close(sockets[0]);
            close(sockets[1]);
        }
        PLOG(FATAL) << "Fork to relaunch snapuserd failed";
    }
    if (pid > 0) {
        // We don't need the descriptor anymore, and it should be closed to
        // avoid leaking into subprocesses.
        close(fd.value());

        if (using_ublk_) close(sockets[1]);

        setenv(kSnapuserdFirstStagePidVar, std::to_string(pid).c_str(), 1);

        LOG(INFO) << "Relaunched snapuserd with pid: " << pid;

        // Since daemon is not started as a service, we have
        // to explicitly set the OOM score to default which is unkillable
        std::string oom_str = std::to_string(DEFAULT_OOM_SCORE_ADJUST);
        std::string oom_file = android::base::StringPrintf("/proc/%d/oom_score_adj", pid);
        if (!android::base::WriteStringToFile(oom_str, oom_file)) {
            PLOG(ERROR) << "couldn't write oom_score_adj to snapuserd daemon with pid: " << pid;
        }
        if (using_ublk_) {
            // When UBLK is enabled for snapshots, the newly launched snapuserd instance
            // requires assistance from init to create the necessary UBLK device nodes
            // (e.g., /dev/ublkc* for control, /dev/block/ublkb* for block devices).
            // This is because ueventd is not be fully operational/
            //
            // To handle this, a socket pair is used:
            // - snapuserd (child) writes requested device paths to its end of the socket.
            // - init (parent) reads these paths from its end (sockets[0]).
            // - init then uses BlockDevInitializer to create/initialize these device nodes
            //   and waits for them to appear.
            // This communication continues until snapuserd sends a "DONE" message,
            // indicating all its required UBLK devices have been requested.
            // The ProcessSnapuserdUeventRequests function encapsulates this interaction.
            ProcessSnapuserdUeventRequests(sockets[0]);
            close(sockets[0]);  // Served its purpose
            LOG(INFO) << "Finished processing uevent requests, socket closed.";
            // relabel newly created devices
            RelabelUblkDevices();
        }

        if (!TestSnapuserdIsReady()) {
            PLOG(FATAL) << "snapuserd daemon failed to launch";
        } else {
            LOG(INFO) << "snapuserd daemon is up and running";
        }
        if (using_ublk_) {
            // When using ublk for snapshots, the original first-stage snapuserd (old_pid_)
            // does not automatically terminate when its device mapper tables are switched
            // by the newly launched snapuserd instance. This behavior differs
            // from snapuserd instances that use dm-user. Therefore, an explicit SIGKILL
            // is necessary to ensure the old instance is terminated.
            SignalFirstStageSnapuserd(old_pid_, SIGKILL);
        }
        return;
    }

    // Make sure the descriptor is gone after we exec.
    if (fcntl(fd.value(), F_SETFD, FD_CLOEXEC) < 0) {
        PLOG(FATAL) << "fcntl FD_CLOEXEC failed for snapuserd fd";
    }
    if (using_ublk_) {
        close(sockets[0]);
        std::string fd_arg = android::base::StringPrintf("--fd_num=%d", sockets[1]);
        argv_.push_back(fd_arg);
    }
    std::vector<char*> argv;
    for (auto& arg : argv_) {
        argv.emplace_back(arg.data());
    }
    argv.emplace_back(nullptr);

    int rv = syscall(SYS_execveat, fd.value(), "", reinterpret_cast<char* const*>(argv.data()),
                     nullptr, AT_EMPTY_PATH);
    if (rv < 0) {
        PLOG(FATAL) << "Failed to execveat() snapuserd";
    }
}

std::unique_ptr<SnapuserdSelinuxHelper> SnapuserdSelinuxHelper::CreateIfNeeded() {
    if (IsRecoveryMode()) {
        return nullptr;
    }

    auto old_pid = GetSnapuserdFirstStagePid();
    if (!old_pid) {
        return nullptr;
    }

    auto sm = SnapshotManager::NewForFirstStageMount();
    if (!sm) {
        LOG(FATAL) << "Unable to create SnapshotManager";
    }
    return std::make_unique<SnapuserdSelinuxHelper>(std::move(sm), old_pid.value());
}

void SignalFirstStageSnapuserd(pid_t pid, int signal) {
    if (kill(pid, signal) < 0 && errno != ESRCH) {
        LOG(ERROR) << "Signal snapuserd pid failed: " << pid;
    } else {
        LOG(INFO) << "Sent signal " << signal << " to snapuserd process " << pid;
    }
}
void CleanupSnapuserdSocket() {
    auto socket_path = ANDROID_SOCKET_DIR "/"s + android::snapshot::kSnapuserdSocket;
    if (access(socket_path.c_str(), F_OK) != 0) {
        return;
    }

    // Tell the daemon to stop accepting connections and to gracefully exit
    // once all outstanding handlers have terminated.
    if (auto client = SnapuserdClient::Connect(android::snapshot::kSnapuserdSocket, 3s)) {
        client->DetachSnapuserd();
    }

    // Unlink the socket so we can create it again in second-stage.
    if (unlink(socket_path.c_str()) < 0) {
        PLOG(FATAL) << "unlink " << socket_path << " failed";
    }
}

void SaveRamdiskPathToSnapuserd() {
    int fd = open(kSnapuserdPath, O_PATH);
    if (fd < 0) {
        PLOG(FATAL) << "Unable to open snapuserd: " << kSnapuserdPath;
    }

    auto value = std::to_string(fd);
    if (setenv(kSnapuserdFirstStageFdVar, value.c_str(), 1) < 0) {
        PLOG(FATAL) << "setenv failed: " << kSnapuserdFirstStageFdVar << "=" << value;
    }
}

bool IsFirstStageSnapuserdRunning() {
    return GetSnapuserdFirstStagePid().has_value();
}

}  // namespace init
}  // namespace android
