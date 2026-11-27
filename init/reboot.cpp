/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "init"

#include "reboot.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/ext4.h>
#include <linux/f2fs.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <mntent.h>
#include <semaphore.h>
#include <stdlib.h>
#include <sys/cdefs.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <chrono>
#include <map>
#include <memory>
#include <set>
#include <thread>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/process.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <cutils/klog.h>
#include <fs_mgr.h>
#include <libsnapshot/snapshot.h>
#include <logwrap/logwrap.h>
#include <private/android_filesystem_config.h>
#include <procinfo/process.h>
#include <selinux/selinux.h>

#include <cutils/properties.h>

#include "action.h"
#include "action_manager.h"
#include "builtin_arguments.h"
#include "init.h"
#include "mount_namespace.h"
#include "property_service.h"
#include "reboot_utils.h"
#include "service.h"
#include "service_list.h"
#include "sigchld_handler.h"
#include "util.h"

using namespace std::literals;

using android::base::boot_clock;
using android::base::GetBoolProperty;
using android::base::GetUintProperty;
using android::base::SetProperty;
using android::base::Split;
using android::base::Timer;
using android::base::unique_fd;
using android::base::WaitForProperty;
using android::base::WriteStringToFile;

namespace android {
namespace init {

static bool shutting_down = false;

[[clang::no_destroy]] static const std::set<std::string> kDebuggingServices{"tombstoned", "logd",
                                                                            "adbd", "console"};

static void PersistRebootReason(const char* reason, bool write_to_property) {
    if (write_to_property) {
        SetProperty(LAST_REBOOT_REASON_PROPERTY, reason);
    }
    auto fd = unique_fd(TEMP_FAILURE_RETRY(open(
            LAST_REBOOT_REASON_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_BINARY, 0666)));
    if (!fd.ok()) {
        PLOG(ERROR) << "Could not open '" << LAST_REBOOT_REASON_FILE
                    << "' to persist reboot reason";
        return;
    }
    WriteStringToFd(reason, fd);
    fsync(fd.get());
}

// represents umount status during reboot / shutdown.
enum UmountStat {
    /* umount succeeded. */
    UMOUNT_STAT_SUCCESS = 0,
    /* umount was not run. */
    UMOUNT_STAT_SKIPPED = 1,
    /* umount failed with timeout. */
    UMOUNT_STAT_TIMEOUT = 2,
    /* could not run due to error */
    UMOUNT_STAT_ERROR = 3,
    /* umount status before reboot is not found / available. */
    UMOUNT_STAT_NOT_AVAILABLE = 4,
};

// Utility for struct mntent
class MountEntry {
  public:
    explicit MountEntry(const mntent& entry)
        : mnt_fsname_(entry.mnt_fsname),
          mnt_dir_(entry.mnt_dir),
          mnt_type_(entry.mnt_type),
          mnt_opts_(entry.mnt_opts) {}

    bool Umount(bool force) {
        LOG(INFO) << "Unmounting " << mnt_fsname_ << ":" << mnt_dir_ << " opts " << mnt_opts_;
        int r = umount2(mnt_dir_.c_str(), force ? MNT_FORCE : 0);
        if (r == 0) {
            LOG(INFO) << "Umounted " << mnt_fsname_ << ":" << mnt_dir_ << " opts " << mnt_opts_;
            return true;
        } else {
            PLOG(WARNING) << "Cannot umount " << mnt_fsname_ << ":" << mnt_dir_ << " opts "
                          << mnt_opts_;
            return false;
        }
    }

    static bool IsBlockDevice(const struct mntent& mntent) {
        return android::base::StartsWith(mntent.mnt_fsname, "/dev/block");
    }

    static bool IsEmulatedDevice(const struct mntent& mntent) {
        return android::base::StartsWith(mntent.mnt_fsname, "/data/");
    }

  private:
    bool IsF2Fs() const { return mnt_type_ == "f2fs"; }

    bool IsExt4() const { return mnt_type_ == "ext4"; }

    std::string mnt_fsname_;
    std::string mnt_dir_;
    std::string mnt_type_;
    std::string mnt_opts_;
};

// Turn off backlight while we are performing power down cleanup activities.
static void TurnOffBacklight() {
    Service* service = ServiceList::GetInstance().FindService("blank_screen");
    if (service == nullptr) {
        LOG(WARNING) << "cannot find blank_screen in TurnOffBacklight";
        return;
    }
    if (auto result = service->Start(); !result.ok()) {
        LOG(WARNING) << "Could not start blank_screen service: " << result.error();
    }
}

static Result<void> CallVdc(const std::string& system, const std::string& cmd) {
    LOG(INFO) << "Calling /system/bin/vdc " << system << " " << cmd;
    const char* vdc_argv[] = {"/system/bin/vdc", system.c_str(), cmd.c_str()};
    int status;
    if (logwrap_fork_execvp(arraysize(vdc_argv), vdc_argv, &status, false, LOG_KLOG, true,
                            nullptr) != 0) {
        return ErrnoError() << "Failed to call '/system/bin/vdc " << system << " " << cmd << "'";
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return {};
    }
    return Error() << "'/system/bin/vdc " << system << " " << cmd << "' failed : " << status;
}

// This function should be called just before kernel reboot/shutdown. At this point, the logd
// is killed, regular logger does not work. Use KLOG to make sure the log is available in
// pstore console file, preventing log data from losing.
static void LogShutdownTime(UmountStat stat, const Timer& t) {
    KLOG_WARNING(LOG_TAG, "powerctl_shutdown_time_ms:%lld:%d\n", t.duration().count(), stat);
}

// Gets the filesystem type of the /data partition.
// Returns the filesystem type as a string (e.g., "ext4", "f2fs") or an empty string if not found
// or if an error occurs.
static std::string GetDataFsType() {
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "re"), endmntent);
    if (fp == nullptr) {
        PLOG(ERROR) << "Failed to open /proc/mounts";
        return "";
    }
    mntent* mentry;
    while ((mentry = getmntent(fp.get())) != nullptr) {
        if (mentry->mnt_dir == "/data"s) {
            return mentry->mnt_type;
        }
    }
    return "";
}

// Find all read+write block devices and emulated devices in /proc/mounts and add them to
// the correpsponding list.
static bool FindPartitionsToUmount(std::vector<MountEntry>* block_dev_partitions,
                                   std::vector<MountEntry>* emulated_partitions) {
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "re"), endmntent);
    if (fp == nullptr) {
        PLOG(ERROR) << "Failed to open /proc/mounts";
        return false;
    }
    mntent* mentry;
    while ((mentry = getmntent(fp.get())) != nullptr) {
        if (MountEntry::IsBlockDevice(*mentry) && hasmntopt(mentry, "rw")) {
            std::string mount_dir(mentry->mnt_dir);
            // These are R/O partitions changed to R/W after adb remount.
            // Do not umount them as shutdown critical services may rely on them.
            if (mount_dir != "/" && mount_dir != "/system" && mount_dir != "/vendor" &&
                mount_dir != "/oem") {
                block_dev_partitions->emplace(block_dev_partitions->begin(), *mentry);
            }
        } else if (MountEntry::IsEmulatedDevice(*mentry)) {
            emulated_partitions->emplace(emulated_partitions->begin(), *mentry);
        }
    }
    return true;
}

static void DumpPartitions() {
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "re"), endmntent);
    if (fp == nullptr) {
        PLOG(ERROR) << "Failed to open /proc/mounts";
        return;
    }

    mntent* mentry;
    while ((mentry = getmntent(fp.get())) != nullptr) {
        LOG(INFO) << "mount entry " << mentry->mnt_fsname << ":" << mentry->mnt_dir << " opts "
                  << mentry->mnt_opts << " type " << mentry->mnt_type;
    }
}

static void DumpUmountDebuggingInfo() {
    DumpPartitions();
    // dump current CPU stack traces and uninterruptible tasks
    WriteStringToFile("l", PROC_SYSRQ);
    WriteStringToFile("w", PROC_SYSRQ);
}

/** Attempts to unmount partitions
 *
 * @param force If true, forces the unmount operation, even if the filesystem is busy.
 * @return UMOUNT_STAT_SUCCESS: if all partitions were unmounted successfully, or if no partitions
 *         were found to unmount after umounting.
 *         UMOUNT_STAT_NOT_AVAILABLE: failed to read umount stats from /proc/mounts.
 *         UMOUNT_STAT_ERROR: failed to umount all partitions.
 */
static UmountStat TryUmountPartitions(bool force) {
    std::vector<MountEntry> block_devices;
    std::vector<MountEntry> emulated_devices;

    // Find partitions to umount and store the mount entries in block_devices and emulated_devices
    if (!FindPartitionsToUmount(&block_devices, &emulated_devices)) {
        return UMOUNT_STAT_NOT_AVAILABLE;
    }

    // Success if there are no partitions need to umount
    if (block_devices.empty()) {
        return UMOUNT_STAT_SUCCESS;
    }

    bool unmount_success = true;
    // Umount emulated device since /data partition needs all pending writes to be completed and
    // all emulated partitions unmounted.
    if (emulated_devices.size() > 0) {
        for (auto& entry : emulated_devices) {
            if (!entry.Umount(false)) unmount_success = false;
        }
        if (unmount_success) {
            sync();
        }
    }

    for (auto& entry : block_devices) {
        if (!entry.Umount(force)) unmount_success = false;
    }

    if (unmount_success) {
        return UMOUNT_STAT_SUCCESS;
    }

    // Some identical mount points may be umounted twice during unmounting, which can cause an
    // INVALID_ARGUMENT error at second umount. However, they were actually unmounted
    // successfully. Update the list of partitions that need to be umounted after the first
    // attempt. If there are no partitions left to umount, we should consider the umount
    // successful.
    block_devices.clear();
    emulated_devices.clear();
    if (!FindPartitionsToUmount(&block_devices, &emulated_devices)) {
        return UMOUNT_STAT_NOT_AVAILABLE;
    }

    if (block_devices.empty() && emulated_devices.empty()) {
        return UMOUNT_STAT_SUCCESS;
    }

    return UMOUNT_STAT_ERROR;
}

static void DumpRemainingProcesses() {
    LOG(INFO) << "Remaining userspace processes except init: ";
    android::procinfo::ProcessInfo info;
    std::string error;
    for (const auto& pid : android::base::AllPids{}) {
        if (!android::procinfo::GetProcessInfo(pid, &info, &error)) {
            LOG(WARNING) << "Cannot get info for pid " << pid << ": " << error;
            continue;
        }
        bool init_or_kthread = (info.ppid == 0) || (info.ppid == 2);
        if (init_or_kthread) {
            continue;
        }
        LOG(INFO) << std::format("pid: {} name: ({}) ppid: {} pgrp: {} state: {}", info.pid,
                                 info.name, info.ppid, info.pgrp, static_cast<char>(info.state));
    }
}

static void KillAllProcesses(bool force) {
    // To know what are die-hard processes.
    DumpRemainingProcesses();
    // SIGKILL on force == true. SIGTERM if not.
    WriteStringToFile(force ? "i" : "e", PROC_SYSRQ);
}

static UmountStat UmountPartitions(std::chrono::milliseconds timeout, bool ota_update_in_progress) {
    const bool immediate = timeout == 0ms;

    // Terminate the services before unmounting partitions.
    for (const auto& s : ServiceList::GetInstance()) {
        if (s->IsShutdownCritical()) {
            LOG(INFO) << "Shutdown service: " << s->name();

            // Terminate to prevent service restarting
            s->Terminate();

            // If we have no time left, kill as fast as possible by sending SIGKILL.
            if (immediate) {
                s->Timeout();
            }
        }
    }
    // Below is to ensure that all remaining processes (except init) are SIGKILL'ed or SIGTERM'ed.
    // This is because some children of the services above might have created new process groups.
    // Note that, each service by default is a process group leader, and we send a signal to the
    // process group when killing the service. So, if some children created their own process group,
    // they don't get killed. Below is to kill even such ones.
    //
    // However, if OTA update is in progress we NEVER send SIGKILL because snapuserd will be serving
    // I/Os and therefore killing it will ruin the update. snapuserd ignores SIGTERM.
    KillAllProcesses(immediate && !ota_update_in_progress);

    ReapAnyOutstandingChildren();

    Timer t;
    /* If the current waiting is not good enough, give up and leave it to fsck after reboot to
     * fix it.
     */
    while (true) {
        // force umount operation if timeout is not set
        UmountStat stat = TryUmountPartitions(immediate);
        if (stat == UMOUNT_STAT_SUCCESS) {
            return UMOUNT_STAT_SUCCESS;
        }

        if (stat == UMOUNT_STAT_NOT_AVAILABLE || immediate) {
            return UMOUNT_STAT_ERROR;
        }

        if ((timeout < t.duration())) {  // try umount at least once
            return UMOUNT_STAT_TIMEOUT;
        }
        std::this_thread::sleep_for(100ms);
    }
}

// Reboot/shutdown monitor thread
static void RebootMonitorThread(unsigned int cmd, const Timer& shutdown_timer) {
    // We want quite a long timeout here since the "sync" in the calling
    // thread can be quite slow.
    constexpr unsigned int shutdown_watchdog_timeout_default = 300;
    constexpr unsigned int shutdown_watchdog_timeout_min = 60;
    auto shutdown_watchdog_timeout = android::base::GetUintProperty(
            "ro.build.shutdown.watchdog.timeout", shutdown_watchdog_timeout_default);

    if (shutdown_watchdog_timeout < shutdown_watchdog_timeout_min) {
        LOG(WARNING) << "ro.build.shutdown.watchdog.timeout = " << shutdown_watchdog_timeout
                     << " is too small; bumping up to " << shutdown_watchdog_timeout_min;
        shutdown_watchdog_timeout = shutdown_watchdog_timeout_min;
    }

    LOG(INFO) << "RebootMonitorThread started for " << shutdown_watchdog_timeout << "s";
    std::chrono::duration timeout = std::chrono::seconds(shutdown_watchdog_timeout);

    constexpr unsigned int num_steps = 10;
    std::chrono::duration sleep_amount =
            std::chrono::duration_cast<std::chrono::milliseconds>(timeout) / num_steps;

    for (unsigned int i = 0; i < num_steps - 1; i++) {
        std::this_thread::sleep_for(sleep_amount);

        // Print a message periodically as we're waiting so there is some
        // warning in the logs if we're getting close to triggering. Use this
        // as a chance to try to preserve data by using the "sync" and
        // "force remount readonly" sysrq requests, both of which kick off
        // background work and are non-blocking. We'll do "sync" most of the
        // time and only do the more intrusive remount right before the last
        // delay (to give it time to take effect).
        LOG(WARNING) << "Reboot monitor still running, forced reboot in "
                     << ((num_steps - i - 1) * sleep_amount.count()) << " ms";
        if (i == num_steps - 2) {
            WriteStringToFile("u", PROC_SYSRQ);
        } else {
            WriteStringToFile("s", PROC_SYSRQ);
        }
    }
    std::this_thread::sleep_for(sleep_amount);

    LOG(ERROR) << "Reboot thread timed out";

    if (android::base::GetBoolProperty("ro.debuggable", false) == true) {
        if (false) {
            // SEPolicy will block debuggerd from running and this is intentional.
            // But these lines are left to be enabled during debugging.
            LOG(INFO) << "Try to dump init process call trace:";
            const char* vdc_argv[] = {"/system/bin/debuggerd", "-b", "1"};
            int status;
            logwrap_fork_execvp(arraysize(vdc_argv), vdc_argv, &status, false, LOG_KLOG, true,
                                nullptr);
        }
        LOG(INFO) << "Show stack for all active CPU:";
        WriteStringToFile("l", PROC_SYSRQ);

        LOG(INFO) << "Show tasks that are in disk sleep(uninterruptable sleep), which are "
                     "like "
                     "blocked in mutex or hardware register access:";
        WriteStringToFile("w", PROC_SYSRQ);
    }

    if (cmd == ANDROID_RB_POWEROFF || cmd == ANDROID_RB_THERMOFF) {
        LogShutdownTime(UMOUNT_STAT_TIMEOUT, shutdown_timer);
        RebootSystem(cmd, "");
    }

    LOG(ERROR) << "Trigger crash at last!";
    WriteStringToFile("c", PROC_SYSRQ);
}

// Create reboot/shutdown monitor thread
static void StartRebootMonitorThread(unsigned int cmd, const Timer& shutdown_timer) {
    [[clang::no_destroy]] static std::atomic_flag started{};

    // Only allow the monitor to be started once.
    if (started.test_and_set(std::memory_order_acquire)) {
        LOG(INFO) << "RebootMonitorThread already started";
        return;
    }

    LOG(INFO) << "Starting RebootMonitorThread";
    std::thread reboot_monitor_thread(&RebootMonitorThread, cmd, shutdown_timer);
    reboot_monitor_thread.detach();
}

static bool UmountDynamicPartitions(const std::vector<std::string>& dynamic_partitions) {
    bool ret = true;
    for (auto device : dynamic_partitions) {
        // Cannot unmount /system
        if (device == "/system") {
            continue;
        }
        int r = umount2(device.c_str(), MNT_FORCE);
        if (r == 0) {
            LOG(INFO) << "Umounted success: " << device;
        } else {
            PLOG(WARNING) << "Cannot umount: " << device;
            ret = false;
        }
    }
    return ret;
}

/* Try umounting all emulated file systems R/W block device cfile systems.
 * This will just try umount and give it up if it fails.
 * For fs like ext4, this is ok as file system will be marked as unclean shutdown
 * and necessary check can be done at the next reboot.
 * For safer shutdown, caller needs to make sure that
 * all processes / emulated partition for the target fs are all cleaned-up.
 *
 * return true when umount was successful. false when timed out.
 */
static UmountStat TryUmount(unsigned int cmd, std::chrono::milliseconds timeout) {
    Timer t;
    std::vector<MountEntry> block_devices;
    std::vector<MountEntry> emulated_devices;
    std::vector<std::string> dynamic_partitions;

    bool ota_update_in_progress = false;
    if (!IsMicrodroid()) {
        auto sm = snapshot::SnapshotManager::New();
        if (sm->IsUserspaceSnapshotUpdateInProgress(dynamic_partitions)) {
            LOG(INFO) << "OTA update in progress. Pause snapshot merge";
            if (!sm->PauseSnapshotMerge()) {
                LOG(ERROR) << "Snapshot-merge pause failed";
            }
            ota_update_in_progress = true;
        }
    }
    UmountStat stat = UmountPartitions(timeout - t.duration(), ota_update_in_progress);
    if (stat != UMOUNT_STAT_SUCCESS) {
        // Do not delete: Critical log for reboot_fs_integrity_test.
        KLOG_INFO(LOG_TAG, "umount timeout, last resort, kill all and try");
        bool dumpUmountDebugInfo = property_get_bool("persist.sys.dumpUmountDebugInfo",false);
        if (dumpUmountDebugInfo) {
            if (DUMP_ON_UMOUNT_FAILURE) DumpUmountDebuggingInfo();
        }
        // Since umount timedout, we will try to kill all processes
        // and do one more attempt to umount the partitions.
        //
        // However, if OTA update is in progress, we don't want
        // to kill the snapuserd daemon as the daemon will
        // be serving I/O requests. Killing the daemon will
        // end up with I/O failures. If the update is in progress,
        // we will just return the umount failure status immediately.
        // This is ok, given the fact that killing the processes
        // and doing an umount is just a last effort. We are
        // still not doing fsck when all processes are killed.
        //
        if (ota_update_in_progress) {
            bool umount_dynamic_partitions = UmountDynamicPartitions(dynamic_partitions);
            LOG(INFO) << "Sending SIGTERM to all process";
            // Send SIGTERM to all processes except init
            KillAllProcesses(/* force */ false);
            // Wait for processes to terminate
            std::this_thread::sleep_for(1s);
            // Try one more attempt to umount other partitions which failed
            // earlier
            if (!umount_dynamic_partitions) {
                UmountDynamicPartitions(dynamic_partitions);
            }
            return stat;
        }
        KillAllProcesses(/* force */ true);
        // even if it succeeds, still it is timeout and do not run fsck with all processes killed
        UmountStat st = UmountPartitions(0ms, ota_update_in_progress);
        if (dumpUmountDebugInfo) {
            if ((st != UMOUNT_STAT_SUCCESS) && DUMP_ON_UMOUNT_FAILURE)
                 DumpUmountDebuggingInfo();
        }
    }

    return stat;
}

// zram is able to use backing device on top of a loopback device.
// In order to unmount /data successfully, we have to kill the loopback device first
#define ZRAM_DEVICE "/dev/block/zram0"
#define ZRAM_RESET "/sys/block/zram0/reset"
#define ZRAM_BACK_DEV "/sys/block/zram0/backing_dev"
#define ZRAM_INITSTATE "/sys/block/zram0/initstate"
static Result<void> KillZramBackingDevice() {
    std::string zram_initstate;
    if (!android::base::ReadFileToString(ZRAM_INITSTATE, &zram_initstate)) {
        return ErrnoError() << "Failed to read " << ZRAM_INITSTATE;
    }

    zram_initstate.erase(zram_initstate.length() - 1);
    if (zram_initstate == "0") {
        LOG(INFO) << "Zram has not been swapped on";
        return {};
    }

    // shutdown zram handle even if it is mis-configured without a backing device.
    Timer swap_timer;
    LOG(INFO) << "swapoff() start...";
    if (swapoff(ZRAM_DEVICE) == -1) {
        if (errno == EINVAL) {
            LOG(INFO) << "No active swap on " << ZRAM_DEVICE << "; skipping swapoff.";
        } else if (errno == ENOENT) {
            LOG(INFO) << ZRAM_DEVICE << " does not exist; skipping swapoff.";
        } else {
            return ErrnoError() << "zram_backing_dev: swapoff(" << ZRAM_DEVICE << ") failed";
        }
    } else {
        LOG(INFO) << "swapoff() took " << swap_timer;
    }

    if (!WriteStringToFile("1", ZRAM_RESET)) {
        return Error() << "zram_backing_dev: reset (" << ZRAM_RESET << ")"
                       << " failed";
    }

    if (access(ZRAM_BACK_DEV, F_OK) != 0 && errno == ENOENT) {
        LOG(INFO) << "No zram backing device configured";
        return {};
    }
    std::string backing_dev;
    if (!android::base::ReadFileToString(ZRAM_BACK_DEV, &backing_dev)) {
        return ErrnoError() << "Failed to read " << ZRAM_BACK_DEV;
    }

    backing_dev = android::base::Trim(backing_dev);

    if (android::base::StartsWith(backing_dev, "none")) {
        LOG(INFO) << "No zram backing device configured";
        return {};
    }

    if (!android::base::ReadFileToString(ZRAM_BACK_DEV, &backing_dev)) {
        return ErrnoError() << "Failed to read " << ZRAM_BACK_DEV;
    }

    backing_dev = android::base::Trim(backing_dev);

    if (!android::base::StartsWith(backing_dev, "/dev/block/loop")) {
        LOG(INFO) << backing_dev << " is not a loop device. Exiting early";
        return {};
    }

    // clear loopback device
    unique_fd loop(TEMP_FAILURE_RETRY(open(backing_dev.c_str(), O_RDWR | O_CLOEXEC)));
    if (loop.get() < 0) {
        return ErrnoError() << "zram_backing_dev: open(" << backing_dev << ")" << " failed";
    }

    if (ioctl(loop.get(), LOOP_CLR_FD, 0) < 0) {
        return ErrnoError() << "zram_backing_dev: loop_clear (" << backing_dev << ")" << " failed";
    }
    LOG(INFO) << "zram_backing_dev: `" << backing_dev << "` is cleared successfully.";
    return {};
}

// Stops given services, and returns pids to be waited on.
// If terminate is true, then SIGTERM is sent to services, otherwise SIGKILL is sent.
// Note that services are stopped in order given by |ServiceList::services_in_shutdown_order|
// function.
static std::vector<pid_t> StopServices(const std::set<std::string>& services, bool terminate) {
    LOG(INFO) << "Stopping " << services.size() << " services by sending "
              << (terminate ? "SIGTERM" : "SIGKILL");
    std::vector<pid_t> pids;
    pids.reserve(services.size());
    for (const auto& s : ServiceList::GetInstance().services_in_shutdown_order()) {
        if (services.count(s->name()) == 0) {
            continue;
        }
        if (s->pid() > 0) {
            pids.push_back(s->pid());
        }
        if (terminate) {
            s->Terminate();
        } else {
            s->Stop();
        }
    }
    return pids;
}

// Retrieves all processes whose process group is not lead by any service which init tracks. In
// other words, these are processes which can't get killed by stopping a service.
static std::vector<android::procinfo::ProcessInfo> GetAllUntrackedProcesses() {
    std::map<pid_t, android::procinfo::ProcessInfo> untracked;
    std::string error;
    pid_t init_pgid = getpgid(0);  // my pgid
    pid_t adbd_pid = -1;           // not found
    for (const auto& pid : android::base::AllPids{}) {
        android::procinfo::ProcessInfo info;
        if (!android::procinfo::GetProcessInfo(pid, &info, &error)) {
            LOG(WARNING) << "Cannot get info for pid " << pid << ": " << error;
            continue;
        }

        // AllPids is not guaranteed to return PIDs in sorted order. Record the pid of adbd in this
        // loop, and find its descendants in another loop below.
        if (info.name == "adbd" && info.ppid == 1) {
            adbd_pid = info.pid;
        }

        bool init_or_kthread = (info.ppid == 0) || (info.ppid == 2);
        if (init_or_kthread) {
            continue;
        }
        // This is mainly to filter out snapuserd which is used for OTA. We shouldn't kill it during
        // reboot until the very end as it may be having I/Os. This condition in theory capture more
        // processes than just snapuserd, and it's fine; we don't have to kill them early. They will
        // eventually be killed via sysrq.
        bool init_subprocess = (info.ppid == 1) && (info.pgrp == init_pgid) && (info.uid == 0);
        if (init_subprocess) {
            continue;
        }

        bool tracked = ServiceList::GetInstance().FindService(info.pgrp, &Service::pid) != nullptr;
        if (!tracked) {
            untracked.insert({info.pid, std::move(info)});
        }
    }
    // If there's adb commands running, don't kill them early, especially before adbd is off.
    // Otherwise, the host-side will notice the termination of the command, instead of adb
    // disconnection.  Some host-side tools (ex: `adb reboot`) expect and
    // handle disconnection gracefully, but assert on the termination of commands.
    auto check_if_descendant_of_adbd = [&](const android::procinfo::ProcessInfo& info) {
        const android::procinfo::ProcessInfo* cur = &info;
        while (cur->ppid != 1) {
            if (cur->ppid == adbd_pid) return true;
            if (auto parent = untracked.find(cur->ppid); parent != untracked.end()) {
                cur = &(parent->second);
                continue;
            } else {
                return false;
            }
        }
        return false;
    };
    std::vector<pid_t> adbd_procs;
    for (const auto& pair : untracked) {
        if (check_if_descendant_of_adbd(pair.second)) {
            adbd_procs.push_back(pair.first);
        }
    }
    std::vector<android::procinfo::ProcessInfo> ret;
    for (auto it = untracked.begin(); it != untracked.end();) {
        auto nh = untracked.extract(it++);
        if (std::find(adbd_procs.begin(), adbd_procs.end(), nh.key()) == adbd_procs.end()) {
            ret.push_back(std::move(nh.mapped()));
        }
    }
    return ret;
}

static std::set<pid_t> StopUntrackedProcesses(bool terminate) {
    std::set<pid_t> groups_to_stop;
    for (auto info : GetAllUntrackedProcesses()) {
        groups_to_stop.insert(info.pgrp);
    }

    int signum = terminate ? SIGTERM : SIGKILL;
    std::string signame = SignalName(signum);
    for (pid_t pgid : groups_to_stop) {
        LOG(INFO) << "Stopping untracked process group " << pgid << " by sending " << signame;
        if (killpg(pgid, signum) == -1) {
            LOG(ERROR) << "Failed to send " << signame << " to process group " << pgid << ": "
                       << strerror(errno);
        }
    }
    return groups_to_stop;
}

// Wait for the given pids to be reaped until |timeout| expires, logs all pids that failed to stop
// after provided timeout. Returns number of violators
static int WaitAndLogViolations(const std::vector<pid_t>& pids, std::chrono::milliseconds timeout) {
    if (timeout > 0ms) {
        WaitToBeReaped(Service::GetSigchldFd(), pids, timeout);
    } else {
        // Even if we don't to wait for services to stop, we still optimistically reap zombies.
        ReapAnyOutstandingChildren();
    }

    int still_running = 0;
    // a pid can be of a service or an untracked process
    for (const auto& s : ServiceList::GetInstance()) {
        if (s->IsRunning() && std::find(pids.begin(), pids.end(), s->pid()) != pids.end()) {
            LOG(ERROR) << "[service-misbehaving] : service '" << s->name() << "' is still running "
                       << timeout.count() << "ms after stopped";
            still_running++;
        }
    }
    for (auto info : GetAllUntrackedProcesses()) {
        if (std::find(pids.begin(), pids.end(), info.pid) != pids.end()) {
            LOG(INFO)
                    << std::format(
                               "Untracked process: pid: {} name: ({}) ppid: {} pgrp: {} state: {}",
                               info.pid, info.name, info.ppid, info.pgrp,
                               static_cast<char>(info.state))
                    << " is still running " << timeout.count() << "ms after stopped";
            still_running++;
        }
    }
    return still_running;
}

// Test-only function:
// Like StopServices, but also waits for the services to fully stop, and also logs all the services
// that failed to stop after the provided timeout.  Returns number of violators.
int StopServicesAndLogViolations(const std::set<std::string>& services,
                                 std::chrono::milliseconds timeout, bool terminate) {
    auto pids = StopServices(services, terminate);
    return WaitAndLogViolations(pids, timeout);
}

static Result<void> UnmountAllApexes() {
    // don't need to unmount because apexd doesn't use /data in Microdroid
    if (IsMicrodroid()) {
        return {};
    }

    const char* args[] = {"/system/bin/apexd", "--unmount-all"};
    int status;
    if (logwrap_fork_execvp(arraysize(args), args, &status, false, LOG_KLOG, true, nullptr) != 0) {
        return ErrnoError() << "Failed to call '/system/bin/apexd --unmount-all'";
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return {};
    }
    return Error() << "'/system/bin/apexd --unmount-all' failed : " << status;
}

//* Reboot / shutdown the system.
// cmd ANDROID_RB_* as defined in android_reboot.h
// reason Reason string like "reboot", "shutdown,userrequested"
// reboot_target Reboot target string like "bootloader". Otherwise, it should be an empty string.
//
static void DoReboot(unsigned int cmd, const std::string& reason,
                     const std::string& reboot_target) {
    Timer t;
    LOG(INFO) << "Reboot start, reason: " << reason << ", reboot_target: " << reboot_target;

    bool is_thermal_shutdown = cmd == ANDROID_RB_THERMOFF;

    auto clean_shutdown_timeout = 0ms;
    if (!SHUTDOWN_ZERO_TIMEOUT) {
        constexpr unsigned int clean_shutdown_timeout_default = 6;
        constexpr unsigned int max_clean_thermal_shutdown_timeout = 3;
        constexpr unsigned int max_clean_shutdown_timeout = 10;
        auto shutdown_timeout_final = android::base::GetUintProperty(
                "ro.build.shutdown_timeout", clean_shutdown_timeout_default);
        if (is_thermal_shutdown && shutdown_timeout_final > max_clean_thermal_shutdown_timeout) {
            shutdown_timeout_final = max_clean_thermal_shutdown_timeout;
        } else if (shutdown_timeout_final > max_clean_shutdown_timeout) {
            LOG(WARNING) << "Shorten clean shutdown timeout from " << shutdown_timeout_final
                         << " s to " << max_clean_shutdown_timeout << " s";
            shutdown_timeout_final = max_clean_shutdown_timeout;
        }
        clean_shutdown_timeout = std::chrono::seconds(shutdown_timeout_final);
    }
    LOG(INFO) << "Clean shutdown timeout: " << clean_shutdown_timeout.count() << " ms";

    StartRebootMonitorThread(cmd, t);

    // Ensure last reboot reason is reduced to canonical
    // alias reported in bootloader or system boot reason.
    size_t skip = 0;
    std::vector<std::string> reasons = Split(reason, ",");
    if (reasons.size() >= 2 && reasons[0] == "reboot" &&
        (reasons[1] == "recovery" || reasons[1] == "bootloader" || reasons[1] == "cold" ||
         reasons[1] == "hard" || reasons[1] == "warm")) {
        skip = strlen("reboot,");
    }
    PersistRebootReason(reason.c_str() + skip, true);

    // If /data isn't mounted then we can skip the extra reboot steps below, since we don't need to
    // worry about unmounting it.
    if (GetDataFsType().empty()) {
        sync();
        LogShutdownTime(UMOUNT_STAT_SKIPPED, t);
        RebootSystem(cmd, reboot_target, reason);
        abort();
    }

    bool do_shutdown_animation = GetBoolProperty("ro.init.shutdown_animation", false);
    // watchdogd is a vendor specific component but should be alive to complete shutdown safely.
    const std::set<std::string> to_starts{"watchdogd"};
    std::set<std::string> stop_first;
    for (const auto& s : ServiceList::GetInstance()) {
        if (kDebuggingServices.count(s->name())) {
            // keep debugging tools until non critical ones are all gone.
            s->SetShutdownCritical();
        } else if (to_starts.count(s->name())) {
            if (auto result = s->Start(); !result.ok()) {
                LOG(ERROR) << "Could not start shutdown 'to_start' service '" << s->name()
                           << "': " << result.error();
            }
            s->SetShutdownCritical();
        } else if (do_shutdown_animation && s->classnames().count("animation") > 0) {
            // Need these for shutdown animations.
        } else if (s->IsShutdownCritical()) {
            // Start shutdown critical service if not started.
            if (auto result = s->Start(); !result.ok()) {
                LOG(ERROR) << "Could not start shutdown critical service '" << s->name()
                           << "': " << result.error();
            }
        } else {
            stop_first.insert(s->name());
        }
    }

    // remaining operations may take a substantial duration
    if (!do_shutdown_animation && (cmd == ANDROID_RB_POWEROFF || is_thermal_shutdown)) {
        TurnOffBacklight();
    }

    Service* boot_anim = ServiceList::GetInstance().FindService("bootanim");
    Service* surface_flinger = ServiceList::GetInstance().FindService("surfaceflinger");
    if (boot_anim != nullptr && surface_flinger != nullptr && surface_flinger->IsRunning()) {
        if (do_shutdown_animation) {
            SetProperty("service.bootanim.exit", "0");
            SetProperty("service.bootanim.progress", "0");
            // Could be in the middle of animation. Stop and start so that it can pick
            // up the right mode.
            boot_anim->Stop();
        }

        for (const auto& service : ServiceList::GetInstance()) {
            if (service->classnames().count("animation") == 0) {
                continue;
            }

            // start all animation classes if stopped.
            if (do_shutdown_animation) {
                service->Start();
            }
            service->SetShutdownCritical();  // will not check animation class separately
        }

        if (do_shutdown_animation) {
            boot_anim->Start();
            surface_flinger->SetShutdownCritical();
            boot_anim->SetShutdownCritical();
        }
    }

    // optional shutdown step
    // 1. terminate all services except shutdown critical ones. wait for delay to finish
    if (clean_shutdown_timeout > 0ms) {
        auto pids = StopServices(stop_first, true /* SIGTERM */);
        auto untracked_pids = StopUntrackedProcesses(true /* SIGTERM */);
        pids.insert(pids.end(), untracked_pids.begin(), untracked_pids.end());
        WaitAndLogViolations(pids, clean_shutdown_timeout / 2);
    }
    // Send SIGKILL to ones that didn't terminate cleanly.
    auto pids = StopServices(stop_first, false /* SIGKILL */);
    auto untracked_pids = StopUntrackedProcesses(false /* SIGKILL */);
    pids.insert(pids.end(), untracked_pids.begin(), untracked_pids.end());
    WaitAndLogViolations(pids, 0ms);

    SubcontextTerminate();
    // Reap subcontext pids.
    ReapAnyOutstandingChildren();

    // 3. send volume abort_fuse and volume shutdown to vold
    Service* vold_service = ServiceList::GetInstance().FindService("vold");
    if (vold_service != nullptr && vold_service->IsRunning()) {
        // Manually abort FUSE connections, since the FUSE daemon is already dead
        // at this point, and unmounting it might hang.
        CallVdc("volume", "abort_fuse");
        CallVdc("volume", "shutdown");
        vold_service->Stop();
    } else {
        LOG(INFO) << "vold not running, skipping vold shutdown";
    }
    // logcat stopped here
    pids = StopServices(kDebuggingServices, false /* SIGKILL */);
    WaitAndLogViolations(pids, 0ms);
    // 4. sync, and try umount
    {
        Timer sync_timer;
        LOG(INFO) << "sync() before umount...";
        sync();
        LOG(INFO) << "sync() before umount took" << sync_timer;
    }
    // 5. drop caches and disable zram backing device, if exist
    KillZramBackingDevice();

    LOG(INFO) << "Ready to unmount apexes. So far shutdown sequence took " << t;
    // 6. unmount active apexes, otherwise they might prevent clean unmount of /data.
    if (auto ret = UnmountAllApexes(); !ret.ok()) {
        LOG(ERROR) << ret.error();
    }
    UmountStat stat = TryUmount(cmd, clean_shutdown_timeout - t.duration());
    // Follow what linux shutdown is doing: one more sync with little bit delay
    {
        Timer sync_timer;
        LOG(INFO) << "sync() after umount...";
        sync();
        LOG(INFO) << "sync() after umount took" << sync_timer;
    }
    if (!is_thermal_shutdown) std::this_thread::sleep_for(100ms);

    // Reboot regardless of umount status. If umount fails, fsck after reboot will fix it.
    std::string data_fs_type = GetDataFsType();
    if (!data_fs_type.empty()) {
        // Do not delete: Critical log for reboot_fs_integrity_test.
        KLOG_WARNING(LOG_TAG, "Umount /data failed, try to use ioctl to shutdown");
        if (data_fs_type == "f2fs") {
            uint32_t flag = F2FS_GOING_DOWN_FULLSYNC;
            unique_fd fd(TEMP_FAILURE_RETRY(open("/data", O_RDONLY)));
            LOG(INFO) << "Invoking F2FS_IOC_SHUTDOWN during shutdown";
            int ret = ioctl(fd.get(), F2FS_IOC_SHUTDOWN, &flag);
            if (ret) {
                PLOG(ERROR) << "Shutdown /data: ";
            } else {
                LOG(INFO) << "Shutdown /data";
            }
        } else if (data_fs_type == "ext4") {
            uint32_t flag = EXT4_GOING_FLAGS_DEFAULT;
            unique_fd fd(TEMP_FAILURE_RETRY(open("/data", O_RDONLY)));
            LOG(INFO) << "Invoking EXT4_IOC_SHUTDOWN during shutdown";
            int ret = ioctl(fd.get(), EXT4_IOC_SHUTDOWN, &flag);
            if (ret) {
                PLOG(ERROR) << "Shutdown /data: ";
            } else {
                LOG(INFO) << "Shutdown /data";
            }
        } else {
            LOG(ERROR) << "Unknown /data fs type: " << data_fs_type;
        }
    }

    LogShutdownTime(stat, t);
    RebootSystem(cmd, reboot_target, reason);
    abort();
}

static void EnterShutdown() {
    LOG(INFO) << "Entering shutdown mode";
    shutting_down = true;
    // Skip wait for prop if it is in progress
    ResetWaitForProp();
    // Clear EXEC flag if there is one pending
    for (const auto& s : ServiceList::GetInstance()) {
        s->UnSetExec();
    }
}

/**
 * Check if "command" field is set in bootloader message.
 *
 * If "command" field is broken (contains non-printable characters prior to
 * terminating zero), it will be zeroed.
 *
 * @param[in,out] boot Bootloader message (BCB) structure
 * @return true if "command" field is already set, and false if it's empty
 */
static bool CommandIsPresent(bootloader_message* boot) {
    if (boot->command[0] == '\0') return false;

    for (size_t i = 0; i < arraysize(boot->command); ++i) {
        if (boot->command[i] == '\0') return true;
        if (!isprint(boot->command[i])) break;
    }

    memset(boot->command, 0, sizeof(boot->command));
    return false;
}

void HandleShutdownRequestedMessage(const std::string& command) {
    int cmd;
    Timer t;

    if (command.starts_with("0thermal")) {
        cmd = ANDROID_RB_THERMOFF;
    } else if (command.starts_with("0")) {
        cmd = ANDROID_RB_POWEROFF;
    } else {
        cmd = ANDROID_RB_RESTART2;
    }

    StartRebootMonitorThread(cmd, t);
}

void HandlePowerctlMessage(const std::string& command) {
    unsigned int cmd = 0;
    std::vector<std::string> cmd_params = Split(command, ",");
    std::string reboot_target = "";
    bool command_invalid = false;

    if (cmd_params[0] == "shutdown") {
        cmd = ANDROID_RB_POWEROFF;
        if (cmd_params.size() >= 2) {
            if (cmd_params[1] == "thermal") {
                // Turn off sources of heat immediately.
                TurnOffBacklight();
                cmd = ANDROID_RB_THERMOFF;
            }
        }
    } else if (cmd_params[0] == "reboot") {
        cmd = ANDROID_RB_RESTART2;
        // Microdroid essentially treats reboot the same as shutdown, so
        // compile out this branch to avoid bootloader_message dependency.
        if (!IsMicrodroid() && cmd_params.size() >= 2) {
            reboot_target = cmd_params[1];
            if (reboot_target == "userspace") {
                LOG(ERROR) << "Userspace reboot is deprecated.";
                return;
            }
            // adb reboot fastboot should boot into bootloader for devices not
            // supporting logical partitions.
            if (reboot_target == "fastboot" &&
                !android::base::GetBoolProperty("ro.boot.dynamic_partitions", false)) {
                reboot_target = "bootloader";
            }
            // When rebooting to the bootloader notify the bootloader writing
            // also the BCB.
            if (reboot_target == "bootloader") {
                std::string err;
                if (!write_reboot_bootloader(&err)) {
                    LOG(ERROR) << "reboot-bootloader: Error writing "
                                  "bootloader_message: "
                               << err;
                }
            } else if (reboot_target == "recovery") {
                bootloader_message boot = {};
                if (std::string err; !read_bootloader_message(&boot, &err)) {
                    LOG(ERROR) << "Failed to read bootloader message: " << err;
                }
                // Update the boot command field if it's empty, and preserve
                // the other arguments in the bootloader message.
                if (!CommandIsPresent(&boot)) {
                    strlcpy(boot.command, "boot-recovery", sizeof(boot.command));
                    if (std::string err; !write_bootloader_message(boot, &err)) {
                        LOG(ERROR) << "Failed to set bootloader message: " << err;
                        return;
                    }
                }
            } else if (std::find(cmd_params.begin(), cmd_params.end(), "quiescent") !=
                       cmd_params.end()) {  // Quiescent can be either subreason or details.
                bootloader_message boot = {};
                if (std::string err; !read_bootloader_message(&boot, &err)) {
                    LOG(ERROR) << "Failed to read bootloader message: " << err;
                }
                // Update the boot command field if it's empty, and preserve
                // the other arguments in the bootloader message.
                if (!CommandIsPresent(&boot)) {
                    strlcpy(boot.command, "boot-quiescent", sizeof(boot.command));
                    if (std::string err; !write_bootloader_message(boot, &err)) {
                        LOG(ERROR) << "Failed to set bootloader message: " << err;
                        return;
                    }
                }
            } else if (reboot_target == "sideload" || reboot_target == "sideload-auto-reboot" ||
                       reboot_target == "fastboot") {
                std::string arg = reboot_target == "sideload-auto-reboot" ? "sideload_auto_reboot"
                                                                          : reboot_target;
                const std::vector<std::string> options = {
                        "--" + arg,
                };
                std::string err;
                if (!write_bootloader_message(options, &err)) {
                    LOG(ERROR) << "Failed to set bootloader message: " << err;
                    return;
                }
                reboot_target = "recovery";
            }

            // If there are additional parameter, pass them along
            for (size_t i = 2; (cmd_params.size() > i) && cmd_params[i].size(); ++i) {
                reboot_target += "," + cmd_params[i];
            }
        }
    } else {
        command_invalid = true;
    }
    if (command_invalid) {
        LOG(ERROR) << "powerctl: unrecognized command '" << command << "'";
        return;
    }

    // We do not want to process any messages (queue'ing triggers, shutdown messages, control
    // messages, etc) from properties during reboot.
    StopSendingMessages();

    LOG(INFO) << "Clear action queue and start shutdown trigger";
    ActionManager::GetInstance().ClearQueue();
    // Queue shutdown trigger first
    ActionManager::GetInstance().QueueEventTrigger("shutdown");
    // Queue built-in shutdown_done
    auto shutdown_handler = [cmd, command, reboot_target](const BuiltinArguments&) {
        DoReboot(cmd, command, reboot_target);
        return Result<void>{};
    };
    ActionManager::GetInstance().QueueBuiltinAction(shutdown_handler, "shutdown_done");

    EnterShutdown();
}

bool IsShuttingDown() {
    return shutting_down;
}

}  // namespace init
}  // namespace android
