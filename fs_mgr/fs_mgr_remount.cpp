/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include <getopt.h>
#include <libavb_user/libavb_user.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <fec/io.h>
#include <fs_mgr_overlayfs.h>
#include <fs_mgr_priv.h>
#include <fstab/fstab.h>

namespace {

[[noreturn]] void usage(int exit_status) {
    LOG(INFO) << getprogname()
              << " [-h] [-R] [-T fstab_file] [partition]...\n"
                 "\t-h --help\tthis help\n"
                 "\t-R --reboot\tdisable verity & reboot to facilitate remount\n"
                 "\t-T --fstab\tcustom fstab file location\n"
                 "\tpartition\tspecific partition(s) (empty does all)\n"
                 "\n"
                 "Remount specified partition(s) read-write, by name or mount point.\n"
                 "-R notwithstanding, verity must be disabled on partition(s).";

    ::exit(exit_status);
}

bool remountable_partition(const android::fs_mgr::FstabEntry& entry) {
    if (entry.fs_mgr_flags.vold_managed) return false;
    if (entry.fs_mgr_flags.recovery_only) return false;
    if (entry.fs_mgr_flags.slot_select_other) return false;
    if (!(entry.flags & MS_RDONLY)) return false;
    if (entry.fs_type == "vfat") return false;
    return true;
}

const std::string system_mount_point(const android::fs_mgr::FstabEntry& entry) {
    if (entry.mount_point == "/") return "/system";
    return entry.mount_point;
}

const android::fs_mgr::FstabEntry* is_wrapped(const android::fs_mgr::Fstab& overlayfs_candidates,
                                              const android::fs_mgr::FstabEntry& entry) {
    auto mount_point = system_mount_point(entry);
    auto it = std::find_if(overlayfs_candidates.begin(), overlayfs_candidates.end(),
                           [&mount_point](const auto& entry) {
                               return android::base::StartsWith(mount_point,
                                                                system_mount_point(entry) + "/");
                           });
    if (it == overlayfs_candidates.end()) return nullptr;
    return &(*it);
}

void MyLogger(android::base::LogId id, android::base::LogSeverity severity, const char* tag,
              const char* file, unsigned int line, const char* message) {
    static const char log_characters[] = "VD\0WEFF";
    if (severity < sizeof(log_characters)) {
        auto severity_char = log_characters[severity];
        if (severity_char) fprintf(stderr, "%c ", severity_char);
    }
    fprintf(stderr, "%s\n", message);

    static auto logd = android::base::LogdLogger();
    logd(id, severity, tag, file, line, message);
}

[[noreturn]] void reboot(bool dedupe) {
    if (dedupe) {
        LOG(INFO) << "The device will now reboot to recovery and attempt un-deduplication.";
    } else {
        LOG(INFO) << "Successfully disabled verity\nrebooting device";
    }
    ::sync();
    android::base::SetProperty(ANDROID_RB_PROPERTY, dedupe ? "reboot,recovery" : "reboot,remount");
    ::sleep(60);
    ::exit(0);  // SUCCESS
}

}  // namespace

int main(int argc, char* argv[]) {
    android::base::InitLogging(argv, MyLogger);

    enum {
        SUCCESS,
        NOT_USERDEBUG,
        BADARG,
        NOT_ROOT,
        NO_FSTAB,
        UNKNOWN_PARTITION,
        INVALID_PARTITION,
        VERITY_PARTITION,
        BAD_OVERLAY,
        NO_MOUNTS,
        REMOUNT_FAILED,
    } retval = SUCCESS;

    // If somehow this executable is delivered on a "user" build, it can
    // not function, so providing a clear message to the caller rather than
    // letting if fall through and provide a lot of confusing failure messages.
    if (!ALLOW_ADBD_DISABLE_VERITY || (android::base::GetProperty("ro.debuggable", "0") != "1")) {
        LOG(ERROR) << "only functions on userdebug or eng builds";
        return NOT_USERDEBUG;
    }

    const char* fstab_file = nullptr;
    auto can_reboot = false;

    struct option longopts[] = {
            {"fstab", required_argument, nullptr, 'T'},
            {"help", no_argument, nullptr, 'h'},
            {"reboot", no_argument, nullptr, 'R'},
            {0, 0, nullptr, 0},
    };
    for (int opt; (opt = ::getopt_long(argc, argv, "hRT:", longopts, nullptr)) != -1;) {
        switch (opt) {
            case 'R':
                can_reboot = true;
                break;
            case 'T':
                if (fstab_file) {
                    LOG(ERROR) << "Cannot supply two fstabs: -T " << fstab_file << " -T" << optarg;
                    usage(BADARG);
                }
                fstab_file = optarg;
                break;
            default:
                LOG(ERROR) << "Bad Argument -" << char(opt);
                usage(BADARG);
                break;
            case 'h':
                usage(SUCCESS);
                break;
        }
    }

    // Make sure we are root.
    if (::getuid() != 0) {
        LOG(ERROR) << "must be run as root";
        return NOT_ROOT;
    }

    // Read the selected fstab.
    android::fs_mgr::Fstab fstab;
    auto fstab_read = false;
    if (fstab_file) {
        fstab_read = android::fs_mgr::ReadFstabFromFile(fstab_file, &fstab);
    } else {
        fstab_read = android::fs_mgr::ReadDefaultFstab(&fstab);
        // Manufacture a / entry from /proc/mounts if missing.
        if (!GetEntryForMountPoint(&fstab, "/system") && !GetEntryForMountPoint(&fstab, "/")) {
            android::fs_mgr::Fstab mounts;
            if (android::fs_mgr::ReadFstabFromFile("/proc/mounts", &mounts)) {
                if (auto entry = GetEntryForMountPoint(&mounts, "/")) {
                    if (entry->fs_type != "rootfs") fstab.emplace_back(*entry);
                }
            }
        }
    }
    if (!fstab_read || fstab.empty()) {
        PLOG(ERROR) << "Failed to read fstab";
        return NO_FSTAB;
    }

    // Generate the list of supported overlayfs mount points.
    auto overlayfs_candidates = fs_mgr_overlayfs_candidate_list(fstab);

    // Generate the all remountable partitions sub-list
    android::fs_mgr::Fstab all;
    for (auto const& entry : fstab) {
        if (!remountable_partition(entry)) continue;
        if (overlayfs_candidates.empty() ||
            GetEntryForMountPoint(&overlayfs_candidates, entry.mount_point) ||
            (is_wrapped(overlayfs_candidates, entry) == nullptr)) {
            all.emplace_back(entry);
        }
    }

    // Parse the unique list of valid partition arguments.
    android::fs_mgr::Fstab partitions;
    for (; argc > optind; ++optind) {
        auto partition = std::string(argv[optind]);
        if (partition.empty()) continue;
        if (partition == "/") partition = "/system";
        auto find_part = [&partition](const auto& entry) {
            const auto mount_point = system_mount_point(entry);
            if (partition == mount_point) return true;
            if (partition == android::base::Basename(mount_point)) return true;
            return false;
        };
        // Do we know about the partition?
        auto it = std::find_if(fstab.begin(), fstab.end(), find_part);
        if (it == fstab.end()) {
            LOG(ERROR) << "Unknown partition " << argv[optind] << ", skipping";
            retval = UNKNOWN_PARTITION;
            continue;
        }
        // Is that one covered by an existing overlayfs?
        auto wrap = is_wrapped(overlayfs_candidates, *it);
        if (wrap) {
            LOG(INFO) << "partition " << argv[optind] << " covered by overlayfs for "
                      << wrap->mount_point << ", switching";
            partition = system_mount_point(*wrap);
        }
        // Is it a remountable partition?
        it = std::find_if(all.begin(), all.end(), find_part);
        if (it == all.end()) {
            LOG(ERROR) << "Invalid partition " << argv[optind] << ", skipping";
            retval = INVALID_PARTITION;
            continue;
        }
        if (GetEntryForMountPoint(&partitions, it->mount_point) == nullptr) {
            partitions.emplace_back(*it);
        }
    }

    if (partitions.empty() && !retval) {
        partitions = all;
    }

    // Check verity and optionally setup overlayfs backing.
    auto reboot_later = false;
    auto uses_overlayfs = fs_mgr_overlayfs_valid() != OverlayfsValidResult::kNotSupported;
    for (auto it = partitions.begin(); it != partitions.end();) {
        auto& entry = *it;
        auto& mount_point = entry.mount_point;
        if (fs_mgr_is_verity_enabled(entry)) {
            retval = VERITY_PARTITION;
            if (android::base::GetProperty("ro.boot.vbmeta.devices_state", "") != "locked") {
                if (AvbOps* ops = avb_ops_user_new()) {
                    auto ret = avb_user_verity_set(
                            ops, android::base::GetProperty("ro.boot.slot_suffix", "").c_str(),
                            false);
                    avb_ops_user_free(ops);
                    if (ret) {
                        LOG(WARNING) << "Disable verity for " << mount_point;
                        reboot_later = can_reboot;
                        if (reboot_later) {
                            // w/o overlayfs available, also check for dedupe
                            if (!uses_overlayfs) {
                                ++it;
                                continue;
                            }
                            reboot(false);
                        }
                    } else if (fs_mgr_set_blk_ro(entry.blk_device, false)) {
                        fec::io fh(entry.blk_device.c_str(), O_RDWR);
                        if (fh && fh.set_verity_status(false)) {
                            LOG(WARNING) << "Disable verity for " << mount_point;
                            reboot_later = can_reboot;
                            if (reboot_later && !uses_overlayfs) {
                                ++it;
                                continue;
                            }
                        }
                    }
                }
            }
            LOG(ERROR) << "Skipping " << mount_point;
            it = partitions.erase(it);
            continue;
        }

        auto change = false;
        errno = 0;
        if (fs_mgr_overlayfs_setup(nullptr, mount_point.c_str(), &change)) {
            if (change) {
                LOG(INFO) << "Using overlayfs for " << mount_point;
            }
        } else if (errno) {
            PLOG(ERROR) << "Overlayfs setup for " << mount_point << " failed, skipping";
            retval = BAD_OVERLAY;
            it = partitions.erase(it);
            continue;
        }
        ++it;
    }

    if (partitions.empty()) {
        if (reboot_later) reboot(false);
        LOG(WARNING) << "No partitions to remount";
        return retval;
    }

    // Mount overlayfs.
    errno = 0;
    if (!fs_mgr_overlayfs_mount_all(&partitions) && errno) {
        retval = BAD_OVERLAY;
        PLOG(ERROR) << "Can not mount overlayfs for partitions";
    }

    // Get actual mounts _after_ overlayfs has been added.
    android::fs_mgr::Fstab mounts;
    if (!android::fs_mgr::ReadFstabFromFile("/proc/mounts", &mounts) || mounts.empty()) {
        PLOG(ERROR) << "Failed to read /proc/mounts";
        retval = NO_MOUNTS;
    }

    // Remount selected partitions.
    for (auto& entry : partitions) {
        // unlock the r/o key for the mount point device
        if (entry.fs_mgr_flags.logical) {
            fs_mgr_update_logical_partition(&entry);
        }
        auto blk_device = entry.blk_device;
        auto mount_point = entry.mount_point;

        for (auto it = mounts.rbegin(); it != mounts.rend(); ++it) {
            auto& rentry = *it;
            if (mount_point == rentry.mount_point) {
                blk_device = rentry.blk_device;
                break;
            }
            // Find overlayfs mount point?
            if ((mount_point == "/") && (rentry.mount_point == "/system")) {
                blk_device = rentry.blk_device;
                mount_point = "/system";
                break;
            }
        }
        if (blk_device == "/dev/root") {
            auto from_fstab = GetEntryForMountPoint(&fstab, mount_point);
            if (from_fstab) blk_device = from_fstab->blk_device;
        }
        fs_mgr_set_blk_ro(blk_device, false);

        // Find system-as-root mount point?
        if ((mount_point == "/system") && !GetEntryForMountPoint(&mounts, mount_point) &&
            GetEntryForMountPoint(&mounts, "/")) {
            mount_point = "/";
        }

        // Now remount!
        if (::mount(blk_device.c_str(), mount_point.c_str(), entry.fs_type.c_str(), MS_REMOUNT,
                    nullptr) == 0) {
            continue;
        }
        if ((errno == EINVAL) && (mount_point != entry.mount_point)) {
            mount_point = entry.mount_point;
            if (::mount(blk_device.c_str(), mount_point.c_str(), entry.fs_type.c_str(), MS_REMOUNT,
                        nullptr) == 0) {
                continue;
            }
        }
        PLOG(WARNING) << "failed to remount partition dev:" << blk_device << " mnt:" << mount_point;
        // If errno = EROFS at this point, we are dealing with r/o
        // filesystem types like squashfs, erofs or ext4 dedupe. We will
        // consider such a device that does not have CONFIG_OVERLAY_FS
        // in the kernel as a misconfigured; except for ext4 dedupe.
        if ((errno == EROFS) && can_reboot) {
            const std::vector<std::string> msg = {"--fsck_unshare_blocks"};
            std::string err;
            if (write_bootloader_message(msg, &err)) reboot(true);
            LOG(ERROR) << "Failed to set bootloader message: " << err;
            errno = EROFS;
        }
        retval = REMOUNT_FAILED;
    }

    if (reboot_later) reboot(false);

    return retval;
}
