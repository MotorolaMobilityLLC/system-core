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

#include "first_stage_mount.h"

#include <signal.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android/avf_cc_flags.h>
#include <com_android_apex_flags.h>
#include <fs_avb/fs_avb.h>
#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <liblp/liblp.h>

#include "block_dev_initializer.h"
#include "devices.h"
#include "result.h"
#include "switch_root.h"
#include "uevent.h"
#include "uevent_listener.h"
#include "util.h"

using android::base::ReadFileToString;
using android::base::Result;
using android::base::Split;
using android::base::StringPrintf;
using android::base::Timer;
using android::fs_mgr::AvbHandle;
using android::fs_mgr::AvbHandleStatus;
using android::fs_mgr::AvbHashtreeResult;
using android::fs_mgr::AvbUniquePtr;
using android::fs_mgr::Fstab;
using android::fs_mgr::FstabEntry;
using android::fs_mgr::ReadDefaultFstab;
using android::fs_mgr::SkipMountingPartitions;

using namespace std::literals;

namespace android {
namespace init {

namespace {

bool DeferOverlayfsMount() {
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);
    return cmdline.find("androidboot.defer_overlayfs_mount=1") != std::string::npos;
}
} // namespace
// Static Functions
// ----------------

static bool IsStandaloneImageRollback(const AvbHandle& builtin_vbmeta,
                                      const AvbHandle& standalone_vbmeta,
                                      const FstabEntry& fstab_entry) {
    std::string old_spl = builtin_vbmeta.GetSecurityPatchLevel(fstab_entry);
    std::string new_spl = standalone_vbmeta.GetSecurityPatchLevel(fstab_entry);

    bool rollbacked = false;
    if (old_spl.empty() || new_spl.empty() || new_spl < old_spl) {
        rollbacked = true;
    }

    if (rollbacked) {
        LOG(ERROR) << "Image rollback detected for " << fstab_entry.mount_point
                   << ", SPL switches from '" << old_spl << "' to '" << new_spl << "'";
        if (AvbHandle::IsDeviceUnlocked()) {
            LOG(INFO) << "Allowing rollbacked standalone image when the device is unlocked";
            return false;
        }
    }

    return rollbacked;
}

bool FirstStageMount::DoCreateDevices() {
    return InitDevices();
}

bool FirstStageMount::DoFirstStageMount() {
    if (!IsDmLinearEnabled() && fstab_.empty()) {
        // Nothing to mount.
        LOG(INFO) << "First stage mount skipped (missing/incompatible/empty fstab in device tree)";
        return true;
    }

    if (!MountPartitions()) return false;

    return true;
}

// TODO: should this be in a library in packages/modules/Virtualization first_stage_init links?
static bool IsMicrodroidStrictBoot() {
    return access("/proc/device-tree/chosen/avf,strict-boot", F_OK) == 0;
}

bool FirstStageMount::InitDevices() {
    if (!block_dev_init_.InitBootDevicesFromPartUuid()) {
        return false;
    }

    std::set<std::string> devices;
    GetSuperDeviceName(&devices);
    GetExtraBlockDevices(&devices);

    if (!GetDmVerityDevices(&devices)) {
        return false;
    }
    if (!InitRequiredDevices(std::move(devices))) {
        return false;
    }

    if (IsMicrodroid() && android::virtualization::IsOpenDiceChangesFlagEnabled()) {
        if (IsMicrodroidStrictBoot()) {
            if (!block_dev_init_.InitPlatformDevice("open-dice0")) {
                return false;
            }
        }
    }

    if (IsDmLinearEnabled()) {
        auto super_symlink = "/dev/block/by-name/"s + super_partition_name_;
        if (!android::base::Realpath(super_symlink, &super_path_)) {
            PLOG(ERROR) << "realpath failed: " << super_symlink;
            return false;
        }
    }

    if constexpr (com::android::apex::flags::mount_before_data()) {
        block_dev_init_.InitLoopDevices();
    }

    return true;
}

bool FirstStageMount::IsDmLinearEnabled() {
    for (const auto& entry : fstab_) {
        if (entry.fs_mgr_flags.logical) return true;
    }
    return false;
}

void FirstStageMount::GetSuperDeviceName(std::set<std::string>* devices) {
    // Add any additional devices required for dm-linear mappings.
    if (!IsDmLinearEnabled()) {
        return;
    }

    devices->emplace(super_partition_name_);
}

// Creates devices with uevent->partition_name matching ones in the given set.
// Found partitions will then be removed from it for the subsequent member
// function to check which devices are NOT created.
bool FirstStageMount::InitRequiredDevices(std::set<std::string> devices) {
    if (!block_dev_init_.InitDeviceMapper()) {
        return false;
    }
    if (devices.empty()) {
        return true;
    }
    return block_dev_init_.InitDevices(std::move(devices));
}

bool FirstStageMount::MountPartition(const Fstab::iterator& begin, bool erase_same_mounts,
                                     Fstab::iterator* end) {
    // Sets end to begin + 1, so we can just return on failure below.
    if (end) {
        *end = begin + 1;
    }

    if (!fs_mgr_create_canonical_mount_point(begin->mount_point)) {
        return false;
    }

    if (begin->fs_mgr_flags.logical) {
        if (!fs_mgr_update_logical_partition(&(*begin))) {
            return false;
        }
        if (!block_dev_init_.InitDmDevice(begin->blk_device)) {
            return false;
        }
    }
    if (!SetUpDmVerity(&(*begin))) {
        PLOG(ERROR) << "Failed to setup verity for '" << begin->mount_point << "'";
        return false;
    }

    bool mounted = (fs_mgr_do_mount_one(*begin) == 0);

    // Try other mounts with the same mount point.
    Fstab::iterator current = begin + 1;
    for (; current != fstab_.end() && current->mount_point == begin->mount_point; current++) {
        if (!mounted) {
            // blk_device is already updated to /dev/dm-<N> by SetUpDmVerity() above.
            // Copy it from the begin iterator.
            current->blk_device = begin->blk_device;
            mounted = (fs_mgr_do_mount_one(*current) == 0);
        }
    }
    if (erase_same_mounts) {
        current = fstab_.erase(begin, current);
    }
    if (end) {
        *end = current;
    }
    return mounted;
}

void FirstStageMount::PreloadAvbKeys() {
    for (const auto& entry : fstab_) {
        // No need to cache the key content if it's empty, or is already cached.
        if (entry.avb_keys.empty() || preload_avb_key_blobs_.count(entry.avb_keys)) {
            continue;
        }

        // Determines all key paths first.
        std::vector<std::string> key_paths;
        if (is_dir(entry.avb_keys.c_str())) {  // fstab_keys might be a dir, e.g., /avb.
            const char* avb_key_dir = entry.avb_keys.c_str();
            std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(avb_key_dir), closedir);
            if (!dir) {
                LOG(ERROR) << "Failed to opendir: " << dir;
                continue;
            }
            // Gets all key pathes under the dir.
            struct dirent* de;
            while ((de = readdir(dir.get()))) {
                if (de->d_type != DT_REG) continue;
                std::string full_path = StringPrintf("%s/%s", avb_key_dir, de->d_name);
                key_paths.emplace_back(std::move(full_path));
            }
            std::sort(key_paths.begin(), key_paths.end());
        } else {
            // avb_keys are key paths separated by ":", if it's not a dir.
            key_paths = Split(entry.avb_keys, ":");
        }

        // Reads the key content then cache it.
        std::vector<std::string> key_blobs;
        for (const auto& path : key_paths) {
            std::string key_value;
            if (!ReadFileToString(path, &key_value)) {
                continue;
            }
            key_blobs.emplace_back(std::move(key_value));
        }

        // Maps entry.avb_keys to actual key blobs.
        preload_avb_key_blobs_[entry.avb_keys] = std::move(key_blobs);
    }
}

// If system is in the fstab then we're not a system-as-root device, and in
// this case, we mount system first then pivot to it.  From that point on,
// we are effectively identical to a system-as-root device.
bool FirstStageMount::TrySwitchSystemAsRoot() {
    UseDsuIfPresent();
    // Preloading all AVB keys from the ramdisk before switching root to /system.
    PreloadAvbKeys();

    auto system_partition = std::find_if(fstab_.begin(), fstab_.end(), [](const auto& entry) {
        return entry.mount_point == "/system";
    });

    if (system_partition == fstab_.end()) return true;

    SaveRamdiskPathToSnapuserd();

    if (!MountPartition(system_partition, false /* erase_same_mounts */)) {
        PLOG(ERROR) << "Failed to mount /system";
        return false;
    }
    if (!AllowVerityCheckAtMostOnce() && fs_mgr_verity_is_check_at_most_once(*system_partition)) {
        LOG(ERROR) << "check_at_most_once forbidden on external media";
        return false;
    }

    SwitchRoot("/system");

    return true;
}

static bool MaybeDeriveMicrodroidVendorDiceNode(Fstab* fstab) {
    std::optional<std::string> microdroid_vendor_block_dev;
    for (auto entry = fstab->begin(); entry != fstab->end(); entry++) {
        if (entry->mount_point == "/vendor") {
            microdroid_vendor_block_dev.emplace(entry->blk_device);
            break;
        }
    }
    if (!microdroid_vendor_block_dev.has_value()) {
        LOG(VERBOSE) << "No microdroid vendor partition to mount";
        return true;
    }
    // clang-format off
    const std::array<const char*, 8> args = {
        "/system/bin/derive_microdroid_vendor_dice_node",
                "--dice-driver", "/dev/open-dice0",
                "--microdroid-vendor-disk-image", microdroid_vendor_block_dev->data(),
                "--output", "/microdroid_resources/dice_chain.raw", nullptr,
    };
    // clang-format-on
    // ForkExecveAndWaitForCompletion calls waitpid to wait for the fork-ed process to finish.
    // The first_stage_console adds SA_NOCLDWAIT flag to the SIGCHLD handler, which means that
    // waitpid will always return -ECHLD. Here we re-register a default handler, so that waitpid
    // works.
    LOG(INFO) << "Deriving dice node for microdroid vendor partition";
    signal(SIGCHLD, SIG_DFL);
    if (ForkExecveAndWaitForCompletion(args[0], (char**)args.data()) != 0) {
        LOG(ERROR) << "Failed to derive microdroid vendor dice node";
        return false;
    }
    return true;
}

bool FirstStageMount::MountPartitions() {
    if (!TrySwitchSystemAsRoot()) return false;

    if (IsMicrodroid() && android::virtualization::IsOpenDiceChangesFlagEnabled()) {
        if (!MaybeDeriveMicrodroidVendorDiceNode(&fstab_)) {
            return false;
        }
    }

    if (!SkipMountingPartitions(&fstab_, true /* verbose */)) return false;

    for (auto current = fstab_.begin(); current != fstab_.end();) {
        // We've already mounted /system above.
        if (current->mount_point == "/system") {
            ++current;
            continue;
        }

        // Handle overlayfs entries later.
        if (current->fs_type == "overlay") {
            ++current;
            continue;
        }

        // Skip raw partition entries such as boot, dtbo, etc.
        // Having emmc fstab entries allows us to probe current->vbmeta_partition
        // in InitDevices() when they are AVB chained partitions.
        if (current->fs_type == "emmc") {
            ++current;
            continue;
        }

        Fstab::iterator end;
        if (!MountPartition(current, false /* erase_same_mounts */, &end)) {
            if (current->fs_mgr_flags.no_fail) {
                LOG(INFO) << "Failed to mount " << current->mount_point
                          << ", ignoring mount for no_fail partition";
            } else if (current->fs_mgr_flags.formattable) {
                LOG(INFO) << "Failed to mount " << current->mount_point
                          << ", ignoring mount for formattable partition";
            } else {
                PLOG(ERROR) << "Failed to mount " << current->mount_point;
                return false;
            }
        }
        current = end;
    }

    MountOverlays();

    return true;
}

FirstStageMount::FirstStageMount(Fstab fstab)
    : fstab_(std::move(fstab)), avb_handle_(nullptr) {
    super_partition_name_ = fs_mgr_get_super_partition_name();

    std::string device_tree_vbmeta_parts;
    read_android_dt_file("vbmeta/parts", &device_tree_vbmeta_parts);

    for (auto&& partition : Split(device_tree_vbmeta_parts, ",")) {
        if (!partition.empty()) {
            vbmeta_partitions_.emplace_back(std::move(partition));
        }
    }

    for (const auto& entry : fstab_) {
        if (!entry.vbmeta_partition.empty()) {
            vbmeta_partitions_.emplace_back(entry.vbmeta_partition);
        }
    }

    if (vbmeta_partitions_.empty()) {
        LOG(ERROR) << "Failed to read vbmeta partitions.";
    }
}

bool FirstStageMount::GetDmVerityDevices(std::set<std::string>* devices) {
    bool need_dm_verity = false;

    std::set<std::string> logical_partitions;

    // fstab_rec->blk_device has A/B suffix.
    for (const auto& fstab_entry : fstab_) {
        if (fstab_entry.fs_mgr_flags.avb) {
            need_dm_verity = true;
        }
        // Skip pseudo filesystems.
        if (fstab_entry.fs_type == "overlay") {
            continue;
        }
        // Don't try to find logical partitions via uevent regeneration.
        if (fstab_entry.fs_mgr_flags.logical) {
            logical_partitions.emplace(basename(fstab_entry.blk_device.c_str()));
            continue;
        }
        // Skip partitions that don't appear to be block devices.
        if (!fstab_entry.blk_device.starts_with("/dev/")) {
            continue;
        }
        devices->emplace(basename(fstab_entry.blk_device.c_str()));
    }

    // Any partitions needed for verifying the partitions used in first stage mount, e.g. vbmeta
    // must be provided as vbmeta_partitions.
    if (need_dm_verity) {
        if (vbmeta_partitions_.empty()) {
            LOG(ERROR) << "Missing vbmeta partitions";
            return false;
        }
        std::string ab_suffix = fs_mgr_get_slot_suffix();
        for (const auto& partition : vbmeta_partitions_) {
            std::string partition_name = partition + ab_suffix;
            if (logical_partitions.count(partition_name)) {
                continue;
            }
            // devices is of type std::set so it's not an issue to emplace a
            // partition twice. e.g., /vendor might be in both places:
            //   - device_tree_vbmeta_parts_ = "vbmeta,boot,system,vendor"
            //   - mount_fstab_recs_: /vendor_a
            devices->emplace(partition_name);
        }
    }
    return true;
}

bool IsHashtreeDisabled(const AvbHandle& vbmeta, const std::string& mount_point) {
    if (vbmeta.status() == AvbHandleStatus::kHashtreeDisabled ||
        vbmeta.status() == AvbHandleStatus::kVerificationDisabled) {
        LOG(ERROR) << "Top-level vbmeta is disabled, skip Hashtree setup for " << mount_point;
        return true;  // Returns true to mount the partition directly.
    }
    return false;
}

bool FirstStageMount::SetUpDmVerity(FstabEntry* fstab_entry) {
    AvbHashtreeResult hashtree_result;

    // It's possible for a fstab_entry to have both avb_keys and avb flag.
    // In this case, try avb_keys first, then fallback to avb flag.
    if (!fstab_entry->avb_keys.empty()) {
        if (!InitAvbHandle()) return false;
        // Checks if hashtree should be disabled from the top-level /vbmeta.
        if (IsHashtreeDisabled(*avb_handle_, fstab_entry->mount_point)) {
            return true;
        }
        auto avb_standalone_handle = AvbHandle::LoadAndVerifyVbmeta(
                *fstab_entry, preload_avb_key_blobs_[fstab_entry->avb_keys]);
        if (!avb_standalone_handle) {
            LOG(ERROR) << "Failed to load offline vbmeta for " << fstab_entry->mount_point;
            // Fallbacks to built-in hashtree if fs_mgr_flags.avb is set.
            if (!fstab_entry->fs_mgr_flags.avb) return false;
            LOG(INFO) << "Fallback to built-in hashtree for " << fstab_entry->mount_point;
            hashtree_result =
                    avb_handle_->SetUpAvbHashtree(fstab_entry, false /* wait_for_verity_dev */);
        } else {
            // Sets up hashtree via the standalone handle.
            if (IsStandaloneImageRollback(*avb_handle_, *avb_standalone_handle, *fstab_entry)) {
                return false;
            }
            hashtree_result = avb_standalone_handle->SetUpAvbHashtree(
                    fstab_entry, false /* wait_for_verity_dev */);
        }
    } else if (fstab_entry->fs_mgr_flags.avb) {
        if (!InitAvbHandle()) return false;
        hashtree_result =
                avb_handle_->SetUpAvbHashtree(fstab_entry, false /* wait_for_verity_dev */);
    } else if (!fstab_entry->avb_hashtree_digest.empty()) {
        // When fstab_entry has neither avb_keys nor avb flag, try using
        // avb_hashtree_digest.
        if (!InitAvbHandle()) return false;
        // Checks if hashtree should be disabled from the top-level /vbmeta.
        if (IsHashtreeDisabled(*avb_handle_, fstab_entry->mount_point)) {
            return true;
        }
        auto avb_standalone_handle = AvbHandle::LoadAndVerifyVbmeta(*fstab_entry);
        if (!avb_standalone_handle) {
            LOG(ERROR) << "Failed to load vbmeta based on hashtree descriptor root digest for "
                       << fstab_entry->mount_point;
            return false;
        }
        hashtree_result = avb_standalone_handle->SetUpAvbHashtree(fstab_entry,
                                                                  false /* wait_for_verity_dev */);
    } else {
        return true;  // No need AVB, returns true to mount the partition directly.
    }

    switch (hashtree_result) {
        case AvbHashtreeResult::kDisabled:
            return true;  // Returns true to mount the partition.
        case AvbHashtreeResult::kSuccess:
            // The exact block device name (fstab_rec->blk_device) is changed to
            // "/dev/block/dm-XX". Needs to create it because ueventd isn't started in init
            // first stage.
            return block_dev_init_.InitDmDevice(fstab_entry->blk_device);
        default:
            return false;
    }
}

bool FirstStageMount::InitAvbHandle() {
    if (avb_handle_) return true;  // Returns true if the handle is already initialized.

    avb_handle_ = AvbHandle::Open();

    if (!avb_handle_) {
        PLOG(ERROR) << "Failed to open AvbHandle";
        return false;
    }
    // Sets INIT_AVB_VERSION here for init to set ro.boot.avb_version in the second stage.
    setenv("INIT_AVB_VERSION", avb_handle_->avb_version().c_str(), 1);
    return true;
}

}  // namespace init
}  // namespace android
