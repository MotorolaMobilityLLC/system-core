//
// Copyright (C) 2025 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "first_stage_mount_android.h"

#include <android-base/strings.h>
#include <com_android_apex_flags.h>
#include <fs_mgr.h>
#include <fs_mgr_overlayfs.h>
#include <libfiemap/image_manager.h>
#include <libgsi/libgsi.h>
#include "snapuserd_transition.h"
#include "util.h"

namespace android {
namespace init {

using android::fiemap::IImageManager;
using android::fs_mgr::AvbHandle;
using android::fs_mgr::AvbUniquePtr;
using android::fs_mgr::Fstab;
using android::fs_mgr::FstabEntry;

static inline bool IsDtVbmetaCompatible(const Fstab& fstab) {
    if (std::any_of(fstab.begin(), fstab.end(),
                    [](const auto& entry) { return entry.fs_mgr_flags.avb; })) {
        return true;
    }
    return is_android_dt_value_expected("vbmeta/compatible", "android,vbmeta");
}

FirstStageMountAndroid::FirstStageMountAndroid(Fstab fstab, bool data_on_userdata)
    : FirstStageMount(std::move(fstab)), data_on_userdata_(data_on_userdata) {}

Result<std::unique_ptr<FirstStageMount>> FirstStageMount::Create(const std::string& cmdline) {
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return Error() << "failed to read default fstab for first stage mount";
    }

    bool data_on_userdata = false;
    if (auto entry = GetEntryForMountPoint(&fstab, "/data"); entry) {
        data_on_userdata = entry->blk_device == "/data/block/by-name/userdata";
    }

    // Select first_stage_mount entries
    std::erase_if(fstab, [](auto& entry) { return !entry.fs_mgr_flags.first_stage_mount; });
    return std::make_unique<FirstStageMountAndroid>(std::move(fstab), data_on_userdata);
}

static bool GetRootEntry(FstabEntry* root_entry) {
    Fstab proc_mounts;
    if (!ReadFstabFromFile("/proc/mounts", &proc_mounts)) {
        LOG(ERROR) << "Could not read /proc/mounts and /system not in fstab, /system will not be "
                      "available for overlayfs";
        return false;
    }

    auto entry = std::find_if(proc_mounts.begin(), proc_mounts.end(), [](const auto& entry) {
        return entry.mount_point == "/" && entry.fs_type != "rootfs";
    });

    if (entry == proc_mounts.end()) {
        LOG(ERROR) << "Could not get mount point for '/' in /proc/mounts, /system will not be "
                      "available for overlayfs";
        return false;
    }

    *root_entry = std::move(*entry);

    // We don't know if we're avb or not, so we query device mapper as if we are avb.  If we get a
    // success, then mark as avb, otherwise default to verify.
    auto& dm = android::dm::DeviceMapper::Instance();
    if (dm.GetState("vroot") != android::dm::DmDeviceState::INVALID) {
        root_entry->fs_mgr_flags.avb = true;
    }
    return true;
}

bool FirstStageMountAndroid::DoCreateDevices() {
    if (!FirstStageMount::DoCreateDevices()) {
        return false;
    }

    // Mount /metadata before creating logical partitions, since we need to
    // know whether a snapshot merge is in progress.
    auto metadata_partition = std::find_if(fstab_.begin(), fstab_.end(), [](const auto& entry) {
        return entry.mount_point == "/metadata";
    });
    if (metadata_partition != fstab_.end()) {
        if (MountPartition(metadata_partition, true /* erase_same_mounts */)) {
            // Copies DSU AVB keys from the ramdisk to /metadata.
            // Must be done before the following TrySwitchSystemAsRoot().
            // Otherwise, ramdisk will be inaccessible after switching root.
            CopyDsuAvbKeys();
        }
    }

    if (!CreateLogicalPartitions()) return false;

    return true;
}

void FirstStageMountAndroid::GetExtraBlockDevices(std::set<std::string>* devices) {
    if constexpr (com::android::apex::flags::mount_before_data()) {
        // Even before /data is mounted, apexd needs to access the block device backing /data. Let's
        // initialize "userdata" so that apexd can avoid waiting for the symlink
        // (/dev/block/by-name/userdata).
        if (data_on_userdata_) {
            devices->insert("userdata");
        }
    }
}

bool FirstStageMountAndroid::InitDmLinearBackingDevices(
        const android::fs_mgr::LpMetadata& metadata) {
    std::set<std::string> devices;

    auto partition_names = android::fs_mgr::GetBlockDevicePartitionNames(metadata);
    for (const auto& partition_name : partition_names) {
        // The super partition was found in the earlier pass.
        if (partition_name == super_partition_name_) {
            continue;
        }
        devices.emplace(partition_name);
    }
    if (devices.empty()) {
        return true;
    }
    return InitRequiredDevices(std::move(devices));
}

bool FirstStageMountAndroid::CreateLogicalPartitions() {
    if (!IsDmLinearEnabled()) {
        return true;
    }
    if (super_path_.empty()) {
        LOG(ERROR) << "Could not locate logical partition tables in partition "
                   << super_partition_name_;
        return false;
    }

    if (!IsMicrodroid() && SnapshotManager::IsSnapshotManagerNeeded()) {
        auto init_devices = [this](const std::string& device) -> bool {
            if (android::base::StartsWith(device, "/dev/block/dm-")) {
                return block_dev_init_.InitDmDevice(device);
            }
            return block_dev_init_.InitDevices({device});
        };

        SnapshotManager::MapTempOtaMetadataPartitionIfNeeded(init_devices);
        auto sm = SnapshotManager::NewForFirstStageMount();
        if (!sm) {
            return false;
        }
        if (sm->NeedSnapshotsInFirstStageMount()) {
            return CreateSnapshotPartitions(sm.get());
        }
    }

    auto metadata = android::fs_mgr::ReadCurrentMetadata(super_path_);
    if (!metadata) {
        LOG(ERROR) << "Could not read logical partition metadata from " << super_path_;
        return false;
    }
    if (!InitDmLinearBackingDevices(*metadata.get())) {
        return false;
    }
    return android::fs_mgr::CreateLogicalPartitions(*metadata.get(), super_path_);
}

bool FirstStageMountAndroid::CreateSnapshotPartitions(SnapshotManager* sm) {
    // When COW images are present for snapshots, they are stored on
    // the data partition.
    if (!InitRequiredDevices({"userdata"})) {
        return false;
    }

    use_snapuserd_ = sm->IsSnapuserdRequired();
    if (use_snapuserd_) {
        bool use_ublk = sm->UpdateUsesUblk();
        LOG(INFO) << "using snapuserd in " << (use_ublk ? "UBLK" : "dm-user") << " mode";
        LaunchFirstStageSnapuserd(use_ublk);
    }

    sm->SetUeventRegenCallback([this](const std::string& device) -> bool {
        if (android::base::StartsWith(device, "/dev/block/dm-")) {
            return block_dev_init_.InitDmDevice(device);
        }
        if (android::base::StartsWith(device, "/dev/dm-user/")) {
            return block_dev_init_.InitDmUser(android::base::Basename(device));
        }
        if (android::base::StartsWith(device, "/dev/block/ublkb")) {
            return block_dev_init_.InitDmDevice(device);
        }
        if (android::base::StartsWith(device, "/dev/ublk")) {
            return block_dev_init_.InitUblkMiscDevices(android::base::Basename(device));
        }
        return block_dev_init_.InitDevices({device});
    });
    if (!sm->CreateLogicalAndSnapshotPartitions(super_path_)) {
        return false;
    }

    if (use_snapuserd_) {
        CleanupSnapuserdSocket();
    }
    return true;
}

void FirstStageMountAndroid::UseDsuIfPresent() {
    std::string error;

    if (!android::gsi::CanBootIntoGsi(&error)) {
        LOG(INFO) << "DSU " << error << ", proceeding with normal boot";
        return;
    }

    auto init_devices = [this](std::set<std::string> devices) -> bool {
        if (devices.count("userdata") == 0 || devices.size() > 1) {
            dsu_not_on_userdata_ = true;
        }
        return InitRequiredDevices(std::move(devices));
    };
    std::string active_dsu;
    if (!gsi::GetActiveDsu(&active_dsu)) {
        LOG(ERROR) << "Failed to GetActiveDsu";
        return;
    }
    LOG(INFO) << "DSU slot: " << active_dsu;
    auto images = IImageManager::Open("dsu/" + active_dsu, 0ms);
    if (!images || !images->MapAllImages(init_devices)) {
        LOG(ERROR) << "DSU partition layout could not be instantiated";
        return;
    }

    if (!android::gsi::MarkSystemAsGsi()) {
        PLOG(ERROR) << "DSU indicator file could not be written";
        return;
    }

    // Publish the logical partition names for TransformFstabForDsu() and ReadFstabFromFile().
    const auto dsu_partitions = images->GetAllBackingImages();
    WriteFile(gsi::kGsiLpNamesFile, android::base::Join(dsu_partitions, ","));
    TransformFstabForDsu(&fstab_, active_dsu, dsu_partitions);
}

void FirstStageMountAndroid::MountOverlays() {
    for (const auto& entry : fstab_) {
        if (entry.fs_type == "overlay") {
            fs_mgr_mount_overlayfs_fstab_entry(entry);
        }
    }

    // If we don't see /system or / in the fstab, then we need to create an root entry for
    // overlayfs.
    if (!GetEntryForMountPoint(&fstab_, "/system") && !GetEntryForMountPoint(&fstab_, "/")) {
        FstabEntry root_entry;
        if (GetRootEntry(&root_entry)) {
            fstab_.emplace_back(std::move(root_entry));
        }
    }

    // heads up for instantiating required device(s) for overlayfs logic
    auto init_devices = [this](std::set<std::string> devices) -> bool {
        for (auto iter = devices.begin(); iter != devices.end();) {
            if (android::base::StartsWith(*iter, "/dev/block/dm-")) {
                if (!block_dev_init_.InitDmDevice(*iter)) {
                    return false;
                }
                iter = devices.erase(iter);
            } else {
                iter++;
            }
        }
        return InitRequiredDevices(std::move(devices));
    };
    MapScratchPartitionIfNeeded(&fstab_, init_devices);

    fs_mgr_overlayfs_mount_all(&fstab_);
}

void FirstStageMountAndroid::SaveRamdiskPathToSnapuserd() {
    if (use_snapuserd_) {
        android::init::SaveRamdiskPathToSnapuserd();
    }
}

// Preserves /avb/*.avbpubkey to /metadata/gsi/dsu/avb/, so they can be used for
// key revocation check by DSU installation service.  Note that failing to
// copy files to /metadata is NOT fatal, because it is auxiliary to perform
// public key matching before booting into DSU images on next boot. The actual
// public key matching will still be done on next boot to DSU.
void FirstStageMountAndroid::CopyDsuAvbKeys() {
    std::error_code ec;
    // Removing existing keys in gsi::kDsuAvbKeyDir as they might be stale.
    std::filesystem::remove_all(gsi::kDsuAvbKeyDir, ec);
    if (ec) {
        LOG(ERROR) << "Failed to remove directory " << gsi::kDsuAvbKeyDir << ": " << ec.message();
    }
    // Copy keys from the ramdisk /avb/* to gsi::kDsuAvbKeyDir.
    static constexpr char kRamdiskAvbKeyDir[] = "/avb";
    std::filesystem::copy(kRamdiskAvbKeyDir, gsi::kDsuAvbKeyDir, ec);
    if (ec) {
        LOG(ERROR) << "Failed to copy " << kRamdiskAvbKeyDir << " into " << gsi::kDsuAvbKeyDir
                   << ": " << ec.message();
    }
}

void SetInitAvbVersionInRecovery() {
    if (!IsRecoveryMode()) {
        LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not in recovery mode)";
        return;
    }

    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        LOG(ERROR) << "failed to read default fstab for first stage mount";
        return;
    }
    // Select first_stage_mount entries
    std::erase_if(fstab, [](auto& entry) { return !entry.fs_mgr_flags.first_stage_mount; });

    if (!IsDtVbmetaCompatible(fstab)) {
        LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not vbmeta compatible)";
        return;
    }

    // Initializes required devices for the subsequent AvbHandle::Open()
    // to verify AVB metadata on all partitions in the verified chain.
    // We only set INIT_AVB_VERSION when the AVB verification succeeds, i.e., the
    // Open() function returns a valid handle.
    // We don't need to mount partitions here in recovery mode.
    FirstStageMount avb_first_mount(std::move(fstab));
    if (!avb_first_mount.InitDevices()) {
        LOG(ERROR) << "Failed to init devices for INIT_AVB_VERSION";
        return;
    }

    AvbUniquePtr avb_handle = AvbHandle::Open();
    if (!avb_handle) {
        PLOG(ERROR) << "Failed to open AvbHandle for INIT_AVB_VERSION";
        return;
    }
    setenv("INIT_AVB_VERSION", avb_handle->avb_version().c_str(), 1);
}

}  // namespace init
}  // namespace android
