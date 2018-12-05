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

#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

#include <chrono>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <fs_avb/fs_avb.h>
#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <fs_mgr_overlayfs.h>
#include <liblp/liblp.h>

#include "devices.h"
#include "switch_root.h"
#include "uevent.h"
#include "uevent_listener.h"
#include "util.h"

using android::base::Timer;
using android::fs_mgr::AvbHandle;
using android::fs_mgr::AvbHashtreeResult;
using android::fs_mgr::AvbUniquePtr;

using namespace std::literals;

namespace android {
namespace init {

// Class Declarations
// ------------------
class FirstStageMount {
  public:
    FirstStageMount();
    virtual ~FirstStageMount() = default;

    // The factory method to create either FirstStageMountVBootV1 or FirstStageMountVBootV2
    // based on device tree configurations.
    static std::unique_ptr<FirstStageMount> Create();
    bool DoFirstStageMount();  // Mounts fstab entries read from device tree.
    bool InitDevices();

  protected:
    ListenerAction HandleBlockDevice(const std::string& name, const Uevent&);
    bool InitRequiredDevices();
    bool InitMappedDevice(const std::string& verity_device);
    bool CreateLogicalPartitions();
    bool MountPartition(fstab_rec* fstab_rec);
    bool MountPartitions();
    bool IsDmLinearEnabled();
    bool GetDmLinearMetadataDevice();
    bool InitDmLinearBackingDevices(const android::fs_mgr::LpMetadata& metadata);

    ListenerAction UeventCallback(const Uevent& uevent);

    // Pure virtual functions.
    virtual bool GetDmVerityDevices() = 0;
    virtual bool SetUpDmVerity(fstab_rec* fstab_rec) = 0;

    bool need_dm_verity_;

    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab_;
    std::string lp_metadata_partition_;
    std::vector<fstab_rec*> mount_fstab_recs_;
    std::set<std::string> required_devices_partition_names_;
    std::string super_partition_name_;
    std::unique_ptr<DeviceHandler> device_handler_;
    UeventListener uevent_listener_;
};

class FirstStageMountVBootV1 : public FirstStageMount {
  public:
    FirstStageMountVBootV1() = default;
    ~FirstStageMountVBootV1() override = default;

  protected:
    bool GetDmVerityDevices() override;
    bool SetUpDmVerity(fstab_rec* fstab_rec) override;
};

class FirstStageMountVBootV2 : public FirstStageMount {
  public:
    friend void SetInitAvbVersionInRecovery();

    FirstStageMountVBootV2();
    ~FirstStageMountVBootV2() override = default;

  protected:
    bool GetDmVerityDevices() override;
    bool SetUpDmVerity(fstab_rec* fstab_rec) override;
    bool InitAvbHandle();

    std::string device_tree_vbmeta_parts_;
    AvbUniquePtr avb_handle_;
};

// Static Functions
// ----------------
static inline bool IsDtVbmetaCompatible() {
    return is_android_dt_value_expected("vbmeta/compatible", "android,vbmeta");
}

static bool IsRecoveryMode() {
    return access("/system/bin/recovery", F_OK) == 0;
}

// Class Definitions
// -----------------
FirstStageMount::FirstStageMount()
    : need_dm_verity_(false), fstab_(fs_mgr_read_fstab_dt(), fs_mgr_free_fstab) {
    // Stores fstab_->recs[] into mount_fstab_recs_ (vector<fstab_rec*>)
    // for easier manipulation later, e.g., range-base for loop.
    if (fstab_) {
        // DT Fstab predated having a first_stage_mount fs_mgr flag, so if it exists, we use it.
        for (int i = 0; i < fstab_->num_entries; i++) {
            mount_fstab_recs_.push_back(&fstab_->recs[i]);
        }
    } else {
        // Fstab found in first stage ramdisk, which should be a copy of the normal fstab.
        // Mounts intended for first stage are explicitly flagged as such.
        fstab_.reset(fs_mgr_read_fstab_default());
        if (fstab_) {
            for (int i = 0; i < fstab_->num_entries; i++) {
                if (fs_mgr_is_first_stage_mount(&fstab_->recs[i])) {
                    mount_fstab_recs_.push_back(&fstab_->recs[i]);
                }
            }
        } else {
            LOG(INFO) << "Failed to read fstab from device tree";
        }
    }

    auto boot_devices = fs_mgr_get_boot_devices();
    device_handler_ = std::make_unique<DeviceHandler>(
            std::vector<Permissions>{}, std::vector<SysfsPermissions>{}, std::vector<Subsystem>{},
            std::move(boot_devices), false);

    super_partition_name_ = fs_mgr_get_super_partition_name();
}

std::unique_ptr<FirstStageMount> FirstStageMount::Create() {
    if (IsDtVbmetaCompatible()) {
        return std::make_unique<FirstStageMountVBootV2>();
    } else {
        return std::make_unique<FirstStageMountVBootV1>();
    }
}

bool FirstStageMount::DoFirstStageMount() {
    if (!IsDmLinearEnabled() && mount_fstab_recs_.empty()) {
        // Nothing to mount.
        LOG(INFO) << "First stage mount skipped (missing/incompatible/empty fstab in device tree)";
        return true;
    }

    if (!InitDevices()) return false;

    if (!CreateLogicalPartitions()) return false;

    if (!MountPartitions()) return false;

    return true;
}

bool FirstStageMount::InitDevices() {
    return GetDmLinearMetadataDevice() && GetDmVerityDevices() && InitRequiredDevices();
}

bool FirstStageMount::IsDmLinearEnabled() {
    for (auto fstab_rec : mount_fstab_recs_) {
        if (fs_mgr_is_logical(fstab_rec)) return true;
    }
    return false;
}

bool FirstStageMount::GetDmLinearMetadataDevice() {
    // Add any additional devices required for dm-linear mappings.
    if (!IsDmLinearEnabled()) {
        return true;
    }

    required_devices_partition_names_.emplace(super_partition_name_);
    return true;
}

// Creates devices with uevent->partition_name matching one in the member variable
// required_devices_partition_names_. Found partitions will then be removed from it
// for the subsequent member function to check which devices are NOT created.
bool FirstStageMount::InitRequiredDevices() {
    if (required_devices_partition_names_.empty()) {
        return true;
    }

    if (IsDmLinearEnabled() || need_dm_verity_) {
        const std::string dm_path = "/devices/virtual/misc/device-mapper";
        bool found = false;
        auto dm_callback = [this, &dm_path, &found](const Uevent& uevent) {
            if (uevent.path == dm_path) {
                device_handler_->HandleUevent(uevent);
                found = true;
                return ListenerAction::kStop;
            }
            return ListenerAction::kContinue;
        };
        uevent_listener_.RegenerateUeventsForPath("/sys" + dm_path, dm_callback);
        if (!found) {
            LOG(INFO) << "device-mapper device not found in /sys, waiting for its uevent";
            Timer t;
            uevent_listener_.Poll(dm_callback, 10s);
            LOG(INFO) << "Wait for device-mapper returned after " << t;
        }
        if (!found) {
            LOG(ERROR) << "device-mapper device not found after polling timeout";
            return false;
        }
    }

    auto uevent_callback = [this](const Uevent& uevent) { return UeventCallback(uevent); };
    uevent_listener_.RegenerateUevents(uevent_callback);

    // UeventCallback() will remove found partitions from required_devices_partition_names_.
    // So if it isn't empty here, it means some partitions are not found.
    if (!required_devices_partition_names_.empty()) {
        LOG(INFO) << __PRETTY_FUNCTION__
                  << ": partition(s) not found in /sys, waiting for their uevent(s): "
                  << android::base::Join(required_devices_partition_names_, ", ");
        Timer t;
        uevent_listener_.Poll(uevent_callback, 10s);
        LOG(INFO) << "Wait for partitions returned after " << t;
    }

    if (!required_devices_partition_names_.empty()) {
        LOG(ERROR) << __PRETTY_FUNCTION__ << ": partition(s) not found after polling timeout: "
                   << android::base::Join(required_devices_partition_names_, ", ");
        return false;
    }

    return true;
}

bool FirstStageMount::InitDmLinearBackingDevices(const android::fs_mgr::LpMetadata& metadata) {
    auto partition_names = android::fs_mgr::GetBlockDevicePartitionNames(metadata);
    for (const auto& partition_name : partition_names) {
        const auto super_device = android::fs_mgr::GetMetadataSuperBlockDevice(metadata);
        if (partition_name == android::fs_mgr::GetBlockDevicePartitionName(*super_device)) {
            continue;
        }
        required_devices_partition_names_.emplace(partition_name);
    }
    if (required_devices_partition_names_.empty()) {
        return true;
    }

    auto uevent_callback = [this](const Uevent& uevent) { return UeventCallback(uevent); };
    uevent_listener_.RegenerateUevents(uevent_callback);

    if (!required_devices_partition_names_.empty()) {
        LOG(ERROR) << __PRETTY_FUNCTION__ << ": partition(s) not found after polling timeout: "
                   << android::base::Join(required_devices_partition_names_, ", ");
        return false;
    }
    return true;
}

bool FirstStageMount::CreateLogicalPartitions() {
    if (!IsDmLinearEnabled()) {
        return true;
    }
    if (lp_metadata_partition_.empty()) {
        LOG(ERROR) << "Could not locate logical partition tables in partition "
                   << super_partition_name_;
        return false;
    }

    auto metadata = android::fs_mgr::ReadCurrentMetadata(lp_metadata_partition_);
    if (!metadata) {
        LOG(ERROR) << "Could not read logical partition metadata from " << lp_metadata_partition_;
        return false;
    }
    if (!InitDmLinearBackingDevices(*metadata.get())) {
        return false;
    }
    return android::fs_mgr::CreateLogicalPartitions(*metadata.get(), lp_metadata_partition_);
}

ListenerAction FirstStageMount::HandleBlockDevice(const std::string& name, const Uevent& uevent) {
    // Matches partition name to create device nodes.
    // Both required_devices_partition_names_ and uevent->partition_name have A/B
    // suffix when A/B is used.
    auto iter = required_devices_partition_names_.find(name);
    if (iter != required_devices_partition_names_.end()) {
        LOG(VERBOSE) << __PRETTY_FUNCTION__ << ": found partition: " << *iter;
        if (IsDmLinearEnabled() && name == super_partition_name_) {
            std::vector<std::string> links = device_handler_->GetBlockDeviceSymlinks(uevent);
            lp_metadata_partition_ = links[0];
        }
        required_devices_partition_names_.erase(iter);
        device_handler_->HandleUevent(uevent);
        if (required_devices_partition_names_.empty()) {
            return ListenerAction::kStop;
        } else {
            return ListenerAction::kContinue;
        }
    }
    return ListenerAction::kContinue;
}

ListenerAction FirstStageMount::UeventCallback(const Uevent& uevent) {
    // Ignores everything that is not a block device.
    if (uevent.subsystem != "block") {
        return ListenerAction::kContinue;
    }

    if (!uevent.partition_name.empty()) {
        return HandleBlockDevice(uevent.partition_name, uevent);
    } else {
        size_t base_idx = uevent.path.rfind('/');
        if (base_idx != std::string::npos) {
            return HandleBlockDevice(uevent.path.substr(base_idx + 1), uevent);
        }
    }
    // Not found a partition or find an unneeded partition, continue to find others.
    return ListenerAction::kContinue;
}

// Creates "/dev/block/dm-XX" for dm-verity by running coldboot on /sys/block/dm-XX.
bool FirstStageMount::InitMappedDevice(const std::string& dm_device) {
    const std::string device_name(basename(dm_device.c_str()));
    const std::string syspath = "/sys/block/" + device_name;
    bool found = false;

    auto verity_callback = [&device_name, &dm_device, this, &found](const Uevent& uevent) {
        if (uevent.device_name == device_name) {
            LOG(VERBOSE) << "Creating device-mapper device : " << dm_device;
            device_handler_->HandleUevent(uevent);
            found = true;
            return ListenerAction::kStop;
        }
        return ListenerAction::kContinue;
    };

    uevent_listener_.RegenerateUeventsForPath(syspath, verity_callback);
    if (!found) {
        LOG(INFO) << "dm-verity device not found in /sys, waiting for its uevent";
        Timer t;
        uevent_listener_.Poll(verity_callback, 10s);
        LOG(INFO) << "wait for dm-verity device returned after " << t;
    }
    if (!found) {
        LOG(ERROR) << "dm-verity device not found after polling timeout";
        return false;
    }

    return true;
}

bool FirstStageMount::MountPartition(fstab_rec* fstab_rec) {
    if (fs_mgr_is_logical(fstab_rec)) {
        if (!fs_mgr_update_logical_partition(fstab_rec)) {
            return false;
        }
        if (!InitMappedDevice(fstab_rec->blk_device)) {
            return false;
        }
    }
    if (!SetUpDmVerity(fstab_rec)) {
        PLOG(ERROR) << "Failed to setup verity for '" << fstab_rec->mount_point << "'";
        return false;
    }
    if (fs_mgr_do_mount_one(fstab_rec)) {
        PLOG(ERROR) << "Failed to mount '" << fstab_rec->mount_point << "'";
        return false;
    }
    return true;
}

bool FirstStageMount::MountPartitions() {
    // If system is in the fstab then we're not a system-as-root device, and in
    // this case, we mount system first then pivot to it.  From that point on,
    // we are effectively identical to a system-as-root device.
    auto system_partition =
            std::find_if(mount_fstab_recs_.begin(), mount_fstab_recs_.end(),
                         [](const auto& rec) { return rec->mount_point == "/system"s; });

    if (system_partition != mount_fstab_recs_.end()) {
        if (!MountPartition(*system_partition)) {
            return false;
        }

        SwitchRoot((*system_partition)->mount_point);

        mount_fstab_recs_.erase(system_partition);
    }

    for (auto fstab_rec : mount_fstab_recs_) {
        if (!MountPartition(fstab_rec) && !fs_mgr_is_nofail(fstab_rec)) {
            return false;
        }
    }

    // heads up for instantiating required device(s) for overlayfs logic
    const auto devices = fs_mgr_overlayfs_required_devices(mount_fstab_recs_);
    for (auto const& device : devices) {
        if (android::base::StartsWith(device, "/dev/block/by-name/")) {
            required_devices_partition_names_.emplace(basename(device.c_str()));
            auto uevent_callback = [this](const Uevent& uevent) { return UeventCallback(uevent); };
            uevent_listener_.RegenerateUevents(uevent_callback);
            uevent_listener_.Poll(uevent_callback, 10s);
        } else {
            InitMappedDevice(device);
        }
    }

    fs_mgr_overlayfs_mount_all(mount_fstab_recs_);

    return true;
}

bool FirstStageMountVBootV1::GetDmVerityDevices() {
    std::string verity_loc_device;
    need_dm_verity_ = false;

    for (auto fstab_rec : mount_fstab_recs_) {
        // Don't allow verifyatboot in the first stage.
        if (fs_mgr_is_verifyatboot(fstab_rec)) {
            LOG(ERROR) << "Partitions can't be verified at boot";
            return false;
        }
        // Checks for verified partitions.
        if (fs_mgr_is_verified(fstab_rec)) {
            need_dm_verity_ = true;
        }
        // Checks if verity metadata is on a separate partition. Note that it is
        // not partition specific, so there must be only one additional partition
        // that carries verity state.
        if (fstab_rec->verity_loc) {
            if (verity_loc_device.empty()) {
                verity_loc_device = fstab_rec->verity_loc;
            } else if (verity_loc_device != fstab_rec->verity_loc) {
                LOG(ERROR) << "More than one verity_loc found: " << verity_loc_device << ", "
                           << fstab_rec->verity_loc;
                return false;
            }
        }
    }

    // Includes the partition names of fstab records and verity_loc_device (if any).
    // Notes that fstab_rec->blk_device has A/B suffix updated by fs_mgr when A/B is used.
    for (auto fstab_rec : mount_fstab_recs_) {
        if (!fs_mgr_is_logical(fstab_rec)) {
            required_devices_partition_names_.emplace(basename(fstab_rec->blk_device));
        }
    }

    if (!verity_loc_device.empty()) {
        required_devices_partition_names_.emplace(basename(verity_loc_device.c_str()));
    }

    return true;
}

bool FirstStageMountVBootV1::SetUpDmVerity(fstab_rec* fstab_rec) {
    if (fs_mgr_is_verified(fstab_rec)) {
        int ret = fs_mgr_setup_verity(fstab_rec, false /* wait_for_verity_dev */);
        switch (ret) {
            case FS_MGR_SETUP_VERITY_SKIPPED:
            case FS_MGR_SETUP_VERITY_DISABLED:
                LOG(INFO) << "Verity disabled/skipped for '" << fstab_rec->mount_point << "'";
                return true;
            case FS_MGR_SETUP_VERITY_SUCCESS:
                // The exact block device name (fstab_rec->blk_device) is changed to
                // "/dev/block/dm-XX". Needs to create it because ueventd isn't started in init
                // first stage.
                return InitMappedDevice(fstab_rec->blk_device);
            default:
                return false;
        }
    }
    return true;  // Returns true to mount the partition.
}

// FirstStageMountVBootV2 constructor.
// Gets the vbmeta partitions from device tree.
// /{
//     firmware {
//         android {
//             vbmeta {
//                 compatible = "android,vbmeta";
//                 parts = "vbmeta,boot,system,vendor"
//             };
//         };
//     };
//  }
FirstStageMountVBootV2::FirstStageMountVBootV2() : avb_handle_(nullptr) {
    if (!read_android_dt_file("vbmeta/parts", &device_tree_vbmeta_parts_)) {
        PLOG(ERROR) << "Failed to read vbmeta/parts from device tree";
        return;
    }
}

bool FirstStageMountVBootV2::GetDmVerityDevices() {
    need_dm_verity_ = false;

    std::set<std::string> logical_partitions;

    // fstab_rec->blk_device has A/B suffix.
    for (auto fstab_rec : mount_fstab_recs_) {
        if (fs_mgr_is_avb(fstab_rec)) {
            need_dm_verity_ = true;
        }
        if (fs_mgr_is_logical(fstab_rec)) {
            // Don't try to find logical partitions via uevent regeneration.
            logical_partitions.emplace(basename(fstab_rec->blk_device));
        } else {
            required_devices_partition_names_.emplace(basename(fstab_rec->blk_device));
        }
    }

    // libavb verifies AVB metadata on all verified partitions at once.
    // e.g., The device_tree_vbmeta_parts_ will be "vbmeta,boot,system,vendor"
    // for libavb to verify metadata, even if there is only /vendor in the
    // above mount_fstab_recs_.
    if (need_dm_verity_) {
        if (device_tree_vbmeta_parts_.empty()) {
            LOG(ERROR) << "Missing vbmeta parts in device tree";
            return false;
        }
        std::vector<std::string> partitions = android::base::Split(device_tree_vbmeta_parts_, ",");
        std::string ab_suffix = fs_mgr_get_slot_suffix();
        for (const auto& partition : partitions) {
            std::string partition_name = partition + ab_suffix;
            if (logical_partitions.count(partition_name)) {
                continue;
            }
            // required_devices_partition_names_ is of type std::set so it's not an issue
            // to emplace a partition twice. e.g., /vendor might be in both places:
            //   - device_tree_vbmeta_parts_ = "vbmeta,boot,system,vendor"
            //   - mount_fstab_recs_: /vendor_a
            required_devices_partition_names_.emplace(partition_name);
        }
    }
    return true;
}

bool FirstStageMountVBootV2::SetUpDmVerity(fstab_rec* fstab_rec) {
    if (fs_mgr_is_avb(fstab_rec)) {
        if (!InitAvbHandle()) return false;
        AvbHashtreeResult hashtree_result =
                avb_handle_->SetUpAvbHashtree(fstab_rec, false /* wait_for_verity_dev */);
        switch (hashtree_result) {
            case AvbHashtreeResult::kDisabled:
                return true;  // Returns true to mount the partition.
            case AvbHashtreeResult::kSuccess:
                // The exact block device name (fstab_rec->blk_device) is changed to
                // "/dev/block/dm-XX". Needs to create it because ueventd isn't started in init
                // first stage.
                return InitMappedDevice(fstab_rec->blk_device);
            default:
                return false;
        }
    }
    return true;  // Returns true to mount the partition.
}

bool FirstStageMountVBootV2::InitAvbHandle() {
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

// Public functions
// ----------------
// Mounts partitions specified by fstab in device tree.
bool DoFirstStageMount() {
    // Skips first stage mount if we're in recovery mode.
    if (IsRecoveryMode()) {
        LOG(INFO) << "First stage mount skipped (recovery mode)";
        return true;
    }

    std::unique_ptr<FirstStageMount> handle = FirstStageMount::Create();
    if (!handle) {
        LOG(ERROR) << "Failed to create FirstStageMount";
        return false;
    }
    return handle->DoFirstStageMount();
}

void SetInitAvbVersionInRecovery() {
    if (!IsRecoveryMode()) {
        LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not in recovery mode)";
        return;
    }

    if (!IsDtVbmetaCompatible()) {
        LOG(INFO) << "Skipped setting INIT_AVB_VERSION (not vbmeta compatible)";
        return;
    }

    // Initializes required devices for the subsequent AvbHandle::Open()
    // to verify AVB metadata on all partitions in the verified chain.
    // We only set INIT_AVB_VERSION when the AVB verification succeeds, i.e., the
    // Open() function returns a valid handle.
    // We don't need to mount partitions here in recovery mode.
    FirstStageMountVBootV2 avb_first_mount;
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
