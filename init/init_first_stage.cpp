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

#include "init_first_stage.h"

#include <stdlib.h>
#include <unistd.h>

#include <chrono>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

#include "devices.h"
#include "fs_mgr.h"
#include "fs_mgr_avb.h"
#include "uevent.h"
#include "uevent_listener.h"
#include "util.h"

using namespace std::chrono_literals;

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
    bool InitRequiredDevices();
    bool InitVerityDevice(const std::string& verity_device);
    bool MountPartitions();

    virtual ListenerAction UeventCallback(const Uevent& uevent);

    // Pure virtual functions.
    virtual bool GetRequiredDevices() = 0;
    virtual bool SetUpDmVerity(fstab_rec* fstab_rec) = 0;

    bool need_dm_verity_;

    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> device_tree_fstab_;
    std::vector<fstab_rec*> mount_fstab_recs_;
    std::set<std::string> required_devices_partition_names_;
    DeviceHandler device_handler_;
    UeventListener uevent_listener_;
};

class FirstStageMountVBootV1 : public FirstStageMount {
  public:
    FirstStageMountVBootV1() = default;
    ~FirstStageMountVBootV1() override = default;

  protected:
    bool GetRequiredDevices() override;
    bool SetUpDmVerity(fstab_rec* fstab_rec) override;
};

class FirstStageMountVBootV2 : public FirstStageMount {
  public:
    friend void SetInitAvbVersionInRecovery();

    FirstStageMountVBootV2();
    ~FirstStageMountVBootV2() override = default;

  protected:
    ListenerAction UeventCallback(const Uevent& uevent) override;
    bool GetRequiredDevices() override;
    bool SetUpDmVerity(fstab_rec* fstab_rec) override;
    bool InitAvbHandle();

    std::string device_tree_vbmeta_parts_;
    FsManagerAvbUniquePtr avb_handle_;
    ByNameSymlinkMap by_name_symlink_map_;
};

// Static Functions
// ----------------
static inline bool IsDtVbmetaCompatible() {
    return is_android_dt_value_expected("vbmeta/compatible", "android,vbmeta");
}

static bool inline IsRecoveryMode() {
    return access("/sbin/recovery", F_OK) == 0;
}

// Class Definitions
// -----------------
FirstStageMount::FirstStageMount()
    : need_dm_verity_(false), device_tree_fstab_(fs_mgr_read_fstab_dt(), fs_mgr_free_fstab) {
    if (!device_tree_fstab_) {
        LOG(ERROR) << "Failed to read fstab from device tree";
        return;
    }
    // Stores device_tree_fstab_->recs[] into mount_fstab_recs_ (vector<fstab_rec*>)
    // for easier manipulation later, e.g., range-base for loop.
    for (int i = 0; i < device_tree_fstab_->num_entries; i++) {
        mount_fstab_recs_.push_back(&device_tree_fstab_->recs[i]);
    }
}

std::unique_ptr<FirstStageMount> FirstStageMount::Create() {
    if (IsDtVbmetaCompatible()) {
        return std::make_unique<FirstStageMountVBootV2>();
    } else {
        return std::make_unique<FirstStageMountVBootV1>();
    }
}

bool FirstStageMount::DoFirstStageMount() {
    // Nothing to mount.
    if (mount_fstab_recs_.empty()) return true;

    if (!InitDevices()) return false;

    if (!MountPartitions()) return false;

    return true;
}

bool FirstStageMount::InitDevices() {
    return GetRequiredDevices() && InitRequiredDevices();
}

// Creates devices with uevent->partition_name matching one in the member variable
// required_devices_partition_names_. Found partitions will then be removed from it
// for the subsequent member function to check which devices are NOT created.
bool FirstStageMount::InitRequiredDevices() {
    if (required_devices_partition_names_.empty()) {
        return true;
    }

    if (need_dm_verity_) {
        const std::string dm_path = "/devices/virtual/misc/device-mapper";
        bool found = false;
        auto dm_callback = [this, &dm_path, &found](const Uevent& uevent) {
            if (uevent.path == dm_path) {
                device_handler_.HandleDeviceEvent(uevent);
                found = true;
                return ListenerAction::kStop;
            }
            return ListenerAction::kContinue;
        };
        uevent_listener_.RegenerateUeventsForPath("/sys" + dm_path, dm_callback);
        if (!found) {
            uevent_listener_.Poll(dm_callback, 10s);
        }
        if (!found) {
            LOG(ERROR) << "device-mapper device not found";
            return false;
        }
    }

    auto uevent_callback = [this](const Uevent& uevent) { return UeventCallback(uevent); };
    uevent_listener_.RegenerateUevents(uevent_callback);

    // UeventCallback() will remove found partitions from required_devices_partition_names_.
    // So if it isn't empty here, it means some partitions are not found.
    if (!required_devices_partition_names_.empty()) {
        uevent_listener_.Poll(uevent_callback, 10s);
    }

    if (!required_devices_partition_names_.empty()) {
        LOG(ERROR) << __PRETTY_FUNCTION__ << ": partition(s) not found: "
                   << android::base::Join(required_devices_partition_names_, ", ");
        return false;
    }

    return true;
}

ListenerAction FirstStageMount::UeventCallback(const Uevent& uevent) {
    // Ignores everything that is not a block device.
    if (uevent.subsystem != "block") {
        return ListenerAction::kContinue;
    }

    if (!uevent.partition_name.empty()) {
        // Matches partition name to create device nodes.
        // Both required_devices_partition_names_ and uevent->partition_name have A/B
        // suffix when A/B is used.
        auto iter = required_devices_partition_names_.find(uevent.partition_name);
        if (iter != required_devices_partition_names_.end()) {
            LOG(VERBOSE) << __PRETTY_FUNCTION__ << ": found partition: " << *iter;
            required_devices_partition_names_.erase(iter);
            device_handler_.HandleDeviceEvent(uevent);
            if (required_devices_partition_names_.empty()) {
                return ListenerAction::kStop;
            } else {
                return ListenerAction::kContinue;
            }
        }
    }
    // Not found a partition or find an unneeded partition, continue to find others.
    return ListenerAction::kContinue;
}

// Creates "/dev/block/dm-XX" for dm-verity by running coldboot on /sys/block/dm-XX.
bool FirstStageMount::InitVerityDevice(const std::string& verity_device) {
    const std::string device_name(basename(verity_device.c_str()));
    const std::string syspath = "/sys/block/" + device_name;
    bool found = false;

    auto verity_callback = [&device_name, &verity_device, this, &found](const Uevent& uevent) {
        if (uevent.device_name == device_name) {
            LOG(VERBOSE) << "Creating dm-verity device : " << verity_device;
            device_handler_.HandleDeviceEvent(uevent);
            found = true;
            return ListenerAction::kStop;
        }
        return ListenerAction::kContinue;
    };

    uevent_listener_.RegenerateUeventsForPath(syspath, verity_callback);
    if (!found) {
        uevent_listener_.Poll(verity_callback, 10s);
    }
    if (!found) {
        LOG(ERROR) << "dm-verity device not found";
        return false;
    }

    return true;
}

bool FirstStageMount::MountPartitions() {
    for (auto fstab_rec : mount_fstab_recs_) {
        if (!SetUpDmVerity(fstab_rec)) {
            PLOG(ERROR) << "Failed to setup verity for '" << fstab_rec->mount_point << "'";
            return false;
        }
        if (fs_mgr_do_mount_one(fstab_rec)) {
            PLOG(ERROR) << "Failed to mount '" << fstab_rec->mount_point << "'";
            return false;
        }
    }
    return true;
}

bool FirstStageMountVBootV1::GetRequiredDevices() {
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
        required_devices_partition_names_.emplace(basename(fstab_rec->blk_device));
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
            break;
        case FS_MGR_SETUP_VERITY_SUCCESS:
            // The exact block device name (fstab_rec->blk_device) is changed to "/dev/block/dm-XX".
            // Needs to create it because ueventd isn't started in init first stage.
            return InitVerityDevice(fstab_rec->blk_device);
            break;
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

bool FirstStageMountVBootV2::GetRequiredDevices() {
    need_dm_verity_ = false;

    // fstab_rec->blk_device has A/B suffix.
    for (auto fstab_rec : mount_fstab_recs_) {
        if (fs_mgr_is_avb(fstab_rec)) {
            need_dm_verity_ = true;
        }
        required_devices_partition_names_.emplace(basename(fstab_rec->blk_device));
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
            // required_devices_partition_names_ is of type std::set so it's not an issue
            // to emplace a partition twice. e.g., /vendor might be in both places:
            //   - device_tree_vbmeta_parts_ = "vbmeta,boot,system,vendor"
            //   - mount_fstab_recs_: /vendor_a
            required_devices_partition_names_.emplace(partition + ab_suffix);
        }
    }
    return true;
}

ListenerAction FirstStageMountVBootV2::UeventCallback(const Uevent& uevent) {
    // Check if this uevent corresponds to one of the required partitions and store its symlinks if
    // so, in order to create FsManagerAvbHandle later.
    // Note that the parent callback removes partitions from the list of required partitions
    // as it finds them, so this must happen first.
    if (!uevent.partition_name.empty() &&
        required_devices_partition_names_.find(uevent.partition_name) !=
            required_devices_partition_names_.end()) {
        // GetBlockDeviceSymlinks() will return three symlinks at most, depending on
        // the content of uevent. by-name symlink will be at [0] if uevent->partition_name
        // is not empty. e.g.,
        //   - /dev/block/platform/soc.0/f9824900.sdhci/by-name/modem
        //   - /dev/block/platform/soc.0/f9824900.sdhci/by-num/p1
        //   - /dev/block/platform/soc.0/f9824900.sdhci/mmcblk0p1
        std::vector<std::string> links = device_handler_.GetBlockDeviceSymlinks(uevent);
        if (!links.empty()) {
            auto[it, inserted] = by_name_symlink_map_.emplace(uevent.partition_name, links[0]);
            if (!inserted) {
                LOG(ERROR) << "Partition '" << uevent.partition_name
                           << "' already existed in the by-name symlink map with a value of '"
                           << it->second << "', new value '" << links[0] << "' will be ignored.";
            }
        }
    }

    return FirstStageMount::UeventCallback(uevent);
}

bool FirstStageMountVBootV2::SetUpDmVerity(fstab_rec* fstab_rec) {
    if (fs_mgr_is_avb(fstab_rec)) {
        if (!InitAvbHandle()) return false;
        if (avb_handle_->hashtree_disabled()) {
            LOG(INFO) << "avb hashtree disabled for '" << fstab_rec->mount_point << "'";
        } else if (avb_handle_->SetUpAvb(fstab_rec, false /* wait_for_verity_dev */)) {
            // The exact block device name (fstab_rec->blk_device) is changed to "/dev/block/dm-XX".
            // Needs to create it because ueventd isn't started in init first stage.
            InitVerityDevice(fstab_rec->blk_device);
        } else {
            return false;
        }
    }
    return true;  // Returns true to mount the partition.
}

bool FirstStageMountVBootV2::InitAvbHandle() {
    if (avb_handle_) return true;  // Returns true if the handle is already initialized.

    if (by_name_symlink_map_.empty()) {
        LOG(ERROR) << "by_name_symlink_map_ is empty";
        return false;
    }

    avb_handle_ = FsManagerAvbHandle::Open(std::move(by_name_symlink_map_));
    by_name_symlink_map_.clear();  // Removes all elements after the above std::move().

    if (!avb_handle_) {
        PLOG(ERROR) << "Failed to open FsManagerAvbHandle";
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

    // Firstly checks if device tree fstab entries are compatible.
    if (!is_android_dt_value_expected("fstab/compatible", "android,fstab")) {
        LOG(INFO) << "First stage mount skipped (missing/incompatible fstab in device tree)";
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

    // Initializes required devices for the subsequent FsManagerAvbHandle::Open()
    // to verify AVB metadata on all partitions in the verified chain.
    // We only set INIT_AVB_VERSION when the AVB verification succeeds, i.e., the
    // Open() function returns a valid handle.
    // We don't need to mount partitions here in recovery mode.
    FirstStageMountVBootV2 avb_first_mount;
    if (!avb_first_mount.InitDevices()) {
        LOG(ERROR) << "Failed to init devices for INIT_AVB_VERSION";
        return;
    }

    FsManagerAvbUniquePtr avb_handle =
        FsManagerAvbHandle::Open(std::move(avb_first_mount.by_name_symlink_map_));
    if (!avb_handle) {
        PLOG(ERROR) << "Failed to open FsManagerAvbHandle for INIT_AVB_VERSION";
        return;
    }
    setenv("INIT_AVB_VERSION", avb_handle->avb_version().c_str(), 1);
}

}  // namespace init
}  // namespace android
