/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "commands.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <unordered_set>

#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <android/hardware/boot/1.1/IBootControl.h>
#include <cutils/android_reboot.h>
#include <ext4_utils/wipe.h>
#include <fs_mgr.h>
#include <fs_mgr/roots.h>
#include <libgsi/libgsi.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>
#include <libsnapshot/snapshot.h>
#include <uuid/uuid.h>

#include "constants.h"
#include "fastboot_device.h"
#include "flashing.h"
#include "utility.h"

using android::fs_mgr::MetadataBuilder;
using ::android::hardware::hidl_string;
using ::android::hardware::boot::V1_0::BoolResult;
using ::android::hardware::boot::V1_0::CommandResult;
using ::android::hardware::boot::V1_0::Slot;
using ::android::hardware::boot::V1_1::MergeStatus;
using ::android::hardware::fastboot::V1_0::Result;
using ::android::hardware::fastboot::V1_0::Status;
using android::snapshot::SnapshotManager;
using IBootControl1_1 = ::android::hardware::boot::V1_1::IBootControl;

struct VariableHandlers {
    // Callback to retrieve the value of a single variable.
    std::function<bool(FastbootDevice*, const std::vector<std::string>&, std::string*)> get;
    // Callback to retrieve all possible argument combinations, for getvar all.
    std::function<std::vector<std::vector<std::string>>(FastbootDevice*)> get_all_args;
};

static bool IsSnapshotUpdateInProgress(FastbootDevice* device) {
    auto hal = device->boot1_1();
    if (!hal) {
        return false;
    }
    auto merge_status = hal->getSnapshotMergeStatus();
    return merge_status == MergeStatus::SNAPSHOTTED || merge_status == MergeStatus::MERGING;
}

static bool IsProtectedPartitionDuringMerge(FastbootDevice* device, const std::string& name) {
    static const std::unordered_set<std::string> ProtectedPartitionsDuringMerge = {
            "userdata", "metadata", "misc"};
    if (ProtectedPartitionsDuringMerge.count(name) == 0) {
        return false;
    }
    return IsSnapshotUpdateInProgress(device);
}

static void GetAllVars(FastbootDevice* device, const std::string& name,
                       const VariableHandlers& handlers) {
    if (!handlers.get_all_args) {
        std::string message;
        if (!handlers.get(device, std::vector<std::string>(), &message)) {
            return;
        }
        device->WriteInfo(android::base::StringPrintf("%s:%s", name.c_str(), message.c_str()));
        return;
    }

    auto all_args = handlers.get_all_args(device);
    for (const auto& args : all_args) {
        std::string message;
        if (!handlers.get(device, args, &message)) {
            continue;
        }
        std::string arg_string = android::base::Join(args, ":");
        device->WriteInfo(android::base::StringPrintf("%s:%s:%s", name.c_str(), arg_string.c_str(),
                                                      message.c_str()));
    }
}

bool GetVarHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    const std::unordered_map<std::string, VariableHandlers> kVariableMap = {
            {FB_VAR_VERSION, {GetVersion, nullptr}},
            {FB_VAR_VERSION_BOOTLOADER, {GetBootloaderVersion, nullptr}},
            {FB_VAR_VERSION_BASEBAND, {GetBasebandVersion, nullptr}},
            {FB_VAR_VERSION_OS, {GetOsVersion, nullptr}},
            {FB_VAR_VERSION_VNDK, {GetVndkVersion, nullptr}},
            {FB_VAR_PRODUCT, {GetProduct, nullptr}},
            {FB_VAR_SERIALNO, {GetSerial, nullptr}},
            {FB_VAR_VARIANT, {GetVariant, nullptr}},
            {FB_VAR_SECURE, {GetSecure, nullptr}},
            {FB_VAR_UNLOCKED, {GetUnlocked, nullptr}},
            {FB_VAR_MAX_DOWNLOAD_SIZE, {GetMaxDownloadSize, nullptr}},
            {FB_VAR_CURRENT_SLOT, {::GetCurrentSlot, nullptr}},
            {FB_VAR_SLOT_COUNT, {GetSlotCount, nullptr}},
            {FB_VAR_HAS_SLOT, {GetHasSlot, GetAllPartitionArgsNoSlot}},
            {FB_VAR_SLOT_SUCCESSFUL, {GetSlotSuccessful, nullptr}},
            {FB_VAR_SLOT_UNBOOTABLE, {GetSlotUnbootable, nullptr}},
            {FB_VAR_PARTITION_SIZE, {GetPartitionSize, GetAllPartitionArgsWithSlot}},
            {FB_VAR_PARTITION_TYPE, {GetPartitionType, GetAllPartitionArgsWithSlot}},
            {FB_VAR_IS_LOGICAL, {GetPartitionIsLogical, GetAllPartitionArgsWithSlot}},
            {FB_VAR_IS_USERSPACE, {GetIsUserspace, nullptr}},
            {FB_VAR_OFF_MODE_CHARGE_STATE, {GetOffModeChargeState, nullptr}},
            {FB_VAR_BATTERY_VOLTAGE, {GetBatteryVoltage, nullptr}},
            {FB_VAR_BATTERY_SOC_OK, {GetBatterySoCOk, nullptr}},
            {FB_VAR_HW_REVISION, {GetHardwareRevision, nullptr}},
            {FB_VAR_SUPER_PARTITION_NAME, {GetSuperPartitionName, nullptr}},
            {FB_VAR_SNAPSHOT_UPDATE_STATUS, {GetSnapshotUpdateStatus, nullptr}},
            {FB_VAR_CPU_ABI, {GetCpuAbi, nullptr}},
            {FB_VAR_SYSTEM_FINGERPRINT, {GetSystemFingerprint, nullptr}},
            {FB_VAR_VENDOR_FINGERPRINT, {GetVendorFingerprint, nullptr}},
            {FB_VAR_DYNAMIC_PARTITION, {GetDynamicPartition, nullptr}},
            {FB_VAR_FIRST_API_LEVEL, {GetFirstApiLevel, nullptr}},
            {FB_VAR_SECURITY_PATCH_LEVEL, {GetSecurityPatchLevel, nullptr}},
            {FB_VAR_TREBLE_ENABLED, {GetTrebleEnabled, nullptr}}};

    if (args.size() < 2) {
        return device->WriteFail("Missing argument");
    }

    // Special case: return all variables that we can.
    if (args[1] == "all") {
        for (const auto& [name, handlers] : kVariableMap) {
            GetAllVars(device, name, handlers);
        }
        return device->WriteOkay("");
    }

    // args[0] is command name, args[1] is variable.
    auto found_variable = kVariableMap.find(args[1]);
    if (found_variable == kVariableMap.end()) {
        return device->WriteFail("Unknown variable");
    }

    std::string message;
    std::vector<std::string> getvar_args(args.begin() + 2, args.end());
    if (!found_variable->second.get(device, getvar_args, &message)) {
        return device->WriteFail(message);
    }
    return device->WriteOkay(message);
}

bool EraseHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteStatus(FastbootResult::FAIL, "Invalid arguments");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL, "Erase is not allowed on locked devices");
    }

    const auto& partition_name = args[1];
    if (IsProtectedPartitionDuringMerge(device, partition_name)) {
        auto message = "Cannot erase " + partition_name + " while a snapshot update is in progress";
        return device->WriteFail(message);
    }

    PartitionHandle handle;
    if (!OpenPartition(device, partition_name, &handle)) {
        return device->WriteStatus(FastbootResult::FAIL, "Partition doesn't exist");
    }
    if (wipe_block_device(handle.fd(), get_block_device_size(handle.fd())) == 0) {
        return device->WriteStatus(FastbootResult::OKAY, "Erasing succeeded");
    }
    return device->WriteStatus(FastbootResult::FAIL, "Erasing failed");
}

bool OemCmdHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    auto fastboot_hal = device->fastboot_hal();
    if (!fastboot_hal) {
        return device->WriteStatus(FastbootResult::FAIL, "Unable to open fastboot HAL");
    }

    Result ret;
    auto ret_val = fastboot_hal->doOemCommand(args[0], [&](Result result) { ret = result; });
    if (!ret_val.isOk()) {
        return device->WriteStatus(FastbootResult::FAIL, "Unable to do OEM command");
    }
    if (ret.status != Status::SUCCESS) {
        return device->WriteStatus(FastbootResult::FAIL, ret.message);
    }

    return device->WriteStatus(FastbootResult::OKAY, ret.message);
}

bool DownloadHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteStatus(FastbootResult::FAIL, "size argument unspecified");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL,
                                   "Download is not allowed on locked devices");
    }

    // arg[0] is the command name, arg[1] contains size of data to be downloaded
    unsigned int size;
    if (!android::base::ParseUint("0x" + args[1], &size, kMaxDownloadSizeDefault)) {
        return device->WriteStatus(FastbootResult::FAIL, "Invalid size");
    }
    device->download_data().resize(size);
    if (!device->WriteStatus(FastbootResult::DATA, android::base::StringPrintf("%08x", size))) {
        return false;
    }

    if (device->HandleData(true, &device->download_data())) {
        return device->WriteStatus(FastbootResult::OKAY, "");
    }

    PLOG(ERROR) << "Couldn't download data";
    return device->WriteStatus(FastbootResult::FAIL, "Couldn't download data");
}

bool SetActiveHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteStatus(FastbootResult::FAIL, "Missing slot argument");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL,
                                   "set_active command is not allowed on locked devices");
    }

    Slot slot;
    if (!GetSlotNumber(args[1], &slot)) {
        // Slot suffix needs to be between 'a' and 'z'.
        return device->WriteStatus(FastbootResult::FAIL, "Bad slot suffix");
    }

    // Non-A/B devices will not have a boot control HAL.
    auto boot_control_hal = device->boot_control_hal();
    if (!boot_control_hal) {
        return device->WriteStatus(FastbootResult::FAIL,
                                   "Cannot set slot: boot control HAL absent");
    }
    if (slot >= boot_control_hal->getNumberSlots()) {
        return device->WriteStatus(FastbootResult::FAIL, "Slot out of range");
    }

    // If the slot is not changing, do nothing.
    if (args[1] == device->GetCurrentSlot()) {
        return device->WriteOkay("");
    }

    // Check how to handle the current snapshot state.
    if (auto hal11 = device->boot1_1()) {
        auto merge_status = hal11->getSnapshotMergeStatus();
        if (merge_status == MergeStatus::MERGING) {
            return device->WriteFail("Cannot change slots while a snapshot update is in progress");
        }
        // Note: we allow the slot change if the state is SNAPSHOTTED. First-
        // stage init does not have access to the HAL, and uses the slot number
        // and /metadata OTA state to determine whether a slot change occurred.
        // Booting into the old slot would erase the OTA, and switching A->B->A
        // would simply resume it if no boots occur in between. Re-flashing
        // partitions implicitly cancels the OTA, so leaving the state as-is is
        // safe.
        if (merge_status == MergeStatus::SNAPSHOTTED) {
            device->WriteInfo(
                    "Changing the active slot with a snapshot applied may cancel the"
                    " update.");
        }
    }

    CommandResult ret;
    auto cb = [&ret](CommandResult result) { ret = result; };
    auto result = boot_control_hal->setActiveBootSlot(slot, cb);
    if (result.isOk() && ret.success) {
        // Save as slot suffix to match the suffix format as returned from
        // the boot control HAL.
        auto current_slot = "_" + args[1];
        device->set_active_slot(current_slot);
        return device->WriteStatus(FastbootResult::OKAY, "");
    }
    return device->WriteStatus(FastbootResult::FAIL, "Unable to set slot");
}

bool ShutDownHandler(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto result = device->WriteStatus(FastbootResult::OKAY, "Shutting down");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "shutdown,fastboot");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
    return result;
}

bool RebootHandler(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto result = device->WriteStatus(FastbootResult::OKAY, "Rebooting");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,from_fastboot");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
    return result;
}

bool RebootBootloaderHandler(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto result = device->WriteStatus(FastbootResult::OKAY, "Rebooting bootloader");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,bootloader");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
    return result;
}

bool RebootFastbootHandler(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto result = device->WriteStatus(FastbootResult::OKAY, "Rebooting fastboot");
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot,fastboot");
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
    return result;
}

static bool EnterRecovery() {
    const char msg_switch_to_recovery = 'r';

    android::base::unique_fd sock(socket(AF_UNIX, SOCK_STREAM, 0));
    if (sock < 0) {
        PLOG(ERROR) << "Couldn't create sock";
        return false;
    }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, "/dev/socket/recovery", sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        PLOG(ERROR) << "Couldn't connect to recovery";
        return false;
    }
    // Switch to recovery will not update the boot reason since it does not
    // require a reboot.
    auto ret = write(sock, &msg_switch_to_recovery, sizeof(msg_switch_to_recovery));
    if (ret != sizeof(msg_switch_to_recovery)) {
        PLOG(ERROR) << "Couldn't write message to switch to recovery";
        return false;
    }

    return true;
}

bool RebootRecoveryHandler(FastbootDevice* device, const std::vector<std::string>& /* args */) {
    auto status = true;
    if (EnterRecovery()) {
        status = device->WriteStatus(FastbootResult::OKAY, "Rebooting to recovery");
    } else {
        status = device->WriteStatus(FastbootResult::FAIL, "Unable to reboot to recovery");
    }
    device->CloseDevice();
    TEMP_FAILURE_RETRY(pause());
    return status;
}

// Helper class for opening a handle to a MetadataBuilder and writing the new
// partition table to the same place it was read.
class PartitionBuilder {
  public:
    explicit PartitionBuilder(FastbootDevice* device, const std::string& partition_name);

    bool Write();
    bool Valid() const { return !!builder_; }
    MetadataBuilder* operator->() const { return builder_.get(); }

  private:
    FastbootDevice* device_;
    std::string super_device_;
    uint32_t slot_number_;
    std::unique_ptr<MetadataBuilder> builder_;
};

PartitionBuilder::PartitionBuilder(FastbootDevice* device, const std::string& partition_name)
    : device_(device) {
    std::string slot_suffix = GetSuperSlotSuffix(device, partition_name);
    slot_number_ = android::fs_mgr::SlotNumberForSlotSuffix(slot_suffix);
    auto super_device = FindPhysicalPartition(fs_mgr_get_super_partition_name(slot_number_));
    if (!super_device) {
        return;
    }
    super_device_ = *super_device;
    builder_ = MetadataBuilder::New(super_device_, slot_number_);
}

bool PartitionBuilder::Write() {
    auto metadata = builder_->Export();
    if (!metadata) {
        return false;
    }
    return UpdateAllPartitionMetadata(device_, super_device_, *metadata.get());
}

bool CreatePartitionHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        return device->WriteFail("Invalid partition name and size");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL, "Command not available on locked devices");
    }

    uint64_t partition_size;
    std::string partition_name = args[1];
    if (!android::base::ParseUint(args[2].c_str(), &partition_size)) {
        return device->WriteFail("Invalid partition size");
    }

    PartitionBuilder builder(device, partition_name);
    if (!builder.Valid()) {
        return device->WriteFail("Could not open super partition");
    }
    // TODO(112433293) Disallow if the name is in the physical table as well.
    if (builder->FindPartition(partition_name)) {
        return device->WriteFail("Partition already exists");
    }

    auto partition = builder->AddPartition(partition_name, 0);
    if (!partition) {
        return device->WriteFail("Failed to add partition");
    }
    if (!builder->ResizePartition(partition, partition_size)) {
        builder->RemovePartition(partition_name);
        return device->WriteFail("Not enough space for partition");
    }
    if (!builder.Write()) {
        return device->WriteFail("Failed to write partition table");
    }
    return device->WriteOkay("Partition created");
}

bool DeletePartitionHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteFail("Invalid partition name and size");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL, "Command not available on locked devices");
    }

    std::string partition_name = args[1];

    PartitionBuilder builder(device, partition_name);
    if (!builder.Valid()) {
        return device->WriteFail("Could not open super partition");
    }
    builder->RemovePartition(partition_name);
    if (!builder.Write()) {
        return device->WriteFail("Failed to write partition table");
    }
    return device->WriteOkay("Partition deleted");
}

bool ResizePartitionHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 3) {
        return device->WriteFail("Invalid partition name and size");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL, "Command not available on locked devices");
    }

    uint64_t partition_size;
    std::string partition_name = args[1];
    if (!android::base::ParseUint(args[2].c_str(), &partition_size)) {
        return device->WriteFail("Invalid partition size");
    }

    PartitionBuilder builder(device, partition_name);
    if (!builder.Valid()) {
        return device->WriteFail("Could not open super partition");
    }

    auto partition = builder->FindPartition(partition_name);
    if (!partition) {
        return device->WriteFail("Partition does not exist");
    }

    // Remove the updated flag to cancel any snapshots.
    uint32_t attrs = partition->attributes();
    partition->set_attributes(attrs & ~LP_PARTITION_ATTR_UPDATED);

    if (!builder->ResizePartition(partition, partition_size)) {
        return device->WriteFail("Not enough space to resize partition");
    }
    if (!builder.Write()) {
        return device->WriteFail("Failed to write partition table");
    }
    return device->WriteOkay("Partition resized");
}

void CancelPartitionSnapshot(FastbootDevice* device, const std::string& partition_name) {
    PartitionBuilder builder(device, partition_name);
    if (!builder.Valid()) return;

    auto partition = builder->FindPartition(partition_name);
    if (!partition) return;

    // Remove the updated flag to cancel any snapshots.
    uint32_t attrs = partition->attributes();
    partition->set_attributes(attrs & ~LP_PARTITION_ATTR_UPDATED);

    builder.Write();
}

bool FlashHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteStatus(FastbootResult::FAIL, "Invalid arguments");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL,
                                   "Flashing is not allowed on locked devices");
    }

    const auto& partition_name = args[1];
    if (IsProtectedPartitionDuringMerge(device, partition_name)) {
        auto message = "Cannot flash " + partition_name + " while a snapshot update is in progress";
        return device->WriteFail(message);
    }

    if (LogicalPartitionExists(device, partition_name)) {
        CancelPartitionSnapshot(device, partition_name);
    }

    int ret = Flash(device, partition_name);
    if (ret < 0) {
        return device->WriteStatus(FastbootResult::FAIL, strerror(-ret));
    }
    return device->WriteStatus(FastbootResult::OKAY, "Flashing succeeded");
}

bool UpdateSuperHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        return device->WriteFail("Invalid arguments");
    }

    if (GetDeviceLockStatus()) {
        return device->WriteStatus(FastbootResult::FAIL, "Command not available on locked devices");
    }

    bool wipe = (args.size() >= 3 && args[2] == "wipe");
    return UpdateSuper(device, args[1], wipe);
}

bool GsiHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    if (args.size() != 2) {
        return device->WriteFail("Invalid arguments");
    }

    AutoMountMetadata mount_metadata;
    if (!mount_metadata) {
        return device->WriteFail("Could not find GSI install");
    }

    if (!android::gsi::IsGsiInstalled()) {
        return device->WriteStatus(FastbootResult::FAIL, "No GSI is installed");
    }

    if (args[1] == "wipe") {
        if (!android::gsi::UninstallGsi()) {
            return device->WriteStatus(FastbootResult::FAIL, strerror(errno));
        }
    } else if (args[1] == "disable") {
        if (!android::gsi::DisableGsi()) {
            return device->WriteStatus(FastbootResult::FAIL, strerror(errno));
        }
    }
    return device->WriteStatus(FastbootResult::OKAY, "Success");
}

bool SnapshotUpdateHandler(FastbootDevice* device, const std::vector<std::string>& args) {
    // Note that we use the HAL rather than mounting /metadata, since we want
    // our results to match the bootloader.
    auto hal = device->boot1_1();
    if (!hal) return device->WriteFail("Not supported");

    // If no arguments, return the same thing as a getvar. Note that we get the
    // HAL first so we can return "not supported" before we return the less
    // specific error message below.
    if (args.size() < 2 || args[1].empty()) {
        std::string message;
        if (!GetSnapshotUpdateStatus(device, {}, &message)) {
            return device->WriteFail("Could not determine update status");
        }
        device->WriteInfo(message);
        return device->WriteOkay("");
    }

    MergeStatus status = hal->getSnapshotMergeStatus();

    if (args.size() != 2) {
        return device->WriteFail("Invalid arguments");
    }
    if (args[1] == "cancel") {
        switch (status) {
            case MergeStatus::SNAPSHOTTED:
            case MergeStatus::MERGING:
                hal->setSnapshotMergeStatus(MergeStatus::CANCELLED);
                break;
            default:
                break;
        }
    } else if (args[1] == "merge") {
        if (status != MergeStatus::MERGING) {
            return device->WriteFail("No snapshot merge is in progress");
        }

        auto sm = SnapshotManager::NewForFirstStageMount();
        if (!sm) {
            return device->WriteFail("Unable to create SnapshotManager");
        }
        if (!sm->HandleImminentDataWipe()) {
            return device->WriteFail("Unable to finish snapshot merge");
        }
    } else {
        return device->WriteFail("Invalid parameter to snapshot-update");
    }
    return device->WriteStatus(FastbootResult::OKAY, "Success");
}
