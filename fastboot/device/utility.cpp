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

#include "utility.h"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>

#include "fastboot_device.h"

using namespace android::fs_mgr;
using namespace std::chrono_literals;
using android::base::unique_fd;
using android::hardware::boot::V1_0::Slot;

namespace {

bool OpenPhysicalPartition(const std::string& name, PartitionHandle* handle) {
    std::optional<std::string> path = FindPhysicalPartition(name);
    if (!path) {
        return false;
    }
    *handle = PartitionHandle(*path);
    return true;
}

bool OpenLogicalPartition(FastbootDevice* device, const std::string& partition_name,
                          PartitionHandle* handle) {
    std::string slot_suffix = GetSuperSlotSuffix(device, partition_name);
    uint32_t slot_number = SlotNumberForSlotSuffix(slot_suffix);
    auto path = FindPhysicalPartition(fs_mgr_get_super_partition_name(slot_number));
    if (!path) {
        return false;
    }
    std::string dm_path;
    if (!CreateLogicalPartition(path->c_str(), slot_number, partition_name, true, 5s, &dm_path)) {
        LOG(ERROR) << "Could not map partition: " << partition_name;
        return false;
    }
    auto closer = [partition_name]() -> void { DestroyLogicalPartition(partition_name, 5s); };
    *handle = PartitionHandle(dm_path, std::move(closer));
    return true;
}

}  // namespace

bool OpenPartition(FastbootDevice* device, const std::string& name, PartitionHandle* handle) {
    // We prioritize logical partitions over physical ones, and do this
    // consistently for other partition operations (like getvar:partition-size).
    if (LogicalPartitionExists(device, name)) {
        if (!OpenLogicalPartition(device, name, handle)) {
            return false;
        }
    } else if (!OpenPhysicalPartition(name, handle)) {
        LOG(ERROR) << "No such partition: " << name;
        return false;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(handle->path().c_str(), O_WRONLY | O_EXCL)));
    if (fd < 0) {
        PLOG(ERROR) << "Failed to open block device: " << handle->path();
        return false;
    }
    handle->set_fd(std::move(fd));
    return true;
}

std::optional<std::string> FindPhysicalPartition(const std::string& name) {
    // Check for an invalid file name
    if (android::base::StartsWith(name, "../") || name.find("/../") != std::string::npos) {
        return {};
    }
    std::string path = "/dev/block/by-name/" + name;
    if (access(path.c_str(), W_OK) < 0) {
        return {};
    }
    return path;
}

static const LpMetadataPartition* FindLogicalPartition(const LpMetadata& metadata,
                                                       const std::string& name) {
    for (const auto& partition : metadata.partitions) {
        if (GetPartitionName(partition) == name) {
            return &partition;
        }
    }
    return nullptr;
}

bool LogicalPartitionExists(FastbootDevice* device, const std::string& name, bool* is_zero_length) {
    std::string slot_suffix = GetSuperSlotSuffix(device, name);
    uint32_t slot_number = SlotNumberForSlotSuffix(slot_suffix);
    auto path = FindPhysicalPartition(fs_mgr_get_super_partition_name(slot_number));
    if (!path) {
        return false;
    }

    std::unique_ptr<LpMetadata> metadata = ReadMetadata(path->c_str(), slot_number);
    if (!metadata) {
        return false;
    }
    const LpMetadataPartition* partition = FindLogicalPartition(*metadata.get(), name);
    if (!partition) {
        return false;
    }
    if (is_zero_length) {
        *is_zero_length = (partition->num_extents == 0);
    }
    return true;
}

bool GetSlotNumber(const std::string& slot, Slot* number) {
    if (slot.size() != 1) {
        return false;
    }
    if (slot[0] < 'a' || slot[0] > 'z') {
        return false;
    }
    *number = slot[0] - 'a';
    return true;
}

std::vector<std::string> ListPartitions(FastbootDevice* device) {
    std::vector<std::string> partitions;

    // First get physical partitions.
    struct dirent* de;
    std::unique_ptr<DIR, decltype(&closedir)> by_name(opendir("/dev/block/by-name"), closedir);
    while ((de = readdir(by_name.get())) != nullptr) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
            continue;
        }
        struct stat s;
        std::string path = "/dev/block/by-name/" + std::string(de->d_name);
        if (!stat(path.c_str(), &s) && S_ISBLK(s.st_mode)) {
            partitions.emplace_back(de->d_name);
        }
    }

    // Find metadata in each super partition (on retrofit devices, there will
    // be two).
    std::vector<std::unique_ptr<LpMetadata>> metadata_list;

    uint32_t current_slot = SlotNumberForSlotSuffix(device->GetCurrentSlot());
    std::string super_name = fs_mgr_get_super_partition_name(current_slot);
    if (auto metadata = ReadMetadata(super_name, current_slot)) {
        metadata_list.emplace_back(std::move(metadata));
    }

    uint32_t other_slot = (current_slot == 0) ? 1 : 0;
    std::string other_super = fs_mgr_get_super_partition_name(other_slot);
    if (super_name != other_super) {
        if (auto metadata = ReadMetadata(other_super, other_slot)) {
            metadata_list.emplace_back(std::move(metadata));
        }
    }

    for (const auto& metadata : metadata_list) {
        for (const auto& partition : metadata->partitions) {
            std::string partition_name = GetPartitionName(partition);
            if (std::find(partitions.begin(), partitions.end(), partition_name) ==
                partitions.end()) {
                partitions.emplace_back(partition_name);
            }
        }
    }
    return partitions;
}

bool GetDeviceLockStatus() {
    std::string cmdline;
    // Return lock status true if unable to read kernel command line.
    if (!android::base::ReadFileToString("/proc/cmdline", &cmdline)) {
        return true;
    }
    return cmdline.find("androidboot.verifiedbootstate=orange") == std::string::npos;
}

bool UpdateAllPartitionMetadata(const std::string& super_name,
                                const android::fs_mgr::LpMetadata& metadata) {
    bool ok = true;
    for (size_t i = 0; i < metadata.geometry.metadata_slot_count; i++) {
        ok &= UpdatePartitionTable(super_name, metadata, i);
    }
    return ok;
}

std::string GetSuperSlotSuffix(FastbootDevice* device, const std::string& partition_name) {
    // If the super partition does not have a slot suffix, this is not a
    // retrofit device, and we should take the current slot.
    std::string current_slot_suffix = device->GetCurrentSlot();
    uint32_t current_slot_number = SlotNumberForSlotSuffix(current_slot_suffix);
    std::string super_partition = fs_mgr_get_super_partition_name(current_slot_number);
    if (GetPartitionSlotSuffix(super_partition).empty()) {
        return current_slot_suffix;
    }

    // Otherwise, infer the slot from the partition name.
    std::string slot_suffix = GetPartitionSlotSuffix(partition_name);
    if (!slot_suffix.empty()) {
        return slot_suffix;
    }
    return current_slot_suffix;
}
