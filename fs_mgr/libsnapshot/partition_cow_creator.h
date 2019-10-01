// Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <stdint.h>

#include <optional>
#include <string>

#include <liblp/builder.h>

#include <libsnapshot/snapshot.h>

namespace android {
namespace snapshot {

// Helper class that creates COW for a partition.
struct PartitionCowCreator {
    using Extent = android::fs_mgr::Extent;
    using Interval = android::fs_mgr::Interval;
    using MetadataBuilder = android::fs_mgr::MetadataBuilder;
    using Partition = android::fs_mgr::Partition;
    using InstallOperation = chromeos_update_engine::InstallOperation;
    template <typename T>
    using RepeatedPtrField = google::protobuf::RepeatedPtrField<T>;

    // The metadata that will be written to target metadata slot.
    MetadataBuilder* target_metadata = nullptr;
    // The suffix of the target slot.
    std::string target_suffix;
    // The partition in target_metadata that needs to be snapshotted.
    Partition* target_partition = nullptr;
    // The metadata at the current slot (that would be used if the device boots
    // normally). This is used to determine which extents are being used.
    MetadataBuilder* current_metadata = nullptr;
    // The suffix of the current slot.
    std::string current_suffix;
    // List of operations to be applied on the partition.
    const RepeatedPtrField<InstallOperation>* operations = nullptr;

    struct Return {
        SnapshotManager::SnapshotStatus snapshot_status;
        std::vector<Interval> cow_partition_usable_regions;
    };

    std::optional<Return> Run();

  private:
    bool HasExtent(Partition* p, Extent* e);
    std::optional<uint64_t> GetCowSize(uint64_t snapshot_size);
};

}  // namespace snapshot
}  // namespace android
