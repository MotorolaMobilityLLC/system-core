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

#include "first_stage_mount.h"

namespace android {
namespace init {

using android::fs_mgr::Fstab;

// Note: this is a temporary solution to avoid blocking devs that depend on /vendor partition in
// Microdroid. For the proper solution the /vendor fstab should probably be defined in the DT.
// TODO(b/285855430): refactor this
// TODO(b/285855436): verify key microdroid-vendor was signed with.
// TODO(b/285855436): should be mounted on top of dm-verity device.
static Result<Fstab> ReadFirstStageFstabMicrodroid(const std::string& cmdline) {
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return Error() << "failed to read fstab";
    }
    if (cmdline.find("androidboot.microdroid.mount_vendor=1") == std::string::npos) {
        // We weren't asked to mount /vendor partition, filter it out from the fstab.
        auto predicate = [](const auto& entry) { return entry.mount_point == "/vendor"; };
        fstab.erase(std::remove_if(fstab.begin(), fstab.end(), predicate), fstab.end());
    }
    return fstab;
}

Result<std::unique_ptr<FirstStageMount>> FirstStageMount::Create(const std::string& cmdline) {
    Result<Fstab> fstab = ReadFirstStageFstabMicrodroid(cmdline);
    if (!fstab.ok()) {
        return fstab.error();
    }

    return std::make_unique<FirstStageMount>(std::move(*fstab));
}

void SetInitAvbVersionInRecovery() {}

}  // namespace init
}  // namespace android
