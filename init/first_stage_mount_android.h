//
// Copyright (C) 2017 The Android Open Source Project
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

#pragma once

#include "first_stage_mount.h"

#include <libsnapshot/snapshot.h>

namespace android {
namespace init {

class FirstStageMountAndroid final : public FirstStageMount {
    using SnapshotManager = android::snapshot::SnapshotManager;

  public:
    FirstStageMountAndroid(Fstab fstab, bool data_on_userdata);

    bool DoCreateDevices() override;

  protected:
    void MountOverlays() override;
    void UseDsuIfPresent() override;
    void SaveRamdiskPathToSnapuserd() override;
    bool AllowVerityCheckAtMostOnce() override { return dsu_not_on_userdata_; }
    void GetExtraBlockDevices(std::set<std::string>* devices) override;

  private:
    bool CreateLogicalPartitions();
    bool CreateSnapshotPartitions(SnapshotManager* sm);
    bool InitDmLinearBackingDevices(const android::fs_mgr::LpMetadata& metadata);

    // Copies /avb/*.avbpubkey used for DSU from the ramdisk to /metadata for key
    // revocation check by DSU installation service.
    void CopyDsuAvbKeys();

    bool dsu_not_on_userdata_ = false;
    bool use_snapuserd_ = false;
    bool data_on_userdata_ = false;
};

}  // namespace init
}  // namespace android
