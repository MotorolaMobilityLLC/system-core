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

#pragma once

#include <memory>

#include <fs_avb/fs_avb.h>
#include <fstab/fstab.h>
#include "block_dev_initializer.h"
#include "result.h"

namespace android {
namespace init {

class FirstStageMount {
  protected:
    using AvbUniquePtr = android::fs_mgr::AvbUniquePtr;
    using Fstab = android::fs_mgr::Fstab;
    using FstabEntry = android::fs_mgr::FstabEntry;

  public:
    friend void SetInitAvbVersionInRecovery();

    FirstStageMount(Fstab fstab);
    virtual ~FirstStageMount() = default;

    // The factory method to create a FirstStageMount instance.
    static Result<std::unique_ptr<FirstStageMount>> Create(const std::string& cmdline);

    virtual bool DoCreateDevices();
    bool DoFirstStageMount();

  protected:
    virtual void MountOverlays() {}
    virtual void UseDsuIfPresent() {}
    virtual void SaveRamdiskPathToSnapuserd() {}
    virtual bool AllowVerityCheckAtMostOnce() { return false; }
    virtual void GetExtraBlockDevices(std::set<std::string>*) {}

    bool InitDevices();
    bool InitRequiredDevices(std::set<std::string> devices);
    bool MountPartition(const Fstab::iterator& begin, bool erase_same_mounts,
                        Fstab::iterator* end = nullptr);

    bool MountPartitions();
    bool TrySwitchSystemAsRoot();
    bool IsDmLinearEnabled();
    void GetSuperDeviceName(std::set<std::string>* devices);
    // Reads all fstab.avb_keys from the ramdisk for first-stage mount.
    void PreloadAvbKeys();

    bool GetDmVerityDevices(std::set<std::string>* devices);
    bool SetUpDmVerity(FstabEntry* fstab_entry);

    bool InitAvbHandle();

    Fstab fstab_;
    // The super path is only set after InitDevices, and is invalid before.
    std::string super_path_;
    std::string super_partition_name_;
    BlockDevInitializer block_dev_init_;
    // Reads all AVB keys before chroot into /system, as they might be used
    // later when mounting other partitions, e.g., /vendor and /product.
    std::map<std::string, std::vector<std::string>> preload_avb_key_blobs_;

    std::vector<std::string> vbmeta_partitions_;
    AvbUniquePtr avb_handle_;
};

void SetInitAvbVersionInRecovery();

}  // namespace init
}  // namespace android
