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

#ifndef __CORE_FS_MGR_AVB_H
#define __CORE_FS_MGR_AVB_H

#include <memory>
#include <string>

#include <libavb/libavb.h>

#include "fs_mgr.h"

enum FsManagerAvbHandleStatus {
    kFsManagerAvbHandleUninitialized = -1,
    kFsManagerAvbHandleSuccess = 0,
    kFsManagerAvbHandleHashtreeDisabled = 1,
    kFsManagerAvbHandleErrorVerification = 2,
};

class FsManagerAvbHandle;
using FsManagerAvbUniquePtr = std::unique_ptr<FsManagerAvbHandle>;

// Provides a factory method to return a unique_ptr pointing to itself and the
// SetUpAvb() function to extract dm-verity parameters from AVB metadata to
// load verity table into kernel through ioctl.
class FsManagerAvbHandle {
  public:
    // The factory method to return a FsManagerAvbUniquePtr that holds
    // the verified AVB (external/avb) metadata of all verified partitions
    // in avb_slot_data_.vbmeta_images[].
    //
    // The metadata is checked against the following values from /proc/cmdline.
    //   - androidboot.vbmeta.{hash_alg, size, digest}.
    //
    // A typical usage will be:
    //   - FsManagerAvbUniquePtr handle = FsManagerAvbHandle::Open();
    //
    // Possible return values:
    //   - nullptr: any error when reading and verifying the metadata,
    //     e.g., I/O error, digest value mismatch, size mismatch, etc.
    //
    //   - a valid unique_ptr with status kFsMgrAvbHandleHashtreeDisabled:
    //     to support the existing 'adb disable-verity' feature in Android.
    //     It's very helpful for developers to make the filesystem writable to
    //     allow replacing binaries on the device.
    //
    //   - a valid unique_ptr with status kFsMgrAvbHandleSuccess: the metadata
    //     is verified and can be trusted.
    //
    static FsManagerAvbUniquePtr Open(const std::string& device_file_by_name_prefix);

    // Sets up dm-verity on the given fstab entry.
    // The 'wait_for_verity_dev' parameter makes this function wait for the
    // verity device to get created before return.
    // Returns true if the mount point is eligible to mount, it includes:
    //   - status_ is kFsMgrAvbHandleHashtreeDisabled or
    //   - status_ is kFsMgrAvbHandleSuccess and sending ioctl DM_TABLE_LOAD
    //     to load verity table is success.
    // Otherwise, returns false.
    bool SetUpAvb(fstab_rec* fstab_entry, bool wait_for_verity_dev);

    bool hashtree_disabled() const { return status_ == kFsManagerAvbHandleHashtreeDisabled; }
    const std::string& avb_version() const { return avb_version_; }

    FsManagerAvbHandle(const FsManagerAvbHandle&) = delete;             // no copy
    FsManagerAvbHandle& operator=(const FsManagerAvbHandle&) = delete;  // no assignment

    FsManagerAvbHandle(FsManagerAvbHandle&&) noexcept = delete;             // no move
    FsManagerAvbHandle& operator=(FsManagerAvbHandle&&) noexcept = delete;  // no move assignment

    ~FsManagerAvbHandle() {
        if (avb_slot_data_) {
            avb_slot_verify_data_free(avb_slot_data_);
        }
    };

  protected:
    FsManagerAvbHandle() : avb_slot_data_(nullptr), status_(kFsManagerAvbHandleUninitialized) {}

  private:
    AvbSlotVerifyData* avb_slot_data_;
    FsManagerAvbHandleStatus status_;
    std::string avb_version_;
};

#endif /* __CORE_FS_MGR_AVB_H */
