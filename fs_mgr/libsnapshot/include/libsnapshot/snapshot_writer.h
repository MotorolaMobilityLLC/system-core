// Copyright (C) 2020 The Android Open Source Project
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

#include <optional>

#include <android-base/unique_fd.h>

#include <libsnapshot/cow_writer.h>

namespace chromeos_update_engine {
class FileDescriptor;
}  // namespace chromeos_update_engine

namespace android {
namespace snapshot {

class ISnapshotWriter : public ICowWriter {
  public:
    using FileDescriptor = chromeos_update_engine::FileDescriptor;

    explicit ISnapshotWriter(const CowOptions& options);

    // Set the source device. This is used for AddCopy() operations, if the
    // underlying writer needs the original bytes (for example if backed by
    // dm-snapshot or if writing directly to an unsnapshotted region). The
    // device is only opened on the first operation that requires it.
    void SetSourceDevice(const std::string& source_device);

    // Open the writer in write mode (no append).
    virtual bool Initialize() = 0;

    // Open the writer in append mode, with the last label to resume
    // from. See CowWriter::InitializeAppend.
    virtual bool InitializeAppend(uint64_t label) = 0;

    virtual std::unique_ptr<FileDescriptor> OpenReader() = 0;

  protected:
    android::base::borrowed_fd GetSourceFd();

    std::optional<std::string> source_device_;

  private:
    android::base::unique_fd source_fd_;
};

// Send writes to a COW or a raw device directly, based on a threshold.
class CompressedSnapshotWriter : public ISnapshotWriter {
  public:
    CompressedSnapshotWriter(const CowOptions& options);

    // Sets the COW device; this is required.
    bool SetCowDevice(android::base::unique_fd&& cow_device);

    bool Initialize() override;
    bool InitializeAppend(uint64_t label) override;
    bool Finalize() override;
    uint64_t GetCowSize() override;
    std::unique_ptr<FileDescriptor> OpenReader() override;

  protected:
    bool EmitCopy(uint64_t new_block, uint64_t old_block) override;
    bool EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) override;
    bool EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) override;
    bool EmitLabel(uint64_t label) override;

  private:
    android::base::unique_fd cow_device_;

    std::unique_ptr<CowWriter> cow_;
};

// Write directly to a dm-snapshot device.
class OnlineKernelSnapshotWriter : public ISnapshotWriter {
  public:
    OnlineKernelSnapshotWriter(const CowOptions& options);

    // Set the device used for all writes.
    void SetSnapshotDevice(android::base::unique_fd&& snapshot_fd, uint64_t cow_size);

    bool Initialize() override { return true; }
    bool InitializeAppend(uint64_t) override { return true; }

    bool Finalize() override;
    uint64_t GetCowSize() override { return cow_size_; }
    std::unique_ptr<FileDescriptor> OpenReader() override;

  protected:
    bool EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) override;
    bool EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) override;
    bool EmitCopy(uint64_t new_block, uint64_t old_block) override;
    bool EmitLabel(uint64_t label) override;

  private:
    android::base::unique_fd snapshot_fd_;
    uint64_t cow_size_ = 0;
};

}  // namespace snapshot
}  // namespace android
