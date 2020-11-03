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

#include <memory>
#include <optional>
#include <string>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_format.h>
#include <libsnapshot/cow_reader.h>

namespace android {
namespace snapshot {

struct CowOptions {
    uint32_t block_size = 4096;
    std::string compression;

    // Maximum number of blocks that can be written.
    std::optional<uint64_t> max_blocks;
};

// Interface for writing to a snapuserd COW. All operations are ordered; merges
// will occur in the sequence they were added to the COW.
class ICowWriter {
  public:
    explicit ICowWriter(const CowOptions& options) : options_(options) {}

    virtual ~ICowWriter() {}

    // Encode an operation that copies the contents of |old_block| to the
    // location of |new_block|.
    bool AddCopy(uint64_t new_block, uint64_t old_block);

    // Encode a sequence of raw blocks. |size| must be a multiple of the block size.
    bool AddRawBlocks(uint64_t new_block_start, const void* data, size_t size);

    // Encode a sequence of zeroed blocks. |size| must be a multiple of the block size.
    bool AddZeroBlocks(uint64_t new_block_start, uint64_t num_blocks);

    // Add a label to the op sequence.
    bool AddLabel(uint64_t label);

    // Flush all pending writes. This must be called before closing the writer
    // to ensure that the correct headers and footers are written.
    virtual bool Finalize() = 0;

    // Return number of bytes the cow image occupies on disk.
    virtual uint64_t GetCowSize() = 0;

    // Returns true if AddCopy() operations are supported.
    virtual bool SupportsCopyOperation() const { return true; }

    const CowOptions& options() { return options_; }

  protected:
    virtual bool EmitCopy(uint64_t new_block, uint64_t old_block) = 0;
    virtual bool EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) = 0;
    virtual bool EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) = 0;
    virtual bool EmitLabel(uint64_t label) = 0;

    bool ValidateNewBlock(uint64_t new_block);

  protected:
    CowOptions options_;
};

class CowWriter : public ICowWriter {
  public:
    enum class OpenMode { WRITE, APPEND };

    explicit CowWriter(const CowOptions& options);

    // Set up the writer.
    // If opening for write, the file starts from the beginning.
    // If opening for append, if the file has a footer, we start appending to the last op.
    // If the footer isn't found, the last label is considered corrupt, and dropped.
    bool Initialize(android::base::unique_fd&& fd, OpenMode mode = OpenMode::WRITE);
    bool Initialize(android::base::borrowed_fd fd, OpenMode mode = OpenMode::WRITE);
    // Set up a writer, assuming that the given label is the last valid label.
    // This will result in dropping any labels that occur after the given on, and will fail
    // if the given label does not appear.
    bool InitializeAppend(android::base::unique_fd&&, uint64_t label);
    bool InitializeAppend(android::base::borrowed_fd fd, uint64_t label);

    bool Finalize() override;

    uint64_t GetCowSize() override;

  protected:
    virtual bool EmitCopy(uint64_t new_block, uint64_t old_block) override;
    virtual bool EmitRawBlocks(uint64_t new_block_start, const void* data, size_t size) override;
    virtual bool EmitZeroBlocks(uint64_t new_block_start, uint64_t num_blocks) override;
    virtual bool EmitLabel(uint64_t label) override;

  private:
    void SetupHeaders();
    bool ParseOptions();
    bool OpenForWrite();
    bool OpenForAppend(std::optional<uint64_t> label = std::nullopt);
    bool GetDataPos(uint64_t* pos);
    bool WriteRawData(const void* data, size_t size);
    bool WriteOperation(const CowOperation& op, const void* data = nullptr, size_t size = 0);
    void AddOperation(const CowOperation& op);
    std::basic_string<uint8_t> Compress(const void* data, size_t length);

  private:
    android::base::unique_fd owned_fd_;
    android::base::borrowed_fd fd_;
    CowHeader header_{};
    CowFooter footer_{};
    int compression_ = 0;
    uint64_t next_op_pos_ = 0;

    // :TODO: this is not efficient, but stringstream ubsan aborts because some
    // bytes overflow a signed char.
    std::basic_string<uint8_t> ops_;
};

}  // namespace snapshot
}  // namespace android
