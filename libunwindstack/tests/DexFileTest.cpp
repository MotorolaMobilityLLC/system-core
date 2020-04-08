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

#include <malloc.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <unordered_map>

#include <MemoryLocal.h>
#include <android-base/file.h>
#include <gtest/gtest.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Memory.h>

#include "DexFile.h"
#include "DexFileData.h"
#include "MemoryFake.h"

namespace unwindstack {

TEST(DexFileTest, from_file_open_non_exist) {
  EXPECT_TRUE(DexFileFromFile::Create(0, "/file/does/not/exist") == nullptr);
}

TEST(DexFileTest, from_file_open_too_small) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_EQ(size_t{10}, static_cast<size_t>(TEMP_FAILURE_RETRY(write(tf.fd, kDexData, 10))));

  // Header too small.
  EXPECT_TRUE(DexFileFromFile::Create(0, tf.path) == nullptr);

  // Header correct, file too small.
  ASSERT_EQ(0, lseek(tf.fd, 0, SEEK_SET));
  ASSERT_EQ(sizeof(kDexData) - 1,
            static_cast<size_t>(TEMP_FAILURE_RETRY(write(tf.fd, kDexData, sizeof(kDexData) - 1))));
  EXPECT_TRUE(DexFileFromFile::Create(0, tf.path) == nullptr);
}

TEST(DexFileTest, from_file_open) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_EQ(sizeof(kDexData),
            static_cast<size_t>(TEMP_FAILURE_RETRY(write(tf.fd, kDexData, sizeof(kDexData)))));

  EXPECT_TRUE(DexFileFromFile::Create(0, tf.path) != nullptr);
}

TEST(DexFileTest, from_file_open_non_zero_offset) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_EQ(0x100, lseek(tf.fd, 0x100, SEEK_SET));
  ASSERT_EQ(sizeof(kDexData),
            static_cast<size_t>(TEMP_FAILURE_RETRY(write(tf.fd, kDexData, sizeof(kDexData)))));

  EXPECT_TRUE(DexFileFromFile::Create(0x100, tf.path) != nullptr);
}

static constexpr size_t kNumLeakLoops = 5000;
static constexpr size_t kMaxAllowedLeakBytes = 1024;

static void CheckForLeak(size_t loop, size_t* first_allocated_bytes, size_t* last_allocated_bytes) {
  size_t allocated_bytes = mallinfo().uordblks;
  if (*first_allocated_bytes == 0) {
    *first_allocated_bytes = allocated_bytes;
  } else if (*last_allocated_bytes > *first_allocated_bytes) {
    // Check that the total memory did not increase too much over the first loop.
    ASSERT_LE(*last_allocated_bytes - *first_allocated_bytes, kMaxAllowedLeakBytes)
        << "Failed in loop " << loop << " first_allocated_bytes " << *first_allocated_bytes
        << " last_allocated_bytes " << *last_allocated_bytes;
  }
  *last_allocated_bytes = allocated_bytes;
}

TEST(DexFileTest, from_file_no_leak) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_EQ(sizeof(kDexData),
            static_cast<size_t>(TEMP_FAILURE_RETRY(write(tf.fd, kDexData, sizeof(kDexData)))));

  size_t first_allocated_bytes = 0;
  size_t last_allocated_bytes = 0;
  for (size_t i = 0; i < kNumLeakLoops; i++) {
    EXPECT_TRUE(DexFileFromFile::Create(0, tf.path) != nullptr);
    ASSERT_NO_FATAL_FAILURE(CheckForLeak(i, &first_allocated_bytes, &last_allocated_bytes));
  }
}

TEST(DexFileTest, from_memory_fail_too_small_for_header) {
  MemoryFake memory;

  memory.SetMemory(0x1000, kDexData, 10);

  EXPECT_TRUE(DexFileFromMemory::Create(0x1000, &memory, "", sizeof(kDexData)) == nullptr);
}

TEST(DexFileTest, from_memory_fail_too_small_for_data) {
  MemoryFake memory;

  memory.SetMemory(0x1000, kDexData, sizeof(kDexData) - 2);

  EXPECT_TRUE(DexFileFromMemory::Create(0x1000, &memory, "", sizeof(kDexData)) == nullptr);
}

TEST(DexFileTest, from_memory_open) {
  MemoryFake memory;

  memory.SetMemory(0x1000, kDexData, sizeof(kDexData));

  EXPECT_TRUE(DexFileFromMemory::Create(0x1000, &memory, "", sizeof(kDexData)) != nullptr);
}

TEST(DexFileTest, from_memory_no_leak) {
  MemoryFake memory;

  memory.SetMemory(0x1000, kDexData, sizeof(kDexData));

  size_t first_allocated_bytes = 0;
  size_t last_allocated_bytes = 0;
  for (size_t i = 0; i < kNumLeakLoops; i++) {
    EXPECT_TRUE(DexFileFromMemory::Create(0x1000, &memory, "", sizeof(kDexData)) != nullptr);
    ASSERT_NO_FATAL_FAILURE(CheckForLeak(i, &first_allocated_bytes, &last_allocated_bytes));
  }
}

TEST(DexFileTest, create_using_file) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_EQ(0x500, lseek(tf.fd, 0x500, SEEK_SET));
  ASSERT_EQ(sizeof(kDexData),
            static_cast<size_t>(TEMP_FAILURE_RETRY(write(tf.fd, kDexData, sizeof(kDexData)))));

  MemoryFake memory;
  MapInfo info(nullptr, nullptr, 0, 0x10000, 0, 0x5, tf.path);
  EXPECT_TRUE(DexFile::Create(0x500, &memory, &info) != nullptr);
}

TEST(DexFileTest, create_using_file_non_zero_start) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_EQ(0x500, lseek(tf.fd, 0x500, SEEK_SET));
  ASSERT_EQ(sizeof(kDexData),
            static_cast<size_t>(TEMP_FAILURE_RETRY(write(tf.fd, kDexData, sizeof(kDexData)))));

  MemoryFake memory;
  MapInfo info(nullptr, nullptr, 0x100, 0x10000, 0, 0x5, tf.path);
  EXPECT_TRUE(DexFile::Create(0x600, &memory, &info) != nullptr);
}

TEST(DexFileTest, create_using_file_non_zero_offset) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_EQ(0x500, lseek(tf.fd, 0x500, SEEK_SET));
  ASSERT_EQ(sizeof(kDexData),
            static_cast<size_t>(TEMP_FAILURE_RETRY(write(tf.fd, kDexData, sizeof(kDexData)))));

  MemoryFake memory;
  MapInfo info(nullptr, nullptr, 0x100, 0x10000, 0x200, 0x5, tf.path);
  EXPECT_TRUE(DexFile::Create(0x400, &memory, &info) != nullptr);
}

TEST(DexFileTest, create_using_memory_empty_file) {
  MemoryFake memory;
  memory.SetMemory(0x4000, kDexData, sizeof(kDexData));
  MapInfo info(nullptr, nullptr, 0x100, 0x10000, 0x200, 0x5, "");
  EXPECT_TRUE(DexFile::Create(0x4000, &memory, &info) != nullptr);
}

TEST(DexFileTest, create_using_memory_file_does_not_exist) {
  MemoryFake memory;
  memory.SetMemory(0x4000, kDexData, sizeof(kDexData));
  MapInfo info(nullptr, nullptr, 0x100, 0x10000, 0x200, 0x5, "/does/not/exist");
  EXPECT_TRUE(DexFile::Create(0x4000, &memory, &info) != nullptr);
}

TEST(DexFileTest, create_using_memory_file_is_malformed) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);

  ASSERT_EQ(sizeof(kDexData) - 10,
            static_cast<size_t>(TEMP_FAILURE_RETRY(write(tf.fd, kDexData, sizeof(kDexData) - 10))));

  MemoryFake memory;
  memory.SetMemory(0x4000, kDexData, sizeof(kDexData));
  MapInfo info(nullptr, nullptr, 0x4000, 0x10000, 0x200, 0x5, "/does/not/exist");
  std::unique_ptr<DexFile> dex_file = DexFile::Create(0x4000, &memory, &info);
  ASSERT_TRUE(dex_file != nullptr);

  // Check it came from memory by clearing memory and verifying it fails.
  memory.Clear();
  dex_file = DexFile::Create(0x4000, &memory, &info);
  EXPECT_TRUE(dex_file == nullptr);
}

TEST(DexFileTest, create_using_memory_size_too_small) {
  MemoryFake memory;
  memory.SetMemory(0x4000, kDexData, sizeof(kDexData));
  MapInfo info(nullptr, nullptr, 0x100, sizeof(kDexData) - 2, 0x200, 0x5, "/does/not/exist");
  EXPECT_TRUE(DexFile::Create(0x4000, &memory, &info) != nullptr);
}

class MemoryLocalFake : public MemoryLocal {
 public:
  MemoryLocalFake(size_t memory_size) : backing_(memory_size) {}
  virtual ~MemoryLocalFake() = default;

  void* Data() { return backing_.data(); }

 private:
  std::vector<void*> backing_;
};

TEST(DexFileTest, create_using_local_memory) {
  MemoryLocalFake memory(sizeof(kDexData));

  memcpy(memory.Data(), kDexData, sizeof(kDexData));
  uint64_t start = reinterpret_cast<uint64_t>(memory.Data());
  MapInfo info(nullptr, nullptr, start, start + 0x1000, 0x200, 0x5, "/does/not/exist");
  EXPECT_TRUE(DexFile::Create(start, &memory, &info) != nullptr);
}

TEST(DexFileTest, create_using_local_memory_size_too_small) {
  MemoryLocalFake memory(sizeof(kDexData));

  memcpy(memory.Data(), kDexData, sizeof(kDexData));
  uint64_t start = reinterpret_cast<uint64_t>(memory.Data());
  MapInfo info(nullptr, nullptr, start, start + sizeof(kDexData) - 2, 0x200, 0x5,
               "/does/not/exist");
  EXPECT_TRUE(DexFile::Create(start, &memory, &info) == nullptr);
}

TEST(DexFileTest, get_method) {
  MemoryFake memory;
  memory.SetMemory(0x4000, kDexData, sizeof(kDexData));
  MapInfo info(nullptr, nullptr, 0x100, 0x10000, 0x200, 0x5, "");
  std::unique_ptr<DexFile> dex_file(DexFile::Create(0x4000, &memory, &info));
  ASSERT_TRUE(dex_file != nullptr);

  std::string method;
  uint64_t method_offset;
  ASSERT_TRUE(dex_file->GetMethodInformation(0x102, &method, &method_offset));
  EXPECT_EQ("Main.<init>", method);
  EXPECT_EQ(2U, method_offset);

  ASSERT_TRUE(dex_file->GetMethodInformation(0x118, &method, &method_offset));
  EXPECT_EQ("Main.main", method);
  EXPECT_EQ(0U, method_offset);
}

TEST(DexFileTest, get_method_empty) {
  MemoryFake memory;
  memory.SetMemory(0x4000, kDexData, sizeof(kDexData));
  MapInfo info(nullptr, nullptr, 0x100, 0x10000, 0x200, 0x5, "");
  std::unique_ptr<DexFile> dex_file(DexFile::Create(0x4000, &memory, &info));
  ASSERT_TRUE(dex_file != nullptr);

  std::string method;
  uint64_t method_offset;
  EXPECT_FALSE(dex_file->GetMethodInformation(0x100000, &method, &method_offset));

  EXPECT_FALSE(dex_file->GetMethodInformation(0x98, &method, &method_offset));
}

}  // namespace unwindstack
