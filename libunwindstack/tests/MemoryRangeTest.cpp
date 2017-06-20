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

#include <stdint.h>
#include <string.h>

#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "Memory.h"

#include "MemoryFake.h"

TEST(MemoryRangeTest, read) {
  std::vector<uint8_t> src(1024);
  memset(src.data(), 0x4c, 1024);
  MemoryFake* memory = new MemoryFake;
  memory->SetMemory(9001, src);

  MemoryRange range(memory, 9001, 9001 + src.size());

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(range.Read(0, dst.data(), src.size()));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]) << "Failed at byte " << i;
  }
}

TEST(MemoryRangeTest, read_near_limit) {
  std::vector<uint8_t> src(4096);
  memset(src.data(), 0x4c, 4096);
  MemoryFake* memory = new MemoryFake;
  memory->SetMemory(1000, src);

  MemoryRange range(memory, 1000, 2024);

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(range.Read(1020, dst.data(), 4));
  for (size_t i = 0; i < 4; i++) {
    ASSERT_EQ(0x4cU, dst[i]) << "Failed at byte " << i;
  }

  // Verify that reads outside of the range will fail.
  ASSERT_FALSE(range.Read(1020, dst.data(), 5));
  ASSERT_FALSE(range.Read(1024, dst.data(), 1));
  ASSERT_FALSE(range.Read(1024, dst.data(), 1024));

  // Verify that reading up to the end works.
  ASSERT_TRUE(range.Read(1020, dst.data(), 4));
}

TEST(MemoryRangeTest, read_overflow) {
  std::vector<uint8_t> buffer(100);

  std::unique_ptr<MemoryRange> overflow(new MemoryRange(new MemoryFakeAlwaysReadZero, 100, 200));
  ASSERT_FALSE(overflow->Read(UINT64_MAX - 10, buffer.data(), 100));
}
