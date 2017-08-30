/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include <android-base/file.h>
#include <android-base/test_utils.h>
#include <gtest/gtest.h>

#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Memory.h>

namespace unwindstack {

class MapInfoCreateMemoryTest : public ::testing::Test {
 protected:
  template <typename Ehdr, typename Shdr>
  static void InitElf(int fd, uint64_t file_offset, uint64_t sh_offset, uint8_t class_type) {
    std::vector<uint8_t> buffer(20000);
    memset(buffer.data(), 0, buffer.size());

    Ehdr ehdr;
    memset(&ehdr, 0, sizeof(ehdr));
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS] = class_type;
    ehdr.e_shoff = sh_offset;
    ehdr.e_shentsize = sizeof(Shdr) + 100;
    ehdr.e_shnum = 4;
    memcpy(&buffer[file_offset], &ehdr, sizeof(ehdr));

    ASSERT_TRUE(android::base::WriteFully(fd, buffer.data(), buffer.size()));
  }

  static void SetUpTestCase() {
    std::vector<uint8_t> buffer(1024);
    memset(buffer.data(), 0, buffer.size());
    memcpy(buffer.data(), ELFMAG, SELFMAG);
    buffer[EI_CLASS] = ELFCLASS32;
    ASSERT_TRUE(android::base::WriteFully(elf_.fd, buffer.data(), buffer.size()));

    memset(buffer.data(), 0, buffer.size());
    memcpy(&buffer[0x100], ELFMAG, SELFMAG);
    buffer[0x100 + EI_CLASS] = ELFCLASS64;
    ASSERT_TRUE(android::base::WriteFully(elf_at_100_.fd, buffer.data(), buffer.size()));

    InitElf<Elf32_Ehdr, Elf32_Shdr>(elf32_at_map_.fd, 0x1000, 0x2000, ELFCLASS32);
    InitElf<Elf64_Ehdr, Elf64_Shdr>(elf64_at_map_.fd, 0x2000, 0x3000, ELFCLASS64);
  }

  static TemporaryFile elf_;

  static TemporaryFile elf_at_100_;

  static TemporaryFile elf32_at_map_;
  static TemporaryFile elf64_at_map_;
};
TemporaryFile MapInfoCreateMemoryTest::elf_;
TemporaryFile MapInfoCreateMemoryTest::elf_at_100_;
TemporaryFile MapInfoCreateMemoryTest::elf32_at_map_;
TemporaryFile MapInfoCreateMemoryTest::elf64_at_map_;

TEST_F(MapInfoCreateMemoryTest, end_le_start) {
  MapInfo info{.start = 0x100, .end = 0x100, .offset = 0, .name = elf_.path};

  std::unique_ptr<Memory> memory;
  memory.reset(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() == nullptr);

  info.end = 0xff;
  memory.reset(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() == nullptr);

  // Make sure this test is valid.
  info.end = 0x101;
  memory.reset(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() != nullptr);
}

// Verify that if the offset is non-zero but there is no elf at the offset,
// that the full file is used.
TEST_F(MapInfoCreateMemoryTest, file_backed_non_zero_offset_full_file) {
  MapInfo info{.start = 0x100, .end = 0x200, .offset = 0x100, .name = elf_.path};

  std::unique_ptr<Memory> memory(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() != nullptr);
  ASSERT_EQ(0x100U, info.elf_offset);

  // Read the entire file.
  std::vector<uint8_t> buffer(1024);
  ASSERT_TRUE(memory->Read(0, buffer.data(), 1024));
  ASSERT_TRUE(memcmp(buffer.data(), ELFMAG, SELFMAG) == 0);
  ASSERT_EQ(ELFCLASS32, buffer[EI_CLASS]);
  for (size_t i = EI_CLASS + 1; i < buffer.size(); i++) {
    ASSERT_EQ(0, buffer[i]) << "Failed at byte " << i;
  }

  ASSERT_FALSE(memory->Read(1024, buffer.data(), 1));
}

// Verify that if the offset is non-zero and there is an elf at that
// offset, that only part of the file is used.
TEST_F(MapInfoCreateMemoryTest, file_backed_non_zero_offset_partial_file) {
  MapInfo info{.start = 0x100, .end = 0x200, .offset = 0x100, .name = elf_at_100_.path};

  std::unique_ptr<Memory> memory(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() != nullptr);
  ASSERT_EQ(0U, info.elf_offset);

  // Read the valid part of the file.
  std::vector<uint8_t> buffer(0x100);
  ASSERT_TRUE(memory->Read(0, buffer.data(), 0x100));
  ASSERT_TRUE(memcmp(buffer.data(), ELFMAG, SELFMAG) == 0);
  ASSERT_EQ(ELFCLASS64, buffer[EI_CLASS]);
  for (size_t i = EI_CLASS + 1; i < buffer.size(); i++) {
    ASSERT_EQ(0, buffer[i]) << "Failed at byte " << i;
  }

  ASSERT_FALSE(memory->Read(0x100, buffer.data(), 1));
}

// Verify that if the offset is non-zero and there is an elf at that
// offset, that only part of the file is used. Further verify that if the
// embedded elf is bigger than the initial map, the new object is larger
// than the original map size. Do this for a 32 bit elf and a 64 bit elf.
TEST_F(MapInfoCreateMemoryTest, file_backed_non_zero_offset_partial_file_whole_elf32) {
  MapInfo info{.start = 0x5000, .end = 0x6000, .offset = 0x1000, .name = elf32_at_map_.path};

  std::unique_ptr<Memory> memory(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() != nullptr);
  ASSERT_EQ(0U, info.elf_offset);

  // Verify the memory is a valid elf.
  uint8_t e_ident[SELFMAG + 1];
  ASSERT_TRUE(memory->Read(0, e_ident, SELFMAG));
  ASSERT_EQ(0, memcmp(e_ident, ELFMAG, SELFMAG));

  // Read past the end of what would normally be the size of the map.
  ASSERT_TRUE(memory->Read(0x1000, e_ident, 1));
}

TEST_F(MapInfoCreateMemoryTest, file_backed_non_zero_offset_partial_file_whole_elf64) {
  MapInfo info{.start = 0x7000, .end = 0x8000, .offset = 0x2000, .name = elf64_at_map_.path};

  std::unique_ptr<Memory> memory(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() != nullptr);
  ASSERT_EQ(0U, info.elf_offset);

  // Verify the memory is a valid elf.
  uint8_t e_ident[SELFMAG + 1];
  ASSERT_TRUE(memory->Read(0, e_ident, SELFMAG));
  ASSERT_EQ(0, memcmp(e_ident, ELFMAG, SELFMAG));

  // Read past the end of what would normally be the size of the map.
  ASSERT_TRUE(memory->Read(0x1000, e_ident, 1));
}

// Verify that device file names will never result in Memory object creation.
TEST_F(MapInfoCreateMemoryTest, check_device_maps) {
  // Set up some memory so that a valid local memory object would
  // be returned if the file mapping fails, but the device check is incorrect.
  std::vector<uint8_t> buffer(1024);
  MapInfo info;
  info.start = reinterpret_cast<uint64_t>(buffer.data());
  info.end = info.start + buffer.size();
  info.offset = 0;
  std::unique_ptr<Memory> memory;

  info.flags = 0x8000;
  info.name = "/dev/something";
  memory.reset(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() == nullptr);
}

TEST_F(MapInfoCreateMemoryTest, local_memory) {
  // Set up some memory for a valid local memory object.
  std::vector<uint8_t> buffer(1024);
  for (size_t i = 0; i < buffer.size(); i++) {
    buffer[i] = i % 256;
  }

  MapInfo info;
  info.start = reinterpret_cast<uint64_t>(buffer.data());
  info.end = info.start + buffer.size();
  info.offset = 0;

  std::unique_ptr<Memory> memory;
  memory.reset(info.CreateMemory(getpid()));
  ASSERT_TRUE(memory.get() != nullptr);

  std::vector<uint8_t> read_buffer(1024);
  ASSERT_TRUE(memory->Read(0, read_buffer.data(), read_buffer.size()));
  for (size_t i = 0; i < read_buffer.size(); i++) {
    ASSERT_EQ(i % 256, read_buffer[i]) << "Failed at byte " << i;
  }

  ASSERT_FALSE(memory->Read(read_buffer.size(), read_buffer.data(), 1));
}

TEST_F(MapInfoCreateMemoryTest, remote_memory) {
  std::vector<uint8_t> buffer(1024);
  memset(buffer.data(), 0xa, buffer.size());

  pid_t pid;
  if ((pid = fork()) == 0) {
    while (true)
      ;
    exit(1);
  }
  ASSERT_LT(0, pid);

  ASSERT_TRUE(ptrace(PTRACE_ATTACH, pid, 0, 0) != -1);
  uint64_t iterations = 0;
  siginfo_t si;
  while (TEMP_FAILURE_RETRY(ptrace(PTRACE_GETSIGINFO, pid, 0, &si)) < 0 && errno == ESRCH) {
    usleep(30);
    iterations++;
    ASSERT_LT(iterations, 500000000ULL);
  }

  MapInfo info;
  info.start = reinterpret_cast<uint64_t>(buffer.data());
  info.end = info.start + buffer.size();
  info.offset = 0;

  std::unique_ptr<Memory> memory;
  memory.reset(info.CreateMemory(pid));
  ASSERT_TRUE(memory.get() != nullptr);
  // Set the local memory to a different value to guarantee we are reading
  // from the remote process.
  memset(buffer.data(), 0x1, buffer.size());
  std::vector<uint8_t> read_buffer(1024);
  ASSERT_TRUE(memory->Read(0, read_buffer.data(), read_buffer.size()));
  for (size_t i = 0; i < read_buffer.size(); i++) {
    ASSERT_EQ(0xaU, read_buffer[i]) << "Failed at byte " << i;
  }

  ASSERT_TRUE(ptrace(PTRACE_DETACH, pid, 0, 0) == 0);

  kill(pid, SIGKILL);
  ASSERT_EQ(pid, wait(nullptr));
}

}  // namespace unwindstack
