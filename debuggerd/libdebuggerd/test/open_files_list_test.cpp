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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

#include <errno.h>
#include <linux/bpf.h>
#include <sys/syscall.h>

#include <android-base/file.h>
#include <gtest/gtest.h>

#include "libdebuggerd/open_files_list.h"

// Check that we can produce a list of open files for the current process, and
// that it includes a known open file.
TEST(OpenFilesListTest, BasicTest) {
  // Open a temporary file that we can check for in the list of open files.
  TemporaryFile tf;

  // Get the list of open files for this process.
  OpenFilesList list;
  populate_open_files_list(&list, getpid());

  // Verify our open file is in the list.
  bool found = false;
  for (auto& file : list) {
    if (file.first == tf.fd) {
      EXPECT_EQ(file.second.path.value_or(""), std::string(tf.path));
      found = true;
      break;
    }
  }
  EXPECT_TRUE(found);
}

// Check that we can correctly identify and extract details for BPF program file descriptors.
TEST(OpenFilesListTest, BpfProgTest) {
  // Create a simple BPF program to test the extraction of its details.
  struct bpf_insn insns[2] = {{.code = BPF_ALU64 | BPF_MOV | BPF_K}, {.code = BPF_JMP | BPF_EXIT}};
  union bpf_attr attr = {.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
                         .insns = reinterpret_cast<uint64_t>(insns),
                         .insn_cnt = 2,
                         .license = reinterpret_cast<uint64_t>(insns)};
  int fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  EXPECT_GE(fd, 0) << "Failed to load BPF program: " << strerrorname_np(errno);

  OpenFilesList list;
  populate_open_files_list(&list, getpid());
  close(fd);

  EXPECT_TRUE(list.contains(fd)) << "BPF program not found in open files.";
  EXPECT_TRUE(list[fd].path.has_value()) << "BPF path not found.";
  EXPECT_EQ("anon_inode:bpf-prog", list[fd].path.value());
  EXPECT_TRUE(list[fd].details.has_value()) << "BPF program details not found.";
  // The prog id is not guaranteed to be the same on every run, so only look for the name.
  EXPECT_TRUE(list[fd].details.value().starts_with("prog_id: "))
      << "BPF details not correct: expected starts with: 'prog_id:' actual: '"
      << list[fd].details.value() << "'";
}
