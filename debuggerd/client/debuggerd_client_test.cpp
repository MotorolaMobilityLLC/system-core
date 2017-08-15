/*
 * Copyright 2017, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <debuggerd/client.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <chrono>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include <debuggerd/util.h>

using namespace std::chrono_literals;
using android::base::unique_fd;

TEST(debuggerd_client, race) {
  static constexpr int THREAD_COUNT = 1024;
  pid_t forkpid = fork();

  ASSERT_NE(-1, forkpid);

  if (forkpid == 0) {
    // Spawn a bunch of threads, to make crash_dump take longer.
    std::vector<std::thread> threads;
    for (int i = 0; i < THREAD_COUNT; ++i) {
      threads.emplace_back([]() {
        while (true) {
          std::this_thread::sleep_for(60s);
        }
      });
    }

    std::this_thread::sleep_for(60s);
    exit(0);
  }

  unique_fd pipe_read, pipe_write;
  ASSERT_TRUE(Pipe(&pipe_read, &pipe_write));

  // 64 kB should be enough for everyone.
  constexpr int PIPE_SIZE = 64 * 1024 * 1024;
  ASSERT_EQ(PIPE_SIZE, fcntl(pipe_read.get(), F_SETPIPE_SZ, PIPE_SIZE));

  // Wait for a bit to let the child spawn all of its threads.
  std::this_thread::sleep_for(250ms);

  ASSERT_TRUE(debuggerd_trigger_dump(forkpid, std::move(pipe_write), kDebuggerdBacktrace, 10000));
  // Immediately kill the forked child, to make sure that the dump didn't return early.
  ASSERT_EQ(0, kill(forkpid, SIGKILL)) << strerror(errno);

  // Check the output.
  std::string result;
  ASSERT_TRUE(android::base::ReadFdToString(pipe_read.get(), &result));

  // Look for "----- end <PID> -----"
  int found_end = 0;

  std::string expected_end = android::base::StringPrintf("----- end %d -----", forkpid);

  std::vector<std::string> lines = android::base::Split(result, "\n");
  for (const std::string& line : lines) {
    if (line == expected_end) {
      ++found_end;
    }
  }

  EXPECT_EQ(1, found_end) << "\nOutput: \n" << result;
}

TEST(debuggerd_client, no_timeout) {
  unique_fd pipe_read, pipe_write;
  ASSERT_TRUE(Pipe(&pipe_read, &pipe_write));

  pid_t forkpid = fork();
  ASSERT_NE(-1, forkpid);
  if (forkpid == 0) {
    pipe_write.reset();
    char dummy;
    TEMP_FAILURE_RETRY(read(pipe_read.get(), &dummy, sizeof(dummy)));
    exit(0);
  }

  pipe_read.reset();

  unique_fd output_read, output_write;
  ASSERT_TRUE(Pipe(&output_read, &output_write));
  ASSERT_TRUE(debuggerd_trigger_dump(forkpid, std::move(output_write), kDebuggerdBacktrace, 0));
}
