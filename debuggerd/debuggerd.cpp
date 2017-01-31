/*
 * Copyright 2016, The Android Open Source Project
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/unique_fd.h>
#include <debuggerd/client.h>
#include <debuggerd/util.h>
#include <selinux/selinux.h>

using android::base::unique_fd;

static void usage(int exit_code) {
  fprintf(stderr, "usage: debuggerd [-b] PID\n");
  _exit(exit_code);
}

static std::thread spawn_redirect_thread(unique_fd fd) {
  return std::thread([fd{ std::move(fd) }]() {
    while (true) {
      char buf[BUFSIZ];
      ssize_t rc = TEMP_FAILURE_RETRY(read(fd.get(), buf, sizeof(buf)));
      if (rc <= 0) {
        return;
      }

      if (!android::base::WriteFully(STDOUT_FILENO, buf, rc)) {
        return;
      }
    }
  });
}

int main(int argc, char* argv[]) {
  if (argc <= 1) usage(0);
  if (argc > 3) usage(1);
  if (argc == 3 && strcmp(argv[1], "-b") != 0) usage(1);

  pid_t pid;
  if (!android::base::ParseInt(argv[argc - 1], &pid, 1, std::numeric_limits<pid_t>::max())) {
    usage(1);
  }

  unique_fd piperead, pipewrite;
  if (!Pipe(&piperead, &pipewrite)) {
    err(1, "failed to create pipe");
  }

  std::thread redirect_thread = spawn_redirect_thread(std::move(piperead));
  bool backtrace = argc == 3;
  if (!debuggerd_trigger_dump(pid, std::move(pipewrite),
                              backtrace ? kDebuggerdBacktrace : kDebuggerdTombstone, 0)) {
    redirect_thread.join();
    errx(1, "failed to dump process %d", pid);
  }

  redirect_thread.join();
  return 0;
}
