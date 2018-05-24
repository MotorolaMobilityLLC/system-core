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

#pragma once

#include <unistd.h>

#include <android-base/unique_fd.h>

// Helper to automatically close an FD when it goes out of scope.
struct AdbCloser {
    static void Close(int fd);
};

using unique_fd = android::base::unique_fd_impl<AdbCloser>;

#if !defined(_WIN32)
inline bool Pipe(unique_fd* read, unique_fd* write) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return false;
    }
    read->reset(pipefd[0]);
    write->reset(pipefd[1]);
    return true;
}
#endif
