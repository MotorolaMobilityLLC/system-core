/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <cutils/native_handle.h>

#include <gtest/gtest.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#else
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#endif

TEST(native_handle, native_handle_delete) {
    ASSERT_EQ(0, native_handle_delete(nullptr));
}

TEST(native_handle, native_handle_close) {
    ASSERT_EQ(0, native_handle_close(nullptr));
}

TEST(native_handle, native_handle_clone_cloexec) {
    native_handle_t* h = native_handle_create(1, 0);
    ASSERT_NE(nullptr, h);
#if !defined(_WIN32)
    h->data[0] = open("/dev/null", O_RDONLY);
#else
    h->data[0] = _open("NUL", _O_RDONLY);
#endif
    ASSERT_GE(h->data[0], 0);

    native_handle_t* clone = native_handle_clone(h);
    ASSERT_NE(nullptr, clone);
    ASSERT_EQ(1, clone->numFds);

    int fd = clone->data[0];
#if !defined(_WIN32)
    int flags = fcntl(fd, F_GETFD);
    ASSERT_NE(-1, flags);
    EXPECT_TRUE(flags & FD_CLOEXEC);
#else
    DWORD flags = 0;
    HANDLE handle = (HANDLE)_get_osfhandle(fd);
    ASSERT_NE(INVALID_HANDLE_VALUE, handle);
    ASSERT_TRUE(GetHandleInformation(handle, &flags));
    EXPECT_FALSE(flags & HANDLE_FLAG_INHERIT);
#endif

    native_handle_close(clone);
    native_handle_delete(clone);
    native_handle_close(h);
    native_handle_delete(h);
}
