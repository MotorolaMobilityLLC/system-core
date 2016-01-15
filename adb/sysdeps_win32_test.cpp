/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <gtest/gtest.h>

#include "sysdeps.h"

#include <android-base/test_utils.h>

TEST(sysdeps_win32, adb_getenv) {
    // Insert all test env vars before first call to adb_getenv() which will
    // read the env var block only once.
    ASSERT_EQ(0, _putenv("SYSDEPS_WIN32_TEST_UPPERCASE=1"));
    ASSERT_EQ(0, _putenv("sysdeps_win32_test_lowercase=2"));
    ASSERT_EQ(0, _putenv("Sysdeps_Win32_Test_MixedCase=3"));

    // UTF-16 value
    ASSERT_EQ(0, _wputenv(L"SYSDEPS_WIN32_TEST_UNICODE=\u00a1\u0048\u006f\u006c"
                          L"\u0061\u0021\u03b1\u03b2\u03b3\u0061\u006d\u0062"
                          L"\u0075\u006c\u014d\u043f\u0440\u0438\u0432\u0435"
                          L"\u0442"));

    // Search for non-existant env vars.
    EXPECT_STREQ(nullptr, adb_getenv("SYSDEPS_WIN32_TEST_NONEXISTANT"));

    // Search for existing env vars.

    // There is no test for an env var with a value of a zero-length string
    // because _putenv() does not support inserting such an env var.

    // Search for env var that is uppercase.
    EXPECT_STREQ("1", adb_getenv("SYSDEPS_WIN32_TEST_UPPERCASE"));
    EXPECT_STREQ("1", adb_getenv("sysdeps_win32_test_uppercase"));
    EXPECT_STREQ("1", adb_getenv("Sysdeps_Win32_Test_Uppercase"));

    // Search for env var that is lowercase.
    EXPECT_STREQ("2", adb_getenv("SYSDEPS_WIN32_TEST_LOWERCASE"));
    EXPECT_STREQ("2", adb_getenv("sysdeps_win32_test_lowercase"));
    EXPECT_STREQ("2", adb_getenv("Sysdeps_Win32_Test_Lowercase"));

    // Search for env var that is mixed-case.
    EXPECT_STREQ("3", adb_getenv("SYSDEPS_WIN32_TEST_MIXEDCASE"));
    EXPECT_STREQ("3", adb_getenv("sysdeps_win32_test_mixedcase"));
    EXPECT_STREQ("3", adb_getenv("Sysdeps_Win32_Test_MixedCase"));

    // Check that UTF-16 was converted to UTF-8.
    EXPECT_STREQ("\xc2\xa1\x48\x6f\x6c\x61\x21\xce\xb1\xce\xb2\xce\xb3\x61\x6d"
                 "\x62\x75\x6c\xc5\x8d\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5"
                 "\xd1\x82",
                 adb_getenv("SYSDEPS_WIN32_TEST_UNICODE"));

    // Check an env var that should always be set.
    const char* path_val = adb_getenv("PATH");
    EXPECT_NE(nullptr, path_val);
    if (path_val != nullptr) {
        EXPECT_GT(strlen(path_val), 0U);
    }
}

void TestAdbStrError(int err, const char* expected) {
    errno = 12345;
    const char* result = adb_strerror(err);
    // Check that errno is not overwritten.
    EXPECT_EQ(12345, errno);
    EXPECT_STREQ(expected, result);
}

TEST(sysdeps_win32, adb_strerror) {
    // Test an error code that should not have a mapped string. Use an error
    // code that is not used by the internal implementation of adb_strerror().
    TestAdbStrError(-2, "Unknown error");
    // adb_strerror() uses -1 internally, so test that it can still be passed
    // as a parameter.
    TestAdbStrError(-1, "Unknown error");
    // Test very big, positive unknown error.
    TestAdbStrError(1000000, "Unknown error");
    // Test success case.
    TestAdbStrError(0, "No error");
    // Test error that regular strerror() should have a string for.
    TestAdbStrError(EPERM, "Operation not permitted");
    // Test error that regular strerror() doesn't have a string for, but that
    // adb_strerror() returns.
    TestAdbStrError(ECONNRESET, "Connection reset by peer");
}

TEST(sysdeps_win32, unix_isatty) {
    // stdin and stdout should be consoles. Use CONIN$ and CONOUT$ special files
    // so that we can test this even if stdin/stdout have been redirected. Read
    // permissions are required for unix_isatty().
    int conin_fd = unix_open("CONIN$", O_RDONLY);
    int conout_fd = unix_open("CONOUT$", O_RDWR);
    for (const int fd : {conin_fd, conout_fd}) {
        EXPECT_TRUE(fd >= 0);
        EXPECT_EQ(1, unix_isatty(fd));
        EXPECT_EQ(0, unix_close(fd));
    }

    // nul returns 1 from isatty(), make sure unix_isatty() corrects that.
    for (auto flags : {O_RDONLY, O_RDWR}) {
        int nul_fd = unix_open("nul", flags);
        EXPECT_TRUE(nul_fd >= 0);
        EXPECT_EQ(0, unix_isatty(nul_fd));
        EXPECT_EQ(0, unix_close(nul_fd));
    }

    // Check a real file, both read-write and read-only.
    TemporaryFile temp_file;
    EXPECT_TRUE(temp_file.fd >= 0);
    EXPECT_EQ(0, unix_isatty(temp_file.fd));

    int temp_file_ro_fd = unix_open(temp_file.path, O_RDONLY);
    EXPECT_TRUE(temp_file_ro_fd >= 0);
    EXPECT_EQ(0, unix_isatty(temp_file_ro_fd));
    EXPECT_EQ(0, unix_close(temp_file_ro_fd));

    // Check a real OS pipe.
    int pipe_fds[2];
    EXPECT_EQ(0, _pipe(pipe_fds, 64, _O_BINARY));
    EXPECT_EQ(0, unix_isatty(pipe_fds[0]));
    EXPECT_EQ(0, unix_isatty(pipe_fds[1]));
    EXPECT_EQ(0, _close(pipe_fds[0]));
    EXPECT_EQ(0, _close(pipe_fds[1]));

    // Make sure an invalid FD is handled correctly.
    EXPECT_EQ(0, unix_isatty(-1));
}
