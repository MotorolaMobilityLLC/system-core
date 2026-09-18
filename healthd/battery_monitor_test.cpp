/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <filesystem>

#include "battery_monitor_internal.h"

#include <android-base/file.h>
#include <gtest/gtest.h>

using namespace android;

TEST(BatteryMonitor, SanitizeSerialNumber) {
    ASSERT_EQ(sanitizeSerialNumber("abcd1234"), "ABCD1234");
    ASSERT_EQ(sanitizeSerialNumber("ABCD1234"), "ABCD1234");
    ASSERT_EQ(sanitizeSerialNumber("H+-"), "H2B2D");
}

TEST(BatteryMonitor, GetBooleanField) {
    std::string filename =
            std::filesystem::temp_directory_path().string() + "/GetBooleanField.XXXXXX";
    base::unique_fd f(mkstemp(filename.data()));
    ASSERT_TRUE(f.ok());

    ASSERT_TRUE(base::WriteStringToFd("0\n", f));
    EXPECT_FALSE(getBooleanField(String8(filename)));

    ASSERT_EQ(lseek(f.get(), 0, SEEK_SET), 0);
    ASSERT_TRUE(base::WriteStringToFd("1\n", f));
    EXPECT_TRUE(getBooleanField(String8(filename)));

    // Anything not beginning with '0' is true.
    ASSERT_EQ(lseek(f.get(), 0, SEEK_SET), 0);
    ASSERT_TRUE(base::WriteStringToFd("7654321", f));
    EXPECT_TRUE(getBooleanField(String8(filename)));

    // Failure to read (in this case, something that's not a file) is false.
    EXPECT_FALSE(getBooleanField(String8(".")));
}
