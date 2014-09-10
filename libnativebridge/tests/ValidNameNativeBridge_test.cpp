/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <NativeBridgeTest.h>

namespace android {

static const char* kTestName = "librandom-bridge_not.existing.so";

TEST_F(NativeBridgeTest, ValidName) {
    // Check that the name is acceptable.
    EXPECT_EQ(true, NativeBridgeNameAcceptable(kTestName));

    // Now check what happens on LoadNativeBridge.
    EXPECT_EQ(false, NativeBridgeError());
    LoadNativeBridge(kTestName, nullptr);
    // TODO: Remove this call. b/17440362
    InitializeNativeBridge();
    // This will lead to an error as the library doesn't exist.
    EXPECT_EQ(true, NativeBridgeError());
    // TODO: Test again. b/17440362
//     EXPECT_EQ(false, NativeBridgeAvailable());
}

}  // namespace android
