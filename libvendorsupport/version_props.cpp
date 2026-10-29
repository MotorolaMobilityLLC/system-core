// Copyright (C) 2024 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "api_level.h"

#include <log/log.h>

#if !defined(__ANDROID_VENDOR__)
#include <android-base/properties.h>
#endif

int AVendorSupport_getVendorApiLevelOf(int sdkApiLevel) {
    if (sdkApiLevel < __ANDROID_API_V__) {
        return sdkApiLevel;
    }
    // In Android V, vendor API level started with version 202404.
    // The calculation assumes that the SDK api level bumps once a year.
    if (sdkApiLevel < __ANDROID_API_FUTURE__) {
        return 202404 + ((sdkApiLevel - __ANDROID_API_V__) * 100);
    }
    ALOGE("The SDK version must be less than 10000: %d", sdkApiLevel);
    return __INVALID_API_LEVEL;
}

int AVendorSupport_getSdkApiLevelOf(int vendorApiLevel) {
    if (vendorApiLevel < __ANDROID_API_V__) {
        return vendorApiLevel;
    }
    if (vendorApiLevel >= 202404 && vendorApiLevel < __ANDROID_VENDOR_API_MAX__) {
        return (vendorApiLevel - 202404) / 100 + __ANDROID_API_V__;
    }
    ALOGE("Unexpected vendor api level: %d", vendorApiLevel);
    return __INVALID_API_LEVEL;
}

#if !defined(__ANDROID_VENDOR__)
int AVendorSupport_getVendorApiLevel() {
    int vendorApiLevel = android::base::GetIntProperty("ro.vndk.version", 0);
    if (vendorApiLevel) {
        if (vendorApiLevel == __ANDROID_API_V__) {
            // We only have ro.vndk.version == 35 in 24Q1(U-QPR2) release.
            // This does not mean the version is bumped up, but we used this as
            // a workaournd to indicate that the VNDK libs are found in the
            // vendor partition.
            // The actual vendor API level still remains at Android U.
            // The next vendor API level of 34 is 202404, not 35.
            return __ANDROID_API_U__;
        }
        return vendorApiLevel;
    }
    return android::base::GetIntProperty("ro.board.api_level", 0);
}

int AVendorSupport_getFirstVendorApiLevel() {
    // `ro.board.first_api_level` is only populated for GRF chipsets.
    // Its numbering scheme is 30, 31, 32, 33, 34, 202404, 202504, etc. so there
    // is no need for conversion using `AVendorSupport_getVendorApiLevelOf`.
    int board_first_api_level = android::base::GetIntProperty("ro.board.first_api_level", -1);
    if (board_first_api_level != -1) {
        return board_first_api_level;
    }

    // `ro.product.first_api_level` is always populated.
    // Its numbering scheme is 30, 31, 32, 33, 34, 35, 36... so it must be converted
    // using `AVendorSupport_getVendorApiLevelOf`.
    int product_first_api_level = android::base::GetIntProperty("ro.product.first_api_level", -1);
    if (product_first_api_level == -1) {
        ALOGE("Could not find ro.product.first_api_level");
        return __INVALID_API_LEVEL;
    }
    return AVendorSupport_getVendorApiLevelOf(product_first_api_level);
}
#endif  // __ANDROID_VENDOR__
