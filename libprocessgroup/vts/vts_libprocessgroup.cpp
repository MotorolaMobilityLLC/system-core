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

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <optional>
#include <random>
#include <string>

#include <android-base/file.h>
#include <vintf/VintfObject.h>

using android::base::ReadFileToString;
using android::base::WriteStringToFile;
using android::vintf::KernelVersion;
using android::vintf::RuntimeInfo;
using android::vintf::VintfObject;

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace {

const std::string CGROUP_V2_ROOT_PATH = "/sys/fs/cgroup";

std::optional<bool> isMemcgV2Enabled() {
    if (std::string controllers;
        ReadFileToString(CGROUP_V2_ROOT_PATH + "/cgroup.controllers", &controllers)) {
        return controllers.find("memory") != std::string::npos;
    }

    std::cerr << "Error: Could not read " << CGROUP_V2_ROOT_PATH
              << "/cgroup.controllers: " << std::strerror(errno) << std::endl;
    return std::nullopt;
}


}  // anonymous namespace

class MemcgV2SubdirTest : public testing::Test {
protected:
    std::optional<std::string> mRandDir;

    void SetUp() override {
        std::optional<bool> memcgV2Enabled = isMemcgV2Enabled();
        ASSERT_NE(memcgV2Enabled, std::nullopt);
        if (!*memcgV2Enabled) GTEST_SKIP() << "Memcg v2 not enabled";

        mRootSubtreeState = checkRootSubtreeState();
        ASSERT_NE(mRootSubtreeState, std::nullopt);

        if (!*mRootSubtreeState) {
            ASSERT_TRUE(
                    WriteStringToFile("+memory", CGROUP_V2_ROOT_PATH + "/cgroup.subtree_control"))
                    << "Could not enable memcg under root: " << std::strerror(errno);
        }

        // Make a new, temporary, randomly-named v2 cgroup in which we will attempt to activate
        // memcg
        std::random_device rd;
        std::uniform_int_distribution dist(static_cast<int>('A'), static_cast<int>('Z'));
        std::string randName = CGROUP_V2_ROOT_PATH + "/vts_libprocessgroup.";
        for (int i = 0; i < 10; ++i) randName.append(1, static_cast<char>(dist(rd)));
        ASSERT_TRUE(std::filesystem::create_directory(randName));
        mRandDir = randName;  // For cleanup in TearDown

        std::string subtree_controllers;
        ASSERT_TRUE(ReadFileToString(*mRandDir + "/cgroup.controllers", &subtree_controllers));
        ASSERT_NE(subtree_controllers.find("memory"), std::string::npos)
                << "Memcg was not activated in child cgroup";
    }

    void TearDown() override {
        if (mRandDir) {
            if (!std::filesystem::remove(*mRandDir)) {
                std::cerr << "Could not remove temporary memcg v2 test directory" << std::endl;
            }
        }

        if (!*mRootSubtreeState) {
            if (!WriteStringToFile("-memory", CGROUP_V2_ROOT_PATH + "/cgroup.subtree_control")) {
                std::cerr << "Could not disable memcg under root: " << std::strerror(errno)
                          << std::endl;
            }
        }
    }

private:
    static std::optional<bool> checkRootSubtreeState() {
        if (std::string controllers;
            ReadFileToString(CGROUP_V2_ROOT_PATH + "/cgroup.subtree_control", &controllers)) {
            return controllers.find("memory") != std::string::npos;
        }
        std::cerr << "Error: Could not read " << CGROUP_V2_ROOT_PATH
                  << "/cgroup.subtree_control: " << std::strerror(errno) << std::endl;
        return std::nullopt;
    }

    std::optional<bool> mRootSubtreeState;
};


TEST_F(MemcgV2SubdirTest, CanActivateMemcgV2Subtree) {
    ASSERT_TRUE(WriteStringToFile("+memory", *mRandDir + "/cgroup.subtree_control"))
            << "Could not enable memcg under child cgroup subtree";
}

TEST(MemcgV2, memcg_v2_enabled) {
    KernelVersion first_required_kernel_version = KernelVersion(6, 1, 0);
    KernelVersion kernel_version = VintfObject::GetInstance()
                                           ->getRuntimeInfo(RuntimeInfo::FetchFlag::CPU_VERSION)
                                           ->kernelVersion();
    if (kernel_version < first_required_kernel_version) {
        GTEST_SKIP();
    }

    int FIRST_REQUIRED_ANDROID_API_LEVEL = 37; // Android 17 / 26Q2
    if (android_get_device_api_level() < FIRST_REQUIRED_ANDROID_API_LEVEL) {
        GTEST_SKIP();
    }

    ASSERT_TRUE(isMemcgV2Enabled().value_or(false))
        << "[GMS-VSR-3.4.9-001] requires Android 17 devices running kernels 6.1 or newer to have "
        << "memcg v2 enabled.";
}
