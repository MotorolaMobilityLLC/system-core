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

#include <sys/mman.h>
#include <cutils/ashmem.h>
#include <gtest/gtest.h>
#include <android-base/unique_fd.h>

using android::base::unique_fd;

void TestCreateRegion(size_t size, unique_fd &fd, int prot) {
    fd = unique_fd(ashmem_create_region(nullptr, size));
    ASSERT_TRUE(fd >= 0);
    ASSERT_TRUE(ashmem_valid(fd));
    ASSERT_EQ(size, static_cast<size_t>(ashmem_get_size_region(fd)));
    ASSERT_EQ(0, ashmem_set_prot_region(fd, prot));
}

void TestMmap(const unique_fd &fd, size_t size, int prot, void **region) {
    *region = mmap(nullptr, size, prot, MAP_SHARED, fd, 0);
    ASSERT_NE(MAP_FAILED, *region);
}

void TestProtDenied(const unique_fd &fd, size_t size, int prot) {
    EXPECT_EQ(MAP_FAILED, mmap(nullptr, size, prot, MAP_SHARED, fd, 0));
}

void FillData(uint8_t* data, size_t dataLen) {
    for (size_t i = 0; i < dataLen; i++) {
        data[i] = i & 0xFF;
    }
}

TEST(AshmemTest, BasicTest) {
    constexpr size_t size = PAGE_SIZE;
    uint8_t data[size];
    FillData(data, size);

    unique_fd fd;
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));

    void *region1;
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ | PROT_WRITE, &region1));

    memcpy(region1, &data, size);
    ASSERT_EQ(0, memcmp(region1, &data, size));

    EXPECT_EQ(0, munmap(region1, size));

    void *region2;
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ, &region2));
    ASSERT_EQ(0, memcmp(region2, &data, size));
    EXPECT_EQ(0, munmap(region2, size));
}

TEST(AshmemTest, ForkTest) {
    constexpr size_t size = PAGE_SIZE;
    uint8_t data[size];
    FillData(data, size);

    unique_fd fd;
    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));

    void *region1;
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ | PROT_WRITE, &region1));

    memcpy(region1, &data, size);
    ASSERT_EQ(0, memcmp(region1, &data, size));
    EXPECT_EQ(0, munmap(region1, size));

    ASSERT_EXIT({
        void *region2 = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (region2 == MAP_FAILED) {
            _exit(1);
        }
        if (memcmp(region2, &data, size) != 0) {
            _exit(2);
        }
        memset(region2, 0, size);
        munmap(region2, size);
        _exit(0);
    }, ::testing::ExitedWithCode(0),"");

    memset(&data, 0, size);
    void *region2;
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ | PROT_WRITE, &region2));
    ASSERT_EQ(0, memcmp(region2, &data, size));
    EXPECT_EQ(0, munmap(region2, size));
}

TEST(AshmemTest, ProtTest) {
    unique_fd fd;
    constexpr size_t size = PAGE_SIZE;
    void *region;

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ));
    TestProtDenied(fd, size, PROT_WRITE);
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_READ, &region));
    EXPECT_EQ(0, munmap(region, size));

    ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_WRITE));
    TestProtDenied(fd, size, PROT_READ);
    ASSERT_NO_FATAL_FAILURE(TestMmap(fd, size, PROT_WRITE, &region));
    EXPECT_EQ(0, munmap(region, size));
}

TEST(AshmemTest, ForkProtTest) {
    unique_fd fd;
    constexpr size_t size = PAGE_SIZE;

    int protFlags[] = { PROT_READ, PROT_WRITE };
    for (int i = 0; i < 2; i++) {
        ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd, PROT_READ | PROT_WRITE));
        ASSERT_EXIT({
            if (ashmem_set_prot_region(fd, protFlags[i]) >= 0) {
                _exit(0);
            } else {
                _exit(1);
            }
        }, ::testing::ExitedWithCode(0), "");
        ASSERT_NO_FATAL_FAILURE(TestProtDenied(fd, size, protFlags[1-i]));
    }
}

TEST(AshmemTest, ForkMultiRegionTest) {
    constexpr size_t size = PAGE_SIZE;
    uint8_t data[size];
    FillData(data, size);

    constexpr int nRegions = 16;
    unique_fd fd[nRegions];
    for (int i = 0; i < nRegions; i++) {
        ASSERT_NO_FATAL_FAILURE(TestCreateRegion(size, fd[i], PROT_READ | PROT_WRITE));
        void *region;
        ASSERT_NO_FATAL_FAILURE(TestMmap(fd[i], size, PROT_READ | PROT_WRITE, &region));
        memcpy(region, &data, size);
        ASSERT_EQ(0, memcmp(region, &data, size));
        EXPECT_EQ(0, munmap(region, size));
    }

    ASSERT_EXIT({
        for (int i = 0; i < nRegions; i++) {
            void *region = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd[i], 0);
            if (region == MAP_FAILED) {
                _exit(1);
            }
            if (memcmp(region, &data, size) != 0) {
                munmap(region, size);
                _exit(2);
            }
            memset(region, 0, size);
            munmap(region, size);
        }
        _exit(0);
    }, ::testing::ExitedWithCode(0), "");

    memset(&data, 0, size);
    for (int i = 0; i < nRegions; i++) {
        void *region;
        ASSERT_NO_FATAL_FAILURE(TestMmap(fd[i], size, PROT_READ | PROT_WRITE, &region));
        ASSERT_EQ(0, memcmp(region, &data, size));
        EXPECT_EQ(0, munmap(region, size));
    }
}
