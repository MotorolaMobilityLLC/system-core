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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <stdint.h>

#include <utils/AllocatorTracker.h>

#include "SharedBuffer.h"

extern "C" void __hwasan_init() __attribute__((weak));
#define SKIP_WITH_HWASAN \
    if (&__hwasan_init != 0) GTEST_SKIP()

#ifdef ANDROID_UTILS_CUSTOM_ALLOCATOR

using ::testing::_;

// A simple allocator that can be used to check that the allocator is being
// called when expected.
// A simple allocator that always returns nullptr.
class MockAllocator : public android::Allocator {
  public:
    MOCK_METHOD(void*, allocate, (size_t size, size_t alignment), (override));
    MOCK_METHOD(void*, reallocate, (void* ptr, size_t size), (override));
    MOCK_METHOD(void, deallocate, (void* ptr), (override));
    MOCK_METHOD(void, abort, (), (override));
};

#endif  // ANDROID_UTILS_CUSTOM_ALLOCATOR

TEST(SharedBufferTest, alloc_death) {
    EXPECT_DEATH(android::SharedBuffer::alloc(SIZE_MAX), "");
    EXPECT_DEATH(android::SharedBuffer::alloc(SIZE_MAX - sizeof(android::SharedBuffer)), "");
}

TEST(SharedBufferTest, alloc_max) {
    SKIP_WITH_HWASAN;  // hwasan has a 2GiB allocation limit.

    android::SharedBuffer* buf =
            android::SharedBuffer::alloc(SIZE_MAX - sizeof(android::SharedBuffer) - 1);
    if (buf != nullptr) {
        EXPECT_NE(nullptr, buf->data());
        buf->release();
    }
}

TEST(SharedBufferTest, alloc_big) {
    SKIP_WITH_HWASAN;  // hwasan has a 2GiB allocation limit.

    android::SharedBuffer* buf = android::SharedBuffer::alloc(SIZE_MAX / 2);
    if (buf != nullptr) {
        EXPECT_NE(nullptr, buf->data());
        buf->release();
    }
}

TEST(SharedBufferTest, alloc_zero_size) {
    android::SharedBuffer* buf = android::SharedBuffer::alloc(0);
    ASSERT_NE(nullptr, buf);
    ASSERT_EQ(0U, buf->size());
    buf->release();
}

TEST(SharedBufferTest, editResize) {
    android::SharedBuffer* buf = android::SharedBuffer::alloc(10);
    EXPECT_EQ(10U, buf->size());
    buf = buf->editResize(20);
    EXPECT_EQ(20U, buf->size());
    buf->release();
}

TEST(SharedBufferTest, editResize_death) {
    android::SharedBuffer* buf = android::SharedBuffer::alloc(10);
    EXPECT_DEATH(buf->editResize(SIZE_MAX - sizeof(android::SharedBuffer)), "");
    buf = android::SharedBuffer::alloc(10);
    EXPECT_DEATH(buf->editResize(SIZE_MAX), "");
}

TEST(SharedBufferTest, editResize_null) {
    // Big enough to fail, not big enough to abort.
    SKIP_WITH_HWASAN;  // hwasan has a 2GiB allocation limit.
    android::SharedBuffer* buf = android::SharedBuffer::alloc(10);
    android::SharedBuffer* buf2 = buf->editResize(SIZE_MAX / 2);
    if (buf2 == nullptr) {
        buf->release();
    } else {
        EXPECT_NE(nullptr, buf2->data());
        buf2->release();
    }
}

TEST(SharedBufferTest, editResize_zero_size) {
    android::SharedBuffer* buf = android::SharedBuffer::alloc(10);
    buf = buf->editResize(0);
    ASSERT_EQ(0U, buf->size());
    buf->release();
}

#ifdef ANDROID_UTILS_CUSTOM_ALLOCATOR
TEST(SharedBufferTest, custom_allocator) {
    MockAllocator allocator;
    android::AllocatorTracker::getInstance().setAllocator(&allocator);

    // Expect allocate to be called and return memory allocated by malloc.
    EXPECT_CALL(allocator, allocate(_, _)).WillOnce([](size_t size, size_t /* alignment */) {
        return malloc(size);
    });

    android::SharedBuffer* buf = android::SharedBuffer::alloc(10);
    ASSERT_NE(buf, nullptr);

    // Expect deallocate to be called and free the memory.
    EXPECT_CALL(allocator, deallocate(_)).WillOnce([](void* ptr) { free(ptr); });

    // This should trigger the deallocate call.
    buf->release();

    android::AllocatorTracker::getInstance().setAllocator(nullptr);
}

TEST(SharedBufferTest, editResize_custom_allocator) {
    MockAllocator allocator;
    android::AllocatorTracker::getInstance().setAllocator(&allocator);

    // Expect allocate to be called and return memory allocated by malloc.
    EXPECT_CALL(allocator, allocate(_, _)).WillOnce([](size_t size, size_t) {
        return malloc(size);
    });

    android::SharedBuffer* buf = android::SharedBuffer::alloc(10);
    ASSERT_NE(buf, nullptr);

    // Expect reallocate to be called and return memory allocated by realloc.
    EXPECT_CALL(allocator, reallocate(_, _)).WillOnce([](void* ptr, size_t size) {
        return realloc(ptr, size);
    });
    buf = buf->editResize(20);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(buf->size(), 20U);

    // Expect deallocate to be called and free the memory.
    EXPECT_CALL(allocator, deallocate(_)).WillOnce([](void* ptr) { free(ptr); });

    // This should trigger the deallocate call.
    buf->release();

    android::AllocatorTracker::getInstance().setAllocator(nullptr);
}

TEST(SharedBufferTest, editResize_custom_allocator_fail) {
    MockAllocator allocator;
    android::AllocatorTracker::getInstance().setAllocator(&allocator);

    // Expect allocate to be called and return memory allocated by malloc.
    EXPECT_CALL(allocator, allocate(_, _)).WillOnce([](size_t size, size_t /* alignment */) {
        return malloc(size);
    });

    android::SharedBuffer* buf = android::SharedBuffer::alloc(10);
    ASSERT_NE(buf, nullptr);

    // Expect reallocate to be called - will fail due to OOM
    EXPECT_CALL(allocator, reallocate(_, _)).WillOnce([](void* ptr, size_t /* size */) {
        free(ptr);
        return nullptr;  // simulate OOM
    });
    // Expect allocate to be called once reallocate fails - will fail due to OOM as well
    EXPECT_CALL(allocator, allocate(_, _)).WillOnce([](size_t /* size */, size_t /* alignment */) {
        return nullptr;
    });
    buf = buf->editResize(20);
    ASSERT_EQ(buf, nullptr);

    android::AllocatorTracker::getInstance().setAllocator(nullptr);
}

#endif  // ANDROID_UTILS_CUSTOM_ALLOCATOR
