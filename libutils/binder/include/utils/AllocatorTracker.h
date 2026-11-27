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

#pragma once

#ifdef ANDROID_UTILS_CUSTOM_ALLOCATOR

#include <cstddef>
#include <cstdlib>
#include <new>
#include <type_traits>

#include <android/log.h>

namespace android {

// Interface for custom memory allocators.
class Allocator {
  public:
    virtual ~Allocator() = default;

    // Allocates a block of memory of the specified size and alignment.
    // Returns pointer to the allocated memory, or nullptr if allocation fails.
    virtual void* allocate(size_t size, size_t alignment) = 0;

    // Deallocates a previously allocated block of memory.
    // 'ptr' must have been returned by allocate().
    virtual void deallocate(void* ptr) = 0;

    // Reallocates a previously allocated block of memory.
    // 'ptr' must have been returned by allocate().
    virtual void* reallocate(void* ptr, size_t size) = 0;

    // Aborts the process. Called when allocation fails on a throwing allocation.
    virtual void abort() = 0;
};

// Default allocator that uses new and delete.
class DefaultAllocator : public Allocator {
  public:
    DefaultAllocator() = default;
    ~DefaultAllocator() = default;

    static DefaultAllocator& getInstance() {
        static DefaultAllocator sInstance;
        return sInstance;
    }

    void* allocate(size_t size, size_t /* alignment */) override { return malloc(size); }
    void* reallocate(void* ptr, size_t size) override { return realloc(ptr, size); }
    void deallocate(void* ptr) override { free(ptr); }
    void abort() override { std::abort(); }
};

// This class is used to track the allocator used by sp, RefBase, and RpcBinder.
// It allows for choosing a specific allocator to be used for all sp allocation
// and RefBase deallocation.
//
// GetAllocatorTracker().setAllocator(...) must be called during init before
// any allocation using sp, RefBase, or binder usage. If not called during init,
// setAllocator should never be called, and the default allocator will be
// nullptr.
class AllocatorTracker {
  public:
    AllocatorTracker(const AllocatorTracker&) = delete;
    AllocatorTracker& operator=(const AllocatorTracker&) = delete;

    Allocator* getAllocator() { return mAllocator; }

    void setAllocator(Allocator* allocator) { mAllocator = allocator; }

    // Returns the global allocator or the Allocator::LibCAllocator if the
    // global allocator is nullptr.
    static Allocator& getAllocatorOrDefault() {
        Allocator* allocator = getInstance().getAllocator();
        if (allocator == nullptr) {
            allocator = &DefaultAllocator::getInstance();
        }
        return *allocator;
    }

    // Returns true if the global allocator is not nullptr.
    static bool hasAllocator() {
      return getInstance().getAllocator() != nullptr;
    }

    static AllocatorTracker& getInstance() {
      [[clang::no_destroy]] static AllocatorTracker sInstance;
      return sInstance;
    }

   private:
    AllocatorTracker() = default;
    ~AllocatorTracker() = default;

    Allocator* mAllocator = nullptr;
};

}  // namespace android

// Creates a new T with provided Args to the constructor with the global
// allocator if available, or global operator new otherwise. This macro
// evaluates to a T* pointer.
#define ANDROID_NEW(T, ...)                                                                        \
    (::android::AllocatorTracker::hasAllocator()                                                   \
     ? [&]() -> T* {                                                                               \
           static_assert(!std::is_array<T>::value, "Array types are not supported.");              \
           ::android::Allocator& allocator = ::android::AllocatorTracker::getAllocatorOrDefault(); \
           void* ptr = allocator.allocate(sizeof(T), alignof(T));                                  \
           if (ptr == nullptr) {                                                                   \
               allocator.abort();                                                                  \
           }                                                                                       \
           return new (ptr) T(__VA_ARGS__);                                                        \
       }()                                                                                         \
     : [&]() -> T* {                                                                               \
           static_assert(!std::is_array<T>::value, "Array types are not supported.");              \
           return new T(__VA_ARGS__);                                                              \
       }())

// Creates a new T with provided Args to the constructor with the global
// allocator if available, or global operator new otherwise. This macro
// evaluates to a T* pointer.
#define ANDROID_NEW_NOTHROW(T, ...)                                                                \
    (::android::AllocatorTracker::hasAllocator()                                                   \
     ? [&]() -> T* {                                                                               \
           static_assert(!std::is_array<T>::value, "Array types are not supported.");              \
           ::android::Allocator& allocator = ::android::AllocatorTracker::getAllocatorOrDefault(); \
           void* ptr = allocator.allocate(sizeof(T), alignof(T));                                  \
           if (ptr == nullptr) {                                                                   \
               return nullptr;                                                                     \
           }                                                                                       \
           return new (ptr) T(__VA_ARGS__);                                                        \
       }()                                                                                         \
     : [&]() -> T* {                                                                               \
           static_assert(!std::is_array<T>::value, "Array types are not supported.");              \
           return new (std::nothrow) T(__VA_ARGS__);                                               \
       }())

// Creates a new buffer of the specified size with the global allocator if
// available, or malloc otherwise. This macro evaluates to a void* pointer.
#define ANDROID_MALLOC(size)                                                                    \
    (::android::AllocatorTracker::hasAllocator() ? [&]() -> void* {                             \
        ::android::Allocator& allocator = ::android::AllocatorTracker::getAllocatorOrDefault(); \
        return allocator.allocate(size, alignof(void*));                                        \
    }()                                                                                         \
                                                 : malloc(size))

// Reallocates the provided pointer using the global allocator if available, or
// global realloc otherwise. This macro evaluates to a void* pointer.
#define ANDROID_REALLOC(ptr, size)                                                              \
    (::android::AllocatorTracker::hasAllocator() ? [&]() -> void* {                             \
        ::android::Allocator& allocator = ::android::AllocatorTracker::getAllocatorOrDefault(); \
        return allocator.reallocate(ptr, size);                                                 \
    }()                                                                                         \
                                                 : realloc(ptr, size))

// Deletes the provided pointer using the global allocator if available, or
// global delete otherwise. T must be the type of ptr, and will be the
// destructed type. This macro evaluates to void.
#define ANDROID_DELETE(T, ptr)                                                     \
    do {                                                                           \
        static_assert(!std::is_array<T>::value, "Array types are not supported."); \
        if (ptr != nullptr) {                                                      \
            if (::android::AllocatorTracker::hasAllocator()) {                     \
                if constexpr (!std::is_trivially_destructible_v<T>) {              \
                    ptr->~T();                                                     \
                }                                                                  \
                ::android::AllocatorTracker::getAllocatorOrDefault().deallocate(   \
                        const_cast<T*>(ptr));                                      \
            } else {                                                               \
                delete ptr;                                                        \
            }                                                                      \
        }                                                                          \
    } while (0)

// Deletes the provided buffer using the global allocator if available, or
// free otherwise. This macro evaluates to void.
#define ANDROID_FREE(ptr)                                                        \
    do {                                                                         \
        if (ptr != nullptr) {                                                    \
            if (::android::AllocatorTracker::hasAllocator()) {                   \
                ::android::AllocatorTracker::getAllocatorOrDefault().deallocate( \
                        const_cast<void*>(static_cast<const void*>(ptr)));       \
            } else {                                                             \
                free(ptr);                                                       \
            }                                                                    \
        }                                                                        \
    } while (0)

#else  // !ANDROID_UTILS_CUSTOM_ALLOCATOR
#define ANDROID_NEW(T, ...)                                                        \
    [&]() -> T* {                                                                  \
        static_assert(!std::is_array<T>::value, "Array types are not supported."); \
        return new T(__VA_ARGS__);                                                 \
    }()
#define ANDROID_NEW_NOTHROW(T, ...)                                                \
    [&]() -> T* {                                                                  \
        static_assert(!std::is_array<T>::value, "Array types are not supported."); \
        return new (std::nothrow) T(__VA_ARGS__);                                  \
    }()
#define ANDROID_MALLOC(size) malloc(size)
#define ANDROID_REALLOC(ptr, size) realloc(ptr, size)
#define ANDROID_DELETE(T, ptr)                                                     \
    do {                                                                           \
        static_assert(!std::is_array<T>::value, "Array types are not supported."); \
        delete ptr;                                                                \
    } while (0)
#define ANDROID_FREE(ptr) free(ptr)
#endif  // ANDROID_UTILS_CUSTOM_ALLOCATOR
