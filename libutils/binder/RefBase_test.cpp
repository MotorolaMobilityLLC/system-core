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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utils/AllocatorTracker.h>
#include <utils/RefBase.h>
#include <utils/StrongPointer.h>

#include <errno.h>
#include <sched.h>
#include <atomic>
#include <thread>

// Enhanced version of StrongPointer_test, but using RefBase underneath.

using namespace android;
using ::testing::_;

static constexpr int NITERS = 500000;

static constexpr int INITIAL_STRONG_VALUE = 1 << 28;  // Mirroring RefBase definition.

class Foo : public RefBase {
  public:
    Foo(bool* deleted_check) : mDeleted(deleted_check) { *mDeleted = false; }
    Foo(bool* deleted_check, bool weak) : Foo(deleted_check) {
        if (weak) {
            extendObjectLifetime(RefBase::OBJECT_LIFETIME_WEAK);
        }
    }

    ~Foo() { *mDeleted = true; }

    void doTag() { getWeakRefs()->tag(RefBase::OBJECT_TAG_JAVA_PROXY); }
    void doUntag() { getWeakRefs()->untag(RefBase::OBJECT_TAG_JAVA_PROXY); }

  private:
    bool* mDeleted;
};

class RefBaseBothLifetimes : public ::testing::TestWithParam<bool> {
  protected:
    void SetUp() override {
        mWeakLifetime = GetParam();
        foo = new Foo(&isDeleted, mWeakLifetime);
    }

    void TearDown() override { EXPECT_TRUE(isDeleted) << "Foo leaked!"; }

    bool mWeakLifetime;
    bool isDeleted;
    Foo* foo;
};

class DoNothingNoVirtualDestructor : public RefBase {
  public:
    DoNothingNoVirtualDestructor() = default;
    ~DoNothingNoVirtualDestructor() = default;
};

class FooDerived : public DoNothingNoVirtualDestructor {
  public:
    FooDerived(bool* deleted_check) : DoNothingNoVirtualDestructor(), mDeleted(deleted_check) {
        *mDeleted = false;
    }
    ~FooDerived() { *mDeleted = true; }

  private:
    bool* mDeleted;
};

// A version of Foo that ensures that all objects are allocated at the same
// address. No more than one can be allocated at a time. Thread-hostile.
class FooFixedAlloc : public RefBase {
public:
    static void* operator new(size_t size) {
        if (mAllocCount != 0) {
            abort();
        }
        mAllocCount = 1;
        if (theMemory == nullptr) {
            theMemory = malloc(size);
        }
        return theMemory;
    }

    static void operator delete(void *p) {
        if (mAllocCount != 1 || p != theMemory) {
            abort();
        }
        mAllocCount = 0;
    }

    FooFixedAlloc(bool* deleted_check) : mDeleted(deleted_check) {
        *mDeleted = false;
    }

    ~FooFixedAlloc() {
        *mDeleted = true;
    }
private:
    bool* mDeleted;
    static int mAllocCount;
    static void* theMemory;
};

int FooFixedAlloc::mAllocCount(0);
void* FooFixedAlloc::theMemory(nullptr);

#ifdef ANDROID_UTILS_CUSTOM_ALLOCATOR
// A simple allocator that can be used to check that the allocator is being
// called when expected.
class TestAllocator : public Allocator {
  public:
    TestAllocator() {
        ON_CALL(*this, allocate(_, _)).WillByDefault([](size_t size, size_t) {
            return malloc(size);
        });
        ON_CALL(*this, reallocate(_, _)).WillByDefault([](void* ptr, size_t size) {
            return realloc(ptr, size);
        });
        ON_CALL(*this, deallocate(_)).WillByDefault([](void* ptr) { free(ptr); });
        ON_CALL(*this, abort()).WillByDefault([]() { std::abort(); });
    }

    MOCK_METHOD(void*, allocate, (size_t size, size_t alignment), (override));
    MOCK_METHOD(void*, reallocate, (void* ptr, size_t size), (override));
    MOCK_METHOD(void, deallocate, (void* ptr), (override));
    MOCK_METHOD(void, abort, (), (override));
};
#endif  // ANDROID_UTILS_CUSTOM_ALLOCATOR

TEST_P(RefBaseBothLifetimes, StrongMoves) {
    ASSERT_EQ(INITIAL_STRONG_VALUE, foo->getStrongCount());
    ASSERT_FALSE(isDeleted) << "Already deleted...?";
    sp<Foo> sp1(foo);
    wp<Foo> wp1(sp1);
    ASSERT_EQ(1, foo->getStrongCount());
    // Weak count includes both strong and weak references.
    ASSERT_EQ(2, foo->getWeakRefs()->getWeakCount());
    {
        sp<Foo> sp2 = std::move(sp1);
        ASSERT_EQ(1, foo->getStrongCount())
                << "std::move failed, incremented refcnt";
        ASSERT_EQ(nullptr, sp1.get()) << "std::move failed, sp1 is still valid";
        // The strong count isn't increasing, let's double check the old object
        // is properly reset and doesn't early delete
        sp1 = std::move(sp2);
    }

    EXPECT_EQ(1, foo->getStrongCount());
    EXPECT_EQ(2, foo->getWeakRefs()->getWeakCount());

    ASSERT_FALSE(isDeleted) << "deleted too early! still has a reference!";
    {
        // Now let's double check it deletes on time
        sp<Foo> sp2 = std::move(sp1);
    }
    ASSERT_NE(mWeakLifetime, isDeleted) << "foo was leaked!";
}

TEST(RefBase, WeakCopies) {
    bool isDeleted;
    Foo* foo = new Foo(&isDeleted);
    EXPECT_EQ(0, foo->getWeakRefs()->getWeakCount());
    ASSERT_FALSE(isDeleted) << "Foo (weak) already deleted...?";
    wp<Foo> wp1(foo);
    EXPECT_EQ(1, foo->getWeakRefs()->getWeakCount());
    {
        wp<Foo> wp2 = wp1;
        ASSERT_EQ(2, foo->getWeakRefs()->getWeakCount());
    }
    EXPECT_EQ(1, foo->getWeakRefs()->getWeakCount());
    ASSERT_FALSE(isDeleted) << "deleted too early! still has a reference!";
    wp1 = nullptr;
    ASSERT_FALSE(isDeleted) << "Deletion on wp destruction should no longer occur";
}

TEST_P(RefBaseBothLifetimes, Comparisons) {
    bool isDeleted2, isDeleted3;
    Foo* foo2 = new Foo(&isDeleted2);
    sp<Foo> sp1(foo);
    sp<Foo> sp2(foo2);
    wp<Foo> wp1(sp1);
    wp<Foo> wp2(sp1);
    wp<Foo> wp3(sp2);
    ASSERT_TRUE(wp1 == wp2);
    ASSERT_TRUE(wp1 == sp1);
    ASSERT_TRUE(wp3 == sp2);
    ASSERT_TRUE(wp1 != sp2);
    ASSERT_TRUE(wp1 <= wp2);
    ASSERT_TRUE(wp1 >= wp2);
    ASSERT_FALSE(wp1 != wp2);
    ASSERT_FALSE(wp1 > wp2);
    ASSERT_FALSE(wp1 < wp2);
    ASSERT_FALSE(sp1 == sp2);
    ASSERT_TRUE(sp1 != sp2);
    bool sp1_smaller = sp1 < sp2;
    wp<Foo> wp_smaller = sp1_smaller ? wp1 : wp3;
    wp<Foo> wp_larger = sp1_smaller ? wp3 : wp1;
    ASSERT_TRUE(wp_smaller < wp_larger);
    ASSERT_TRUE(wp_smaller != wp_larger);
    ASSERT_TRUE(wp_smaller <= wp_larger);
    ASSERT_FALSE(wp_smaller == wp_larger);
    ASSERT_FALSE(wp_smaller > wp_larger);
    ASSERT_FALSE(wp_smaller >= wp_larger);
    sp2 = nullptr;
    ASSERT_TRUE(isDeleted2);
    ASSERT_FALSE(isDeleted);
    ASSERT_FALSE(wp3 == sp2);
    // Comparison results on weak pointers should not be affected.
    ASSERT_TRUE(wp_smaller < wp_larger);
    ASSERT_TRUE(wp_smaller != wp_larger);
    ASSERT_TRUE(wp_smaller <= wp_larger);
    ASSERT_FALSE(wp_smaller == wp_larger);
    ASSERT_FALSE(wp_smaller > wp_larger);
    ASSERT_FALSE(wp_smaller >= wp_larger);
    wp2 = nullptr;
    ASSERT_FALSE(wp1 == wp2);
    ASSERT_TRUE(wp1 != wp2);
    wp1.clear();
    ASSERT_TRUE(wp1 == wp2);
    ASSERT_FALSE(wp1 != wp2);
    wp3.clear();
    ASSERT_TRUE(wp1 == wp3);
    ASSERT_FALSE(wp1 != wp3);
    ASSERT_FALSE(isDeleted);
    sp1.clear();
    ASSERT_NE(mWeakLifetime, isDeleted);
    ASSERT_TRUE(sp1 == sp2);
    // Try to check that null pointers are properly initialized.
    {
        // Try once with non-null, to maximize chances of getting junk on the
        // stack.
        sp<Foo> sp3(new Foo(&isDeleted3));
        wp<Foo> wp4(sp3);
        wp<Foo> wp5;
        ASSERT_FALSE(wp4 == wp5);
        ASSERT_TRUE(wp4 != wp5);
        ASSERT_FALSE(sp3 == wp5);
        ASSERT_FALSE(wp5 == sp3);
        ASSERT_TRUE(sp3 != wp5);
        ASSERT_TRUE(wp5 != sp3);
        ASSERT_TRUE(sp3 == wp4);
    }
    {
        sp<Foo> sp3;
        wp<Foo> wp4(sp3);
        wp<Foo> wp5;
        ASSERT_TRUE(wp4 == wp5);
        ASSERT_FALSE(wp4 != wp5);
        ASSERT_TRUE(sp3 == wp5);
        ASSERT_TRUE(wp5 == sp3);
        ASSERT_FALSE(sp3 != wp5);
        ASSERT_FALSE(wp5 != sp3);
        ASSERT_TRUE(sp3 == wp4);
    }
}

// Check whether comparison against dead wp works, even if the object referenced
// by the new wp happens to be at the same address.
TEST(RefBase, ReplacedComparison) {
    bool isDeleted, isDeleted2;
    FooFixedAlloc* foo = new FooFixedAlloc(&isDeleted);
    sp<FooFixedAlloc> sp1(foo);
    wp<FooFixedAlloc> wp1(sp1);
    ASSERT_TRUE(wp1 == sp1);
    sp1.clear();  // Deallocates the object.
    ASSERT_TRUE(isDeleted);
    FooFixedAlloc* foo2 = new FooFixedAlloc(&isDeleted2);
    ASSERT_FALSE(isDeleted2);
    ASSERT_EQ(foo, foo2);  // Not technically a legal comparison, but ...
    sp<FooFixedAlloc> sp2(foo2);
    wp<FooFixedAlloc> wp2(sp2);
    ASSERT_TRUE(sp2 == wp2);
    ASSERT_FALSE(sp2 != wp2);
    ASSERT_TRUE(sp2 != wp1);
    ASSERT_FALSE(sp2 == wp1);
    ASSERT_FALSE(sp2 == sp1);  // sp1 is null.
    ASSERT_FALSE(wp1 == wp2);  // wp1 refers to old object.
    ASSERT_TRUE(wp1 != wp2);
    ASSERT_TRUE(wp1 > wp2 || wp1 < wp2);
    ASSERT_TRUE(wp1 >= wp2 || wp1 <= wp2);
    ASSERT_FALSE(wp1 >= wp2 && wp1 <= wp2);
    ASSERT_FALSE(wp1 == nullptr);
    wp1 = sp2;
    ASSERT_TRUE(wp1 == wp2);
    ASSERT_FALSE(wp1 != wp2);
}

TEST_P(RefBaseBothLifetimes, AssertWeakRefExistsSuccess) {
    sp<Foo> strongFoo = foo;
    wp<Foo> weakFoo = strongFoo;

    EXPECT_EQ(weakFoo, wp<Foo>::fromExisting(strongFoo.get()));
    EXPECT_EQ(weakFoo.unsafe_get(), wp<Foo>::fromExisting(strongFoo.get()).unsafe_get());

    EXPECT_FALSE(isDeleted);
}

TEST_P(RefBaseBothLifetimes, AssertWeakRefExistsDeath) {
    // can only get a valid wp<> object when you construct it from an sp<>
    EXPECT_DEATH(wp<Foo>::fromExisting(foo),
                 "incWeakRequireWeak called on .* which has no weak refs");

    delete foo;  // if inc/decStrong is never used must manually delete
}

TEST_P(RefBaseBothLifetimes, TagUntag) {
    foo->incStrong(nullptr);
    foo->doTag();
    foo->doUntag();
    EXPECT_FALSE(isDeleted);
    foo->decStrong(nullptr);
}

TEST_P(RefBaseBothLifetimes, DoubleTag) {
    foo->incStrong(nullptr);
    foo->doTag();
    EXPECT_DEATH(foo->doTag(), "RBSAN: Can't set flag 65536 when it's set: 65536");
    foo->doUntag();
    foo->decStrong(nullptr);
}

TEST_P(RefBaseBothLifetimes, DieIfOnlyUntagged) {
    foo->incStrong(nullptr);
    EXPECT_DEATH(foo->doUntag(), "Can't unset flag 65536 when it's not set: 0");
    foo->decStrong(nullptr);
}

TEST_P(RefBaseBothLifetimes, DieIfDeletedWithTag) {
    foo->incStrong(nullptr);
    foo->doTag();
    EXPECT_DEATH(foo->decStrong(nullptr), "RBSAN: Object is deleted, but it is tagged: 65536");
    foo->doUntag();
    foo->decStrong(nullptr);
}

TEST_P(RefBaseBothLifetimes, NoStrongCountPromoteFromWeak) {
    wp<Foo> weakFoo = wp<Foo>(foo);

    EXPECT_FALSE(isDeleted);

    {
        sp<Foo> strongFoo = weakFoo.promote();
        EXPECT_EQ(strongFoo, foo);
    }

    // this shows the justification of wp<>::fromExisting.
    // if you construct a wp<>, for instance in a constructor, and it is
    // accidentally promoted, that promoted sp<> will exclusively own
    // the object. If that happens during the initialization of the
    // object or in this scope, as you can see 'Foo* foo' is unowned,
    // then we are left with a deleted object, and we could not put it
    // into an sp<>.
    //
    // Consider the other implementation, where we disallow promoting
    // a wp<> if there are no strong counts. If we return null, then
    // the object would be unpromotable even though it hasn't been deleted.
    // This is also errorprone.
    //
    // attemptIncStrong aborting in this case is a backwards incompatible
    // change due to frequent use of wp<T>(this) in the constructor.
    EXPECT_NE(mWeakLifetime, isDeleted);
}

// TODO: this is not caught for OBJECT_LIFETIME_WEAK. Please improve?
TEST(RefBase, DoubleOwnershipDeath) {
    bool isDeleted;
    sp<Foo> foo = sp<Foo>::make(&isDeleted);

    // if something else thinks it owns foo, should die
    EXPECT_DEATH(delete foo.get(), "object .* with strong count 1 deleted. Double owned?");
}

TEST(RefBase, StackOwnershipDeath) {
    bool isDeleted;

    // The death on the stack does not always work, but in such a case, we still abort due to
    // deletion of the object while a strong reference is taken.
    EXPECT_DEATH(
            {
                Foo foo(&isDeleted);
                foo.incStrong(nullptr);
            },
            "(RefBase used with stack pointer argument|object .* with strong count 1 deleted. Double owned?)");
}

// Set up a situation in which we race with visit2AndRremove() to delete
// 2 strong references.  Bar destructor checks that there are no early
// deletions and prior updates are visible to destructor.
class Bar : public RefBase {
public:
    Bar(std::atomic<int>* delete_count) : mVisited1(false), mVisited2(false),
            mDeleteCount(delete_count) {
    }

    ~Bar() {
        EXPECT_TRUE(mVisited1);
        EXPECT_TRUE(mVisited2);
        (*mDeleteCount)++;
    }
    bool mVisited1;
    bool mVisited2;
private:
    std::atomic<int>* mDeleteCount;
};

[[clang::no_destroy]] static constinit sp<Bar> buffer;
static constinit std::atomic<bool> bufferFull(false);

// Wait until bufferFull has value val.
static inline void waitFor(bool val) {
    while (bufferFull != val) {}
}

cpu_set_t otherCpus;

// Divide the cpus we're allowed to run on into myCpus and otherCpus.
// Set origCpus to the processors we were originally allowed to run on.
// Return false if origCpus doesn't include at least processors 0 and 1.
static bool setExclusiveCpus(cpu_set_t* origCpus /* out */,
        cpu_set_t* myCpus /* out */, cpu_set_t* otherCpus) {
    if (sched_getaffinity(0, sizeof(cpu_set_t), origCpus) != 0) {
        return false;
    }
    if (!CPU_ISSET(0,  origCpus) || !CPU_ISSET(1, origCpus)) {
        return false;
    }
    CPU_ZERO(myCpus);
    CPU_ZERO(otherCpus);
    CPU_OR(myCpus, myCpus, origCpus);
    CPU_OR(otherCpus, otherCpus, origCpus);
    for (unsigned i = 0; i < CPU_SETSIZE; ++i) {
        // I get the even cores, the other thread gets the odd ones.
        if (i & 1) {
            CPU_CLR(i, myCpus);
        } else {
            CPU_CLR(i, otherCpus);
        }
    }
    return true;
}

static void visit2AndRemove() {
    if (sched_setaffinity(0, sizeof(cpu_set_t), &otherCpus) != 0) {
        FAIL() << "setaffinity returned:" << errno;
    }
    for (int i = 0; i < NITERS; ++i) {
        waitFor(true);
        buffer->mVisited2 = true;
        buffer = nullptr;
        bufferFull = false;
    }
}

TEST(RefBase, RacingDestructors) {
    cpu_set_t origCpus;
    cpu_set_t myCpus;
    // Restrict us and the helper thread to disjoint cpu sets.
    // This prevents us from getting scheduled against each other,
    // which would be atrociously slow.
    if (setExclusiveCpus(&origCpus, &myCpus, &otherCpus)) {
        std::thread t(visit2AndRemove);
        std::atomic<int> deleteCount(0);
        if (sched_setaffinity(0, sizeof(cpu_set_t), &myCpus) != 0) {
            FAIL() << "setaffinity returned:" << errno;
        }
        for (int i = 0; i < NITERS; ++i) {
            waitFor(false);
            Bar* bar = new Bar(&deleteCount);
            sp<Bar> sp3(bar);
            buffer = sp3;
            bufferFull = true;
            ASSERT_TRUE(bar->getStrongCount() >= 1);
            // Weak count includes strong count.
            ASSERT_TRUE(bar->getWeakRefs()->getWeakCount() >= 1);
            sp3->mVisited1 = true;
            sp3 = nullptr;
        }
        t.join();
        if (sched_setaffinity(0, sizeof(cpu_set_t), &origCpus) != 0) {
            FAIL();
        }
        ASSERT_EQ(NITERS, deleteCount) << "Deletions missed!";
    }  // Otherwise this is slow and probably pointless on a uniprocessor.
}

[[clang::no_destroy]] static constinit wp<Bar> wpBuffer;
static constinit std::atomic<bool> wpBufferFull(false);

// Wait until wpBufferFull has value val.
static inline void wpWaitFor(bool val) {
    while (wpBufferFull != val) {}
}

static void visit3AndRemove() {
    if (sched_setaffinity(0, sizeof(cpu_set_t), &otherCpus) != 0) {
        FAIL() << "setaffinity returned:" << errno;
    }
    for (int i = 0; i < NITERS; ++i) {
        wpWaitFor(true);
        {
            sp<Bar> sp1 = wpBuffer.promote();
            // We implicitly check that sp1 != NULL
            sp1->mVisited2 = true;
        }
        wpBuffer = nullptr;
        wpBufferFull = false;
    }
}

TEST(RefBase, RacingPromotions) {
    cpu_set_t origCpus;
    cpu_set_t myCpus;
    // Restrict us and the helper thread to disjoint cpu sets.
    // This prevents us from getting scheduled against each other,
    // which would be atrociously slow.
    if (setExclusiveCpus(&origCpus, &myCpus, &otherCpus)) {
        std::thread t(visit3AndRemove);
        std::atomic<int> deleteCount(0);
        if (sched_setaffinity(0, sizeof(cpu_set_t), &myCpus) != 0) {
            FAIL() << "setaffinity returned:" << errno;
        }
        for (int i = 0; i < NITERS; ++i) {
            Bar* bar = new Bar(&deleteCount);
            wp<Bar> wp1(bar);
            bar->mVisited1 = true;
            if (i % (NITERS / 10) == 0) {
                // Do this rarely, since it generates a log message.
                wp1 = nullptr;  // No longer destroys the object.
                wp1 = bar;
            }
            wpBuffer = wp1;
            ASSERT_EQ(bar->getWeakRefs()->getWeakCount(), 2);
            wpBufferFull = true;
            // Promotion races with that in visit3AndRemove.
            // This may or may not succeed, but it shouldn't interfere with
            // the concurrent one.
            sp<Bar> sp1 = wp1.promote();
            wpWaitFor(false);  // Waits for other thread to drop strong pointer.
            sp1 = nullptr;
            // No strong pointers here.
            sp1 = wp1.promote();
            ASSERT_EQ(sp1.get(), nullptr) << "Dead wp promotion succeeded!";
        }
        t.join();
        if (sched_setaffinity(0, sizeof(cpu_set_t), &origCpus) != 0) {
            FAIL();
        }
        ASSERT_EQ(NITERS, deleteCount) << "Deletions missed!";
    }  // Otherwise this is slow and probably pointless on a uniprocessor.
}

#ifdef ANDROID_UTILS_CUSTOM_ALLOCATOR
// TODO: also test with RefBaseBothLifetimes

TEST(RefBase, CustomAllocator) {
    TestAllocator allocator;  // Use the mock allocator
    android::AllocatorTracker::getInstance().setAllocator(&allocator);

    bool isDeleted = false;
    // The underlying pointer will be allocated then the refs will be allocated.
    void* allocated_ptrs[2] = {nullptr, nullptr};

    // Expect DoAllocate to be called once when creating the object
    EXPECT_CALL(allocator, allocate(_, _))
            .Times(2)
            .WillRepeatedly([&allocated_ptrs](size_t size, size_t) {
                void* ptr = malloc(size);
                if (allocated_ptrs[0] == nullptr) {
                    allocated_ptrs[0] = ptr;
                } else {
                    allocated_ptrs[1] = ptr;
                }
                return ptr;
            });

    sp<Foo> foo = sp<Foo>::make(&isDeleted);
    EXPECT_FALSE(isDeleted);

    // Expect deallocate to be called twice when the object is deleted -
    // refs first then the pointer.
    EXPECT_CALL(allocator, deallocate(allocated_ptrs[1]));
    EXPECT_CALL(allocator, deallocate(allocated_ptrs[0]));

    foo = nullptr;
    EXPECT_TRUE(isDeleted);
    android::AllocatorTracker::getInstance().setAllocator(nullptr);
}

TEST(RefBase, CustomAllocatorCallsRightDestructor) {
    TestAllocator allocator;  // Use the mock allocator
    android::AllocatorTracker::getInstance().setAllocator(&allocator);

    bool isDeleted = false;
    // The underlying pointer will be allocated then the refs will be allocated.
    void* allocated_ptrs[2] = {nullptr, nullptr};

    // Expect allocate to be called once when creating the object
    EXPECT_CALL(allocator, allocate(_, _))
            .Times(2)
            .WillRepeatedly([&allocated_ptrs](size_t size, size_t) {
                void* ptr = malloc(size);
                if (allocated_ptrs[0] == nullptr) {
                    allocated_ptrs[0] = ptr;
                } else {
                    allocated_ptrs[1] = ptr;
                }
                return ptr;
            });

    sp<FooDerived> foo = sp<FooDerived>::make(&isDeleted);
    EXPECT_FALSE(isDeleted);

    // Expect deallocate to be called twice when the object is deleted -
    // refs first then the pointer.
    EXPECT_CALL(allocator, deallocate(allocated_ptrs[1]));
    EXPECT_CALL(allocator, deallocate(allocated_ptrs[0]));
    foo = nullptr;
    EXPECT_TRUE(isDeleted);

    android::AllocatorTracker::getInstance().setAllocator(nullptr);
}

#endif  // ANDROID_UTILS_CUSTOM_ALLOCATOR

INSTANTIATE_TEST_SUITE_P(Strong0Weak1, RefBaseBothLifetimes, ::testing::Bool());
