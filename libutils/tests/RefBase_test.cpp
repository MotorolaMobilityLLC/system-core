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

#include <gtest/gtest.h>

#include <utils/StrongPointer.h>
#include <utils/RefBase.h>

#include <thread>
#include <atomic>
#include <sched.h>
#include <errno.h>

// Enhanced version of StrongPointer_test, but using RefBase underneath.

using namespace android;

static constexpr int NITERS = 1000000;

static constexpr int INITIAL_STRONG_VALUE = 1 << 28;  // Mirroring RefBase definition.

class Foo : public RefBase {
public:
    Foo(bool* deleted_check) : mDeleted(deleted_check) {
        *mDeleted = false;
    }

    ~Foo() {
        *mDeleted = true;
    }
private:
    bool* mDeleted;
};

TEST(RefBase, StrongMoves) {
    bool isDeleted;
    Foo* foo = new Foo(&isDeleted);
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
    ASSERT_FALSE(isDeleted) << "deleted too early! still has a reference!";
    {
        // Now let's double check it deletes on time
        sp<Foo> sp2 = std::move(sp1);
    }
    ASSERT_TRUE(isDeleted) << "foo was leaked!";
    ASSERT_TRUE(wp1.promote().get() == nullptr);
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
    ASSERT_TRUE(isDeleted) << "foo2 was leaked!";
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

static sp<Bar> buffer;
static std::atomic<bool> bufferFull(false);

// Wait until bufferFull has value val.
static inline void waitFor(bool val) {
    while (bufferFull != val) {}
}

cpu_set_t otherCpus;

static void visit2AndRemove() {
    EXPECT_TRUE(CPU_ISSET(1,  &otherCpus));
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
    // which would be atrociously slow.  We fail if that's impossible.
    if (sched_getaffinity(0, sizeof(cpu_set_t), &origCpus) != 0) {
        FAIL();
    }
    EXPECT_TRUE(CPU_ISSET(0,  &origCpus));
    if (CPU_ISSET(1, &origCpus)) {
        CPU_ZERO(&myCpus);
        CPU_ZERO(&otherCpus);
        CPU_OR(&myCpus, &myCpus, &origCpus);
        CPU_OR(&otherCpus, &otherCpus, &origCpus);
        for (unsigned i = 0; i < CPU_SETSIZE; ++i) {
            // I get the even cores, the other thread gets the odd ones.
            if (i & 1) {
                CPU_CLR(i, &myCpus);
            } else {
                CPU_CLR(i, &otherCpus);
            }
        }
        std::thread t(visit2AndRemove);
        std::atomic<int> deleteCount(0);
        EXPECT_TRUE(CPU_ISSET(0,  &myCpus));
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
