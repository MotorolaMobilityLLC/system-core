#include "thread_pool.h"

#include <atomic>
#include <latch>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace android {
namespace init {

using ::testing::ElementsAre;

enum TestPriority {
    kPriorityHigh = 0,
    kPriorityDefault = 1,
    kPriorityLow = 2,
};

TEST(ThreadPoolTest, ImmediateStopWorks) {
    ThreadPool pool(4);
    // The pool should stop without any error.
    pool.Wait();
}

TEST(ThreadPoolTest, DoesNotStopWhenTaskQueueIsEmptyBeforeWait) {
    ThreadPool pool(4);
    std::latch finished(1);
    pool.Enqueue(kPriorityDefault, [&] { finished.count_down(); });

    // Wait for the first task to complete.
    finished.wait();

    // Now the queue is empty, but the pool is still running.

    bool executed = false;
    pool.Enqueue(kPriorityDefault, [&] { executed = true; });

    pool.Wait();
    // The second task should have been executed.
    EXPECT_TRUE(executed);
}

TEST(ThreadPoolTest, EnqueueAfterStopFails) {
    ThreadPool pool(4);
    bool executed = false;
    pool.Enqueue(kPriorityDefault, [&] { executed = true; });
    pool.Wait();
    EXPECT_TRUE(executed);
    // The pool is stopped, so it should crash when a new task is enqueued.
    EXPECT_DEATH(pool.Enqueue(kPriorityDefault, [] {}), "");
}

TEST(ThreadPoolTest, ThreadNumberDoesNotChangeAfterQueueIsEmpty) {
    ThreadPool pool(2);

    // Enqueue one task and wait for it to complete.
    std::latch finished(1);
    pool.Enqueue(kPriorityDefault, [&] { finished.count_down(); });
    finished.wait();

    // Now the queue is empty, but the pool is still running.

    // Enqueue two tasks, and check if the number of threads in the pool is still 2.
    std::latch completed(3);
    for (size_t i = 0; i < 2; ++i) {
        pool.Enqueue(kPriorityDefault, [&] { completed.arrive_and_wait(); });
    }
    completed.arrive_and_wait();
    // We would not reach here if the number of worker threads in the pool was not 2.

    pool.Wait();
}

class ThreadPoolForTest {
  public:
    void SetWaitCallbackForTest(ThreadPool& pool, std::function<void()> callback) {
        pool.wait_callback_for_test_ = std::move(callback);
    }
};

TEST(ThreadPoolTest, EnqueueTasksWhileStopping) {
    ThreadPool pool(4);
    std::atomic<int> counter{0};
    std::latch started(1);
    std::latch cont(1);

    // Enqueue a task that will block, ensuring the pool has a busy thread.
    pool.Enqueue(kPriorityDefault, [&] {
        counter++;
        started.count_down();
        cont.wait();
    });

    // Wait for the first task to start.
    started.wait();

    ThreadPoolForTest t;
    t.SetWaitCallbackForTest(pool, [&] {
        // Now the thread pool is in State::Stopping.
        pool.Enqueue(kPriorityDefault, [&counter] { counter++; });
        // Unblock the first task.
        cont.count_down();
    });

    pool.Wait();

    // All tasks should have been executed.
    EXPECT_EQ(counter, 2);
}

TEST(ThreadPoolTest, PriorityIsPreserved) {
    ThreadPool pool(1);
    std::latch started(1);
    std::latch cont(1);
    std::vector<TestPriority> execution_order;
    std::mutex m;

    pool.Enqueue(kPriorityDefault, [&] {
        started.count_down();
        cont.wait();
    });

    started.wait();
    // The only worker thread is now blocked.

    pool.Enqueue(kPriorityLow, [&] {
        std::lock_guard lock(m);
        execution_order.push_back(kPriorityLow);
    });

    pool.Enqueue(kPriorityDefault, [&] {
        std::lock_guard lock(m);
        execution_order.push_back(kPriorityDefault);
    });

    pool.Enqueue(kPriorityHigh, [&] {
        std::lock_guard lock(m);
        execution_order.push_back(kPriorityHigh);
    });

    // Unblock the first task.
    cont.count_down();
    pool.Wait();

    EXPECT_THAT(execution_order, ElementsAre(kPriorityHigh, kPriorityDefault, kPriorityLow));
}

}  // namespace init
}  // namespace android
