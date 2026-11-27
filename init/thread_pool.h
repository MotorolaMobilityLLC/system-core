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
 * WITHOUT WARRANTIES OR condition_S OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include <android-base/logging.h>
#include <android-base/thread_annotations.h>

namespace android {
namespace init {

struct Task {
    std::function<void()> fn;
    int priority;

    // Smaller `priority` is prioritized in the queue.
    bool operator<(const Task& other) const { return priority > other.priority; }
};

/**
 * A thread pool that executes tasks in parallel.
 */
class ThreadPool {
  public:
    /**
     * Constructs a thread pool with the given number of threads.
     *
     * @param num_threads The number of threads to use with its default value being the number of
     *                    hardware threads.
     */
    ThreadPool(size_t num_threads = std::thread::hardware_concurrency());

    /**
     * Enqueues a task and its arguments with the given priority.
     *
     * @param priority The priority of the task. The smaller, the more prioritized.
     * @param f The task function.
     */
    template <class F, class... Args>
    void Enqueue(int priority, F&& f) {
        {
            std::lock_guard<std::mutex> lock(task_lock_);
            CHECK(state_ != State::Stopped);
            tasks_.push(Task{std::forward<F>(f), priority});
        }
        task_cond_.notify_one();
    }

    /**
     * Waits for all tasks to finish, and shut down the thread pool.  No more tasks can be enqueued
     * after.
     */
    void Wait();

  private:
    friend class ThreadPoolForTest;

    enum class State {
        // The thread pool is running and accepting tasks.
        Running,
        // The thread pool is stopping but still accepting tasks.
        Stopping,
        // The thread pool is stopped and no new tasks can be enqueued.
        Stopped,
    };

    std::mutex thread_lock_;
    std::vector<std::thread> workers_ GUARDED_BY(thread_lock_);
    std::mutex task_lock_;
    std::condition_variable task_cond_;
    std::priority_queue<Task> tasks_ GUARDED_BY(task_lock_);
    size_t busy_threads_ GUARDED_BY(task_lock_){0};
    State state_ GUARDED_BY(task_lock_){State::Running};

    /**
     * The main loop of the worker thread.
     */
    void RunWorker();

    /**
     * Returns if there are no queued or running tasks.
     */
    bool IsReadyToStop() const EXCLUSIVE_LOCKS_REQUIRED(task_lock_);

    // Prevent copy and move
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    // Test-only function called after the state transition and before joining threads to ensure the
    // deterministic behavior of the thread pool during testing.
    std::function<void()> wait_callback_for_test_;
};

}  // namespace init
}  // namespace android
