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

#include "thread_pool.h"

namespace android {
namespace init {

ThreadPool::ThreadPool(size_t num_threads) {
    std::lock_guard<std::mutex> lock(thread_lock_);
    for (size_t i = 0; i < num_threads; i++) {
        workers_.emplace_back(std::thread(&ThreadPool::RunWorker, this));
    }
}

void ThreadPool::Wait() {
    {
        std::lock_guard<std::mutex> lock(task_lock_);
        if (IsReadyToStop()) {
            state_ = State::Stopped;
        } else {
            state_ = State::Stopping;
        }
    }
    task_cond_.notify_all();

    if (wait_callback_for_test_) {
        wait_callback_for_test_();
    }

    {
        std::lock_guard<std::mutex> lock(thread_lock_);
        for (auto& worker : workers_) {
            worker.join();
        }
        workers_.clear();
    }
}

void ThreadPool::RunWorker() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(task_lock_);
            // Assertion is required to make thread safety annotations work well with a unique_lock
            base::ScopedLockAssertion mutex_lock_assertion(task_lock_);

            task_cond_.wait(lock, [this] {
                base::ScopedLockAssertion mutex_lock_assertion(task_lock_);
                return state_ == State::Stopped || !tasks_.empty();
            });

            if (state_ == State::Stopped) {
                // thread pool is stopped at the end of the loop only when there are no more tasks
                // and no running threads.
                CHECK(tasks_.empty());
                break;
            }

            task = std::move(tasks_.top().fn);
            tasks_.pop();
            busy_threads_++;
        }
        task();
        {
            std::lock_guard<std::mutex> lock(task_lock_);
            busy_threads_--;
            // If there are no more tasks, no running threads, and Wait() has been called, then stop
            // the thread pool.
            if (state_ != State::Running && IsReadyToStop()) {
                state_ = State::Stopped;
                task_cond_.notify_all();
                break;
            }
        }
    }
}

bool ThreadPool::IsReadyToStop() const {
    return tasks_.empty() && busy_threads_ == 0;
}

}  // namespace init
}  // namespace android
