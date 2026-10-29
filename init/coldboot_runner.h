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

#include <memory>
#include <set>
#include <string>
#include <vector>

#include <unistd.h>

#include "thread_pool.h"
#include "uevent.h"
#include "uevent_handler.h"

namespace android {
namespace init {

void RestoreconRecurse(const std::string& dir);

class ColdbootRunner {
  public:
    virtual ~ColdbootRunner() = default;
    virtual void StartInBackground() = 0;
    virtual void Wait() = 0;
};

class ColdbootRunnerSubprocess : public ColdbootRunner {
  public:
    ColdbootRunnerSubprocess(unsigned int num_handler_processes,
                             const std::vector<Uevent>& uevent_queue,
                             const std::vector<std::shared_ptr<UeventHandler>>& uevent_handlers,
                             bool enable_parallel_restorecon,
                             const std::vector<std::string>& restorecon_queue);

    void StartInBackground() override;
    void Wait() override;

  private:
    void UeventHandlerMain(unsigned int process_num, unsigned int total_processes);

    void RestoreConHandler(unsigned int process_num, unsigned int total_processes);

    unsigned int num_handler_subprocesses_;
    const std::vector<Uevent>& uevent_queue_;
    const std::vector<std::shared_ptr<UeventHandler>>& uevent_handlers_;
    bool enable_parallel_restorecon_;
    const std::vector<std::string>& restorecon_queue_;
    std::set<pid_t> subprocess_pids_;
};

class ColdbootRunnerThreadPool : public ColdbootRunner {
  public:
    ColdbootRunnerThreadPool(unsigned int num_threads, const std::vector<Uevent>& uevent_queue,
                             const std::vector<std::shared_ptr<UeventHandler>>& uevent_handlers,
                             bool enable_parallel_restorecon,
                             const std::vector<std::string>& restorecon_queue);

    void StartInBackground() override;

    void Wait() override;

  private:
    const std::vector<Uevent>& uevent_queue_;
    const std::vector<std::shared_ptr<UeventHandler>>& uevent_handlers_;
    bool enable_parallel_restorecon_;
    const std::vector<std::string>& restorecon_queue_;
    ThreadPool thread_pool_;
};

}  // namespace init
}  // namespace android
