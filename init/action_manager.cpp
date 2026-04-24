/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifdef G1122717
#include <set>
#endif

#if defined(MTK_LOG) && defined(MTK_COMMAND_WDOG)
#include <sys/eventfd.h>
#include <thread>
#include <android-base/chrono_utils.h>
#include <android-base/stringprintf.h>

#include "epoll.h"

using android::base::boot_clock;
using android::base::StringPrintf;
#endif

#include "action_manager.h"

#include <android-base/logging.h>

namespace android {
namespace init {

ActionManager::ActionManager() : current_command_(0) {}

#if defined(MTK_LOG) && defined(MTK_COMMAND_WDOG)
struct CommSetLogInfo {
    bool isStart;
    std::string log;
};

static std::mutex pending_wd_messages_lock;
static std::queue<struct CommSetLogInfo> pending_wd_messages;
static std::string wd_comm;
static boot_clock::time_point starttime_wd_comm;

static std::thread comm_wd_thread;

static int wake_wd_thread_fd = -1;
static uint64_t wd_wait_time = 0;

enum class WDThreadState {
    kNotStarted,  // Initial state when starting the program or when restarting with no items to
                  // process.
    kWaiting_1,   // The thread is running and is in a state that it will process new items if
                  // are run.
};

static WDThreadState wd_thread_state_ = WDThreadState::kNotStarted;

static void DropWDSocket() {
    uint64_t counter;
    TEMP_FAILURE_RETRY(read(wake_wd_thread_fd, &counter, sizeof(counter)));
}

static void HandleWDSocket() {
    auto lock = std::unique_lock{pending_wd_messages_lock};

    uint64_t nowms = std::chrono::duration_cast<std::chrono::milliseconds>(boot_clock::now().time_since_epoch()).count();

    while (!pending_wd_messages.empty()) {
        auto wd_message = pending_wd_messages.front();
        pending_wd_messages.pop();

        switch (wd_thread_state_) {
            case WDThreadState::kNotStarted:
                if (wd_message.isStart) {
                    wd_thread_state_ = WDThreadState::kWaiting_1;
                    wd_wait_time = nowms + 3000;
                    wd_comm = wd_message.log;
                    starttime_wd_comm = boot_clock::now();
                }
                break;
            case WDThreadState::kWaiting_1:
                if (!wd_message.isStart) {
                    wd_thread_state_ = WDThreadState::kNotStarted;
                    wd_wait_time = 0;
                }
                break;
            default:
                break;
        }
    }
}

static void HandleWDSocket_wrap() {
    DropWDSocket();
    HandleWDSocket();
}

static void CheckWDTimeout(uint64_t nowms) {
    auto lock = std::unique_lock{pending_wd_messages_lock};
    bool dump_stack = false;
    std::string dumpstr;
    std::string waitstr;

    switch (wd_thread_state_) {
        case WDThreadState::kWaiting_1:
            if (nowms >= wd_wait_time) {
                dump_stack = true;
                wd_wait_time = nowms + 1000;
                dumpstr = wd_comm;

                auto duration = boot_clock::now() - starttime_wd_comm;
                auto duration_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
                waitstr.append("Have been waiting ");
                waitstr.append(StringPrintf("%llu", duration_ms));
                waitstr.append("ms for ");
            }
            break;
        default:
            break;
    }

    if (dump_stack) {
        lock.unlock();
        LOG(INFO) << waitstr << dumpstr;
        lock.lock();
    }
}

static void InstallWDNotifier(Epoll* epoll) {
    wake_wd_thread_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake_wd_thread_fd == -1) {
        PLOG(FATAL) << "Failed to create eventfd for waking property watchdog.";
    }

    if (auto result = epoll->RegisterHandler(wake_wd_thread_fd, HandleWDSocket_wrap); !result.ok()) {
        LOG(FATAL) << result.error();
    }
}

static void WakePROPWDThread() {
    uint64_t counter = 1;
    TEMP_FAILURE_RETRY(write(wake_wd_thread_fd, &counter, sizeof(counter)));
}

void ActionManager::QueueCommWDMessage(const std::string& msg, bool isStart) {
    auto lock = std::lock_guard{pending_wd_messages_lock};

    struct CommSetLogInfo comminfo;
    comminfo.isStart = isStart;
    comminfo.log = msg;

    pending_wd_messages.push(comminfo);
    WakePROPWDThread();
}

static void CommWDThread() {
    Epoll epoll;
    if (auto result = epoll.Open(); !result.ok()) {
        LOG(FATAL) << result.error();
    }

    InstallWDNotifier(&epoll);

    while (true) {
        auto epoll_timeout = std::optional<std::chrono::milliseconds>{};

        uint64_t nowms = std::chrono::duration_cast<std::chrono::milliseconds>(boot_clock::now().time_since_epoch()).count();

        CheckWDTimeout(nowms);

        if (wd_wait_time) {
            epoll_timeout = 0ms;

            if (nowms < wd_wait_time)
                epoll_timeout = std::chrono::milliseconds(wd_wait_time - nowms);
        }

        auto pending_functions = epoll.Wait(epoll_timeout);

        if (!pending_functions.ok()) {
            LOG(ERROR) << pending_functions.error();
        } else {
            for (const auto& function : *pending_functions) {
                (*function)();
            }
        }
    }
}
#endif

size_t ActionManager::CheckAllCommands() {
    size_t failures = 0;
    for (const auto& action : actions_) {
        failures += action->CheckAllCommands();
    }
    return failures;
}

ActionManager& ActionManager::GetInstance() {
    static ActionManager instance;
    return instance;
}

void ActionManager::AddAction(std::unique_ptr<Action> action) {
    actions_.emplace_back(std::move(action));
}

void ActionManager::QueueEventTrigger(const std::string& trigger) {
    auto lock = std::lock_guard{event_queue_lock_};
    event_queue_.emplace(trigger);
}

void ActionManager::QueuePropertyChange(const std::string& name, const std::string& value) {
    auto lock = std::lock_guard{event_queue_lock_};
    event_queue_.emplace(std::make_pair(name, value));
}

void ActionManager::QueueAllPropertyActions() {
    QueuePropertyChange("", "");
}

void ActionManager::QueueBuiltinAction(BuiltinFunction func, const std::string& name) {
    auto lock = std::lock_guard{event_queue_lock_};
    auto action = std::make_unique<Action>(true, nullptr, "<Builtin Action>", 0, name,
                                           std::map<std::string, std::string>{});
    action->AddCommand(std::move(func), {name}, 0);

    event_queue_.emplace(action.get());
    actions_.emplace_back(std::move(action));
}

void ActionManager::ExecuteOneCommand() {
    {
        auto lock = std::lock_guard{event_queue_lock_};
        // Loop through the event queue until we have an action to execute
        while (current_executing_actions_.empty() && !event_queue_.empty()) {
            for (const auto& action : actions_) {
                if (std::visit([&action](const auto& event) { return action->CheckEvent(event); },
                               event_queue_.front())) {
                    current_executing_actions_.emplace(action.get());
                }
            }
            event_queue_.pop();
        }
    }

    if (current_executing_actions_.empty()) {
        return;
    }

    auto action = current_executing_actions_.front();

    if (current_command_ == 0) {
        std::string trigger_name = action->BuildTriggersString();
        LOG(INFO) << "processing action (" << trigger_name << ") from (" << action->filename()
                  << ":" << action->line() << ")";
    }

    action->ExecuteOneCommand(current_command_);

    // If this was the last command in the current action, then remove
    // the action from the executing list.
    // If this action was oneshot, then also remove it from actions_.
    ++current_command_;
    if (current_command_ == action->NumCommands()) {
        current_executing_actions_.pop();
        current_command_ = 0;
        if (action->oneshot()) {
            auto eraser = [&action](std::unique_ptr<Action>& a) { return a.get() == action; };
            actions_.erase(std::remove_if(actions_.begin(), actions_.end(), eraser),
                           actions_.end());
        }
    }
}

bool ActionManager::HasMoreCommands() const {
    auto lock = std::lock_guard{event_queue_lock_};
    return !current_executing_actions_.empty() || !event_queue_.empty();
}

void ActionManager::DumpState() const {
    for (const auto& a : actions_) {
        a->DumpState();
    }
}

void ActionManager::ClearQueue() {
    auto lock = std::lock_guard{event_queue_lock_};
    // We are shutting down so don't claim the oneshot builtin actions back
    current_executing_actions_ = {};
    event_queue_ = {};
    current_command_ = 0;
}

#ifdef G1122717
void ActionManager::StartWatchingProperty(const std::string& property) {
    auto lock = std::lock_guard{event_queue_lock_};
    init_watched_properties.emplace(property);
}

bool ActionManager::WatchingPropertyCount(const std::string& property) {
    auto lock = std::lock_guard{event_queue_lock_};
    if (init_watched_properties.count(property))
        return true;

    return false;
}
#endif

#if defined(MTK_LOG) && defined(MTK_COMMAND_WDOG)
void ActionManager::StartCommandWDOG(void) {
    auto new_wd_thread = std::thread{CommWDThread};
    comm_wd_thread.swap(new_wd_thread);
}
#endif

}  // namespace init
}  // namespace android
