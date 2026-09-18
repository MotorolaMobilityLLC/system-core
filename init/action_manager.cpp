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

#include "action_manager.h"

#include <variant>

#include <android-base/chrono_utils.h>
#include <android-base/logging.h>
#include <android-base/properties.h>

#include "action.h"
#include "util.h"

namespace android {
namespace init {

size_t ActionManager::CheckAllCommands() {
    size_t failures = 0;
    for (const auto& action : actions_) {
        failures += action->CheckAllCommands();
    }
    return failures;
}

ActionManager& ActionManager::GetInstance() {
    [[clang::no_destroy]] static ActionManager instance;
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
    std::vector<EventTrigger> triggered_events;
    {
        auto lock = std::lock_guard{event_queue_lock_};
        triggered_events.reserve(event_queue_.size());
        // Loop through the event queue until we have an action to execute
        while (current_executing_actions_.empty() && !event_queue_.empty()) {
            for (const auto& action : actions_) {
                if (std::visit([&action](const auto& event) { return action->CheckEvent(event); },
                               event_queue_.front())) {
                    current_executing_actions_.emplace(action.get());
                }
            }
            if (EventTrigger* trigger = std::get_if<EventTrigger>(&event_queue_.front())) {
                triggered_events.emplace_back(std::move(*trigger));
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

    // Set a property outside the event_queue_lock_ to avoid a deadlock.
    // Record when the first command for `on <event-name>` began execution.
    if (enables_init_event_timestamp_) {
        for (auto& event : triggered_events) {
            std::string trigger_time_prop =
                    property_prefix_for_testing_ + "ro.boottime.event." + event;
            if (!IsLegalPropertyName(trigger_time_prop)) {
                LOG(WARNING) << "an event boottime property '" << trigger_time_prop
                             << "' is not a legal property name. Skipping.";
                continue;
            }
            if (base::GetProperty(trigger_time_prop, "").empty()) {
                uint64_t clock_ns = base::boot_clock::now().time_since_epoch().count();
                if (!base::SetProperty(trigger_time_prop, std::to_string(clock_ns))) {
                    LOG(WARNING) << "failed to set property '" << trigger_time_prop << "'";
                }
            }
        }
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

}  // namespace init
}  // namespace android
