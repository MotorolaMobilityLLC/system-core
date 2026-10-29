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

#pragma once

#include <mutex>
#include <string>
#include <vector>

#include <android-base/thread_annotations.h>

#include "action.h"
#include "builtins.h"

namespace android {
namespace init {

class ActionManager {
  public:
    static ActionManager& GetInstance();

    // Exposed for testing
    ActionManager() {};
    ActionManager(std::string property_prefix_for_testing)
        : property_prefix_for_testing_(std::move(property_prefix_for_testing)) {};
    size_t CheckAllCommands();

    void AddAction(std::unique_ptr<Action> action);
    template <class UnaryPredicate>
    void RemoveActionIf(UnaryPredicate predicate) {
        actions_.erase(std::remove_if(actions_.begin(), actions_.end(), predicate), actions_.end());
    }
    void QueueEventTrigger(const std::string& trigger);
    void QueuePropertyChange(const std::string& name, const std::string& value);
    void QueueAllPropertyActions();
    void QueueBuiltinAction(BuiltinFunction func, const std::string& name);
    void ExecuteOneCommand();
    bool HasMoreCommands() const;
    void DumpState() const;
    void ClearQueue();
    auto size() const { return actions_.size(); }
    void EnableInitEventTimestamp(bool enable) { enables_init_event_timestamp_ = enable; }

  private:
    ActionManager(ActionManager const&) = delete;
    void operator=(ActionManager const&) = delete;

    std::vector<std::unique_ptr<Action>> actions_;
    std::queue<std::variant<EventTrigger, PropertyChange, BuiltinAction>> event_queue_
            GUARDED_BY(event_queue_lock_);
    mutable std::mutex event_queue_lock_;
    std::queue<const Action*> current_executing_actions_;
    std::size_t current_command_ = 0;
    // feature flag to enable the new `ro.boottime.event.<event>` props
    bool enables_init_event_timestamp_ = false;

    // Override system property prefix for testing
    const std::string property_prefix_for_testing_ = "";
};

}  // namespace init
}  // namespace android
