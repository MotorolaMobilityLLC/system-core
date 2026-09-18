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

#include "uevent_dependency_graph.h"

#include <condition_variable>
#include <mutex>
#include <optional>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/thread_annotations.h>

namespace android {
namespace init {

/**
 * Finds the sequence number of the latest event that the given uevent depends on.
 * Dependencies arise from:
 * 1. Ancestor devices (e.g., "devices/block/sda" must be processed before
 *    "devices/block/sda/sda1").
 * 2. Descendant devices for "remove" actions (e.g., "devices/block/sda/sda1" must be removed
 *    before "devices/block/sda").
 * 3. Events for the identical device path with a lower sequence number.
 * Note rename events are not processed currently since it's not processed in the main ueventd.
 */
std::optional<UeventDependencyGraph::seqnum_t> UeventDependencyGraph::FindDependency(
        const Uevent& uevent) {
    int max_seqnum = -1;

    // e.g. devices/virtual/mac80211_hwsim/hwsim0 is descendant of devices/virtual/mac80211_hwsim.
    // They immediately follow uevent.path in the sorted event_paths_ map.
    auto descendant = event_paths_.upper_bound({uevent.path, uevent.seqnum});
    while (descendant != event_paths_.end() && descendant->first.starts_with(uevent.path)) {
        if (descendant->second < uevent.seqnum && descendant->second > max_seqnum) {
            max_seqnum = descendant->second;
        }
        descendant++;
    }

    // Find events of ancestor devices and the identical device with lower seqnum.
    // e.g. devices/some_device is descendant of devices/some_device/wakeup
    for (auto ancestor = uevent.path; ancestor != "/" && ancestor != ".";
         ancestor = base::Dirname(ancestor)) {
        auto it = event_paths_.upper_bound({ancestor, uevent.seqnum});
        if (it == event_paths_.begin()) {
            continue;
        }
        it--;
        if (it->first == ancestor && it->second > max_seqnum) {
            max_seqnum = it->second;
        }
    }

    if (max_seqnum == -1) {
        return std::nullopt;
    } else {
        return {max_seqnum};
    }
}

void UeventDependencyGraph::Add(Uevent uevent) {
    bool should_wake_thread = false;
    {
        std::lock_guard<std::mutex> lock(graph_lock_);
        std::optional<UeventDependencyGraph::seqnum_t> dependency = FindDependency(uevent);
        if (dependency) {
            dependencies_.emplace(dependency.value(), uevent.seqnum);
        } else {
            dependency_free_events_.emplace(uevent.seqnum);
            should_wake_thread = true;
        }
        event_paths_.emplace(uevent.path, uevent.seqnum);
        events_.emplace(uevent.seqnum, std::move(uevent));
    }
    if (should_wake_thread) {
        graph_condvar_.notify_one();
    }
}

std::optional<Uevent> UeventDependencyGraph::PopDependencyFreeEventWithoutLock() {
    if (dependency_free_events_.empty()) {
        return std::nullopt;
    }
    auto seqnum = dependency_free_events_.front();
    dependency_free_events_.pop();
    return events_.find(seqnum)->second;
}

std::optional<Uevent> UeventDependencyGraph::PopDependencyFreeEvent() {
    std::lock_guard<std::mutex> lock(graph_lock_);
    return PopDependencyFreeEventWithoutLock();
}

Uevent UeventDependencyGraph::WaitDependencyFreeEvent() {
    std::unique_lock<std::mutex> lock(graph_lock_);
    // Assertion is required to make thread safety annotations work well with a unique_lock
    base::ScopedLockAssertion mutex_lock_assertion(graph_lock_);

    if (dependency_free_events_.empty()) {
        graph_condvar_.wait(lock, [this] {
            base::ScopedLockAssertion mutex_lock_assertion(graph_lock_);
            return !dependency_free_events_.empty();
        });
    }

    return PopDependencyFreeEventWithoutLock().value();
}

void UeventDependencyGraph::MarkEventCompleted(seqnum_t seqnum) {
    bool should_wake_thread = false;
    {
        std::lock_guard<std::mutex> lock(graph_lock_);
        auto dependency = dependencies_.equal_range(seqnum);
        for (auto it = dependency.first; it != dependency.second; ++it) {
            dependency_free_events_.emplace(it->second);
            should_wake_thread = true;
        }
        dependencies_.erase(dependency.first, dependency.second);
        event_paths_.erase({events_.find(seqnum)->second.path, seqnum});
        events_.erase(seqnum);
    }
    if (should_wake_thread) {
        graph_condvar_.notify_one();
    }
}

}  // namespace init
}  // namespace android
