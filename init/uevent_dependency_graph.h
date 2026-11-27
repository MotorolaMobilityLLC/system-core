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

#include <condition_variable>
#include <map>
#include <queue>
#include <set>

#include <android-base/thread_annotations.h>

#include "uevent.h"

namespace android {
namespace init {

/**
 * Manages dependencies between uevents to ensure they are processed in the correct order.
 *
 * Uevents often have dependencies based on their device path. For example, a child device's
 * uevent should typically be processed only after its parent device's uevent has been processed.
 * Similarly, events for the same device should be processed sequentially based on their sequence
 * number.
 *
 * This class builds a dependency graph based on device paths and sequence numbers. It allows
 * adding new uevents and retrieving events that have no outstanding dependencies, ready for
 * processing. Once an event is processed, it should be marked as completed to unblock any
 * dependent events.
 *
 * This class is thread-safe.
 */
class UeventDependencyGraph {
    using seqnum_t = long long;

  public:
    UeventDependencyGraph() = default;

    /**
     * Adds a new uevent to the dependency graph.
     *
     * @param uevent The uevent to add to the graph.
     */
    void Add(Uevent uevent);

    /**
     * Retrieves and removes a uevent that has no outstanding dependencies.
     *
     * This method returns any uevents ready for processing (i.e., all their
     * dependencies have been met).  If no events are ready, it returns std::nullopt immediately.
     *
     * @return An optional containing a dependency-free uevent if one is available, otherwise
     * std::nullopt.
     */
    std::optional<Uevent> PopDependencyFreeEvent();

    /**
     * Waits until a dependency-free uevent is available, then retrieves and removes it.
     *
     * If no dependency-free events are currently available, this method blocks until one becomes
     * available (due to a call to Add() or MarkEventCompleted()).
     *
     * @return The next available dependency-free uevent.
     */
    Uevent WaitDependencyFreeEvent();

    /**
     * Marks a uevent as completed, potentially unblocking dependent events.
     *
     * @param seqnum The sequence number of the uevent that has been completed.
     */
    void MarkEventCompleted(seqnum_t seqnum);

  private:
    /**
     * Finds the sequence number of the latest event that the given uevent depends on.
     *
     * @param uevent The uevent to find dependencies for.
     * @return An optional containing the sequence number of the dependency if found, otherwise
     * std::nullopt.
     */
    std::optional<seqnum_t> FindDependency(const Uevent& uevent)
            EXCLUSIVE_LOCKS_REQUIRED(graph_lock_);

    /**
     * Internal implementation of PopDependencyFreeEvent without locking.
     * Assumes the caller holds the graph_lock_.
     *
     * @return An optional containing a dependency-free uevent if one is available, otherwise
     * std::nullopt.
     */
    std::optional<Uevent> PopDependencyFreeEventWithoutLock() EXCLUSIVE_LOCKS_REQUIRED(graph_lock_);

    std::condition_variable graph_condvar_;
    std::mutex graph_lock_;
    // Stores all uevents currently in the graph, keyed by sequence number.
    std::map<seqnum_t, Uevent> events_ GUARDED_BY(graph_lock_);
    // Queue of events that are ready to be processed.
    std::queue<seqnum_t> dependency_free_events_ GUARDED_BY(graph_lock_);
    // Multimap storing dependencies: key is the sequence number of the prerequisite event,
    // value is the sequence number of the dependent event.
    std::multimap<seqnum_t, seqnum_t> dependencies_ GUARDED_BY(graph_lock_);
    // Set storing pairs of (device path, sequence number) for efficient dependency lookup.
    std::set<std::pair<std::string, seqnum_t>> event_paths_ GUARDED_BY(graph_lock_);
};

}  // namespace init
}  // namespace android
