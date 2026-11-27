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

#include <cstdlib>
#include <mutex>
#include <optional>
#include <thread>

#include <gtest/gtest.h>

#include "uevent.h"

namespace android {
namespace init {

TEST(UeventDependencyGraphTest, NoDependency) {
    UeventDependencyGraph graph;
    Uevent uevent1 = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
    Uevent uevent2 = {.action = "add", .path = "devices/block/sdb", .seqnum = 2};

    graph.Add(uevent1);
    graph.Add(uevent2);

    std::optional<Uevent> result1 = graph.PopDependencyFreeEvent();
    std::optional<Uevent> result2 = graph.PopDependencyFreeEvent();

    EXPECT_TRUE(result1.has_value());
    EXPECT_TRUE(result2.has_value());
    EXPECT_EQ(1, result1->seqnum);
    EXPECT_EQ(2, result2->seqnum);
}

TEST(UeventDependencyGraphTest, AncestorDependencies) {
    UeventDependencyGraph graph;
    Uevent uevent1 = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
    Uevent uevent2 = {.action = "add", .path = "devices/block/sda/child1", .seqnum = 2};
    Uevent uevent3 = {.action = "add", .path = "devices/block/sda/child2", .seqnum = 3};
    Uevent uevent4 = {.action = "add", .path = "devices/block/sda/child1/grandchild", .seqnum = 4};

    graph.Add(uevent1);
    graph.Add(uevent2);
    graph.Add(uevent3);
    graph.Add(uevent4);

    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent1.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent1.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent2.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent3.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent2.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent4.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
}

TEST(UeventDependencyGraphTest, DescendantDependencies) {
    UeventDependencyGraph graph;
    Uevent uevent1 = {
            .action = "remove", .path = "devices/block/sda/child1/grandchild", .seqnum = 1};
    Uevent uevent2 = {.action = "remove", .path = "devices/block/sda/child1", .seqnum = 2};
    Uevent uevent3 = {.action = "remove", .path = "devices/block/sda", .seqnum = 3};

    graph.Add(uevent1);
    graph.Add(uevent2);
    graph.Add(uevent3);

    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent1.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent1.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent2.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent2.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent3.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
}

TEST(UeventDependencyGraphTest, IdenticalEventDependencies) {
    UeventDependencyGraph graph;
    Uevent uevent1 = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
    Uevent uevent2 = {.action = "change", .path = "devices/block/sda", .seqnum = 2};
    Uevent uevent3 = {.action = "remove", .path = "devices/block/sda", .seqnum = 3};

    graph.Add(uevent1);
    graph.Add(uevent2);
    graph.Add(uevent3);

    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent1.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent1.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent2.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent2.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent3.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
}

TEST(UeventDependencyGraphTest, MixedDependencies) {
    UeventDependencyGraph graph;
    Uevent uevent = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
    Uevent uevent_child_dep = {
            .action = "add", .path = "devices/block/sda/child_dependency", .seqnum = 2};
    Uevent uevent_parent_dep = {.action = "change", .path = "devices/block/sda", .seqnum = 3};
    Uevent uevent_self_dep = {.action = "remove", .path = "devices/block/sda", .seqnum = 4};
    Uevent uevent_no_dependency = {.action = "add", .path = "devices/snd/foo", .seqnum = 5};

    graph.Add(uevent);
    graph.Add(uevent_child_dep);
    graph.Add(uevent_parent_dep);
    graph.Add(uevent_self_dep);
    graph.Add(uevent_no_dependency);

    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_no_dependency.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_child_dep.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent_child_dep.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_parent_dep.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent_parent_dep.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_self_dep.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent_self_dep.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
}

TEST(UeventDependencyGraphTest, DependsOnLaterEventsNotOnEarlier) {
    UeventDependencyGraph graph;
    Uevent uevent = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
    Uevent uevent_child_add = {
            .action = "add", .path = "devices/block/sda/child_dependency", .seqnum = 2};
    Uevent uevent_grandchild_add1 = {
            .action = "add", .path = "devices/block/sda/child_dependency", .seqnum = 3};
    Uevent uevent_removal = {.action = "remove", .path = "devices/block/sda", .seqnum = 4};
    Uevent uevent_grandchild_add2 = {
            .action = "add", .path = "devices/block/sda/child_dependency/grandchild", .seqnum = 5};

    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    graph.Add(uevent);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    // New events should not be immediately available due to the dependency.
    graph.Add(uevent_child_add);
    graph.Add(uevent_grandchild_add1);
    graph.Add(uevent_removal);
    graph.Add(uevent_grandchild_add2);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    // Should kick only uevent_child_add
    graph.MarkEventCompleted(uevent.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_child_add.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    // Should kick only uevent_grandchild_add1
    graph.MarkEventCompleted(uevent_child_add.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_grandchild_add1.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    // Should kick only uevent_removal
    graph.MarkEventCompleted(uevent_grandchild_add1.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_removal.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    // Should kick only uevent_grandchild_add2
    graph.MarkEventCompleted(uevent_removal.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_grandchild_add2.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    // No more events should be available
    graph.MarkEventCompleted(uevent_grandchild_add2.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
}

TEST(UeventDependencyGraphTest, PushEventsWithDependencyOnPending) {
    UeventDependencyGraph graph;
    Uevent uevent = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
    Uevent uevent_child_dep = {
            .action = "add", .path = "devices/block/sda/child_dependency", .seqnum = 2};
    Uevent uevent_grandchild_dep1 = {
            .action = "add",
            .path = "devices/block/sda/child_dependency/grandchild_dependency1",
            .seqnum = 3};
    Uevent uevent_grandchild_dep2 = {
            .action = "add",
            .path = "devices/block/sda/child_dependency/grandchild_dependency2",
            .seqnum = 4};

    graph.Add(uevent);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    graph.Add(uevent_child_dep);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.MarkEventCompleted(uevent.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_child_dep.seqnum);

    graph.Add(uevent_grandchild_dep1);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
    graph.Add(uevent_grandchild_dep2);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    graph.MarkEventCompleted(uevent_child_dep.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_grandchild_dep1.seqnum);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent_grandchild_dep2.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
}

TEST(UeventDependencyGraphTest, WaitDependencyFreeEventBlocksUntilDependencyIsMet) {
    UeventDependencyGraph graph;
    bool t_started = false;
    std::mutex m;
    std::condition_variable cv;

    Uevent uevent1 = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
    Uevent uevent2 = {.action = "add", .path = "devices/block/sda/child", .seqnum = 2};
    Uevent uevent3 = {.action = "add", .path = "devices/block/sda/child/grandchild", .seqnum = 3};

    graph.Add(uevent1);
    graph.Add(uevent2);
    graph.Add(uevent3);
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent1.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    std::thread t([&graph, &uevent2, &t_started, &m, &cv]() {
        m.lock();
        t_started = true;
        m.unlock();
        cv.notify_all();
        // Should wait until uevent2 is available
        EXPECT_EQ(graph.WaitDependencyFreeEvent().seqnum, uevent2.seqnum);
        // Unblock uevent3
        graph.MarkEventCompleted(uevent2.seqnum);
    });

    // Wait for the thread to start, which waits for uevent2
    std::unique_lock<std::mutex> lock(m);
    cv.wait(lock, [&t_started] { return t_started; });
    lock.unlock();
    // Kick the uevent2 for the thread
    graph.MarkEventCompleted(uevent1.seqnum);
    t.join();
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent3.seqnum);
}

TEST(UeventDependencyGraphTest, WaitDependencyFreeEventReturnsIfDependencyFreeOneIsAvailable) {
    UeventDependencyGraph graph;
    bool t_started = false;
    std::mutex m;
    std::condition_variable cv;

    Uevent uevent1 = {.action = "add", .path = "devices/block/sda", .seqnum = 1};
    Uevent uevent2 = {.action = "add", .path = "devices/block/sda/child", .seqnum = 2};
    Uevent uevent3 = {.action = "add", .path = "devices/block/sda/child/grandchild", .seqnum = 3};

    graph.Add(uevent1);
    graph.Add(uevent2);
    graph.Add(uevent3);

    // No dependency free events are available until uevent1 is processed
    EXPECT_EQ(graph.PopDependencyFreeEvent()->seqnum, uevent1.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());

    // Should kick uevent2 and WaitDependencyFreeEvent immediately returns it.
    graph.MarkEventCompleted(uevent1.seqnum);
    EXPECT_EQ(graph.WaitDependencyFreeEvent().seqnum, uevent2.seqnum);

    // Should kick uevent3 and WaitDependencyFreeEvent immediately returns it.
    graph.MarkEventCompleted(uevent2.seqnum);
    EXPECT_EQ(graph.WaitDependencyFreeEvent().seqnum, uevent3.seqnum);

    // No more events should be available
    graph.MarkEventCompleted(uevent3.seqnum);
    EXPECT_FALSE(graph.PopDependencyFreeEvent().has_value());
}

}  // namespace init
}  // namespace android
