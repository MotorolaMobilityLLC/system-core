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

#include <modprobe/module_dependency_graph.h>

#include <unordered_set>

#include <android-base/file.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "module_config_test.h"

using testing::UnorderedElementsAre;

namespace android {
namespace modprobe {

static std::unordered_set<std::string> LoadAllModules(ModuleDependencyGraph& graph) {
    std::unordered_set<std::string> loaded_module_paths;
    while (true) {
        const auto& m = graph.PopReadyModules();
        if (m.empty()) {
            break;
        }
        for (const auto& ready : m) {
            graph.MarkModuleLoaded(ready);
            loaded_module_paths.emplace(ready);
        }
    }
    return loaded_module_paths;
}

TEST(ModuleDependencyGraphTest, NoDependency) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko:\n"
            "test2.ko:\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, "", "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test0");
    graph.AddModule("test1");
    graph.AddModule("test2");

    const auto& m = LoadAllModules(graph);
    EXPECT_THAT(m, UnorderedElementsAre(std::string(dir.path) + "/test0.ko",
                                        std::string(dir.path) + "/test1.ko",
                                        std::string(dir.path) + "/test2.ko"));
}

TEST(ModuleDependencyGraphTest, SimpleDependency) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n"
            "test2.ko: test1.ko\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, "", "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test2");

    const auto& m1 = graph.PopReadyModules();
    EXPECT_THAT(m1, UnorderedElementsAre(std::string(dir.path) + "/test0.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test0.ko");
    const auto& m2 = graph.PopReadyModules();
    EXPECT_THAT(m2, UnorderedElementsAre(std::string(dir.path) + "/test1.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test1.ko");
    const auto& m3 = graph.PopReadyModules();
    EXPECT_THAT(m3, UnorderedElementsAre(std::string(dir.path) + "/test2.ko"));
}

TEST(ModuleDependencyGraphTest, SimpleDependencyFailed) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n"
            "test2.ko: test1.ko\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, "", "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test2");

    const auto& m1 = graph.PopReadyModules();
    EXPECT_THAT(m1, UnorderedElementsAre(std::string(dir.path) + "/test0.ko"));

    graph.MarkModuleLoadFailed(std::string(dir.path) + "/test0.ko");
    const auto& m2 = graph.PopReadyModules();
    EXPECT_TRUE(m2.empty());

    graph.MarkModuleLoaded(std::string(dir.path) + "/test0.ko");
    const auto& m3 = graph.PopReadyModules();
    EXPECT_THAT(m3, UnorderedElementsAre(std::string(dir.path) + "/test1.ko"));

    graph.MarkModuleLoadFailed(std::string(dir.path) + "/test1.ko");
    const auto& m4 = graph.PopReadyModules();
    EXPECT_TRUE(m4.empty());

    graph.MarkModuleLoaded(std::string(dir.path) + "/test1.ko");
    const auto& m5 = graph.PopReadyModules();
    EXPECT_THAT(m5, UnorderedElementsAre(std::string(dir.path) + "/test2.ko"));
}

TEST(ModuleDependencyGraphTest, SimplePreSoftdep) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n"
            "test2.ko:\n";
    const std::string softdep = "softdep test0 pre: test2\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, softdep, "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test0");
    graph.AddModule("test1");

    const auto& m1 = graph.PopReadyModules();
    EXPECT_THAT(m1, UnorderedElementsAre(std::string(dir.path) + "/test2.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test2.ko");
    const auto& m2 = graph.PopReadyModules();
    EXPECT_THAT(m2, UnorderedElementsAre(std::string(dir.path) + "/test0.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test0.ko");
    const auto& m3 = graph.PopReadyModules();
    EXPECT_THAT(m3, UnorderedElementsAre(std::string(dir.path) + "/test1.ko"));
}

TEST(ModuleDependencyGraphTest, SimplePreSoftdepLoadFailed) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n"
            "test2.ko:\n";
    const std::string softdep = "softdep test0 pre: test2\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, softdep, "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test0");
    graph.AddModule("test1");

    const auto& m1 = graph.PopReadyModules();
    EXPECT_THAT(m1, UnorderedElementsAre(std::string(dir.path) + "/test2.ko"));

    graph.MarkModuleLoadFailed(std::string(dir.path) + "/test2.ko");
    const auto& m2 = graph.PopReadyModules();
    EXPECT_THAT(m2, UnorderedElementsAre(std::string(dir.path) + "/test0.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test0.ko");
    const auto& m3 = graph.PopReadyModules();
    EXPECT_THAT(m3, UnorderedElementsAre(std::string(dir.path) + "/test1.ko"));
}

TEST(ModuleDependencyGraphTest, SimplePostSoftdep) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n"
            "test2.ko:\n";
    const std::string softdep = "softdep test1 post: test2\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, softdep, "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test0");
    graph.AddModule("test1");

    const auto& m1 = graph.PopReadyModules();
    EXPECT_THAT(m1, UnorderedElementsAre(std::string(dir.path) + "/test0.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test0.ko");
    const auto& m2 = graph.PopReadyModules();
    EXPECT_THAT(m2, UnorderedElementsAre(std::string(dir.path) + "/test1.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test1.ko");
    const auto& m3 = graph.PopReadyModules();
    EXPECT_THAT(m3, UnorderedElementsAre(std::string(dir.path) + "/test2.ko"));
}

TEST(ModuleDependencyGraphTest, SimpleAlias) {
    const std::string deps = "test0.ko:\n";
    const std::string aliases = "alias test_zero_* test0\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, aliases, deps, "", "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test_zero_some_random_id");

    const auto& m = LoadAllModules(graph);
    EXPECT_THAT(m, UnorderedElementsAre(std::string(dir.path) + "/test0.ko"));
}

TEST(ModuleDependencyGraphTest, AliasInPreSoftdep) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n"
            "test2.ko:\n";
    const std::string softdep = "softdep test0 pre: test_two_some_random_id\n";
    const std::string aliases = "alias test_two_* test2\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, aliases, deps, softdep, "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test0");
    graph.AddModule("test1");

    const auto& m1 = graph.PopReadyModules();
    EXPECT_THAT(m1, UnorderedElementsAre(std::string(dir.path) + "/test2.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test2.ko");
    const auto& m2 = graph.PopReadyModules();
    EXPECT_THAT(m2, UnorderedElementsAre(std::string(dir.path) + "/test0.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test0.ko");
    const auto& m3 = graph.PopReadyModules();
    EXPECT_THAT(m3, UnorderedElementsAre(std::string(dir.path) + "/test1.ko"));
}

TEST(ModuleDependencyGraphTest, HandlesLoopHarddep) {
    const std::string deps =
            "test0.ko: test1.ko\n"
            "test1.ko: test2.ko\n"
            "test2.ko: test0.ko\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, "", "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test0");
    // No modules should be ready due to dependency loop.
    EXPECT_TRUE(graph.PopReadyModules().empty());
}

TEST(ModuleDependencyGraphTest, HandlesLoopSoftAndHarddep) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n";
    const std::string softdep = "softdep test0 pre: test1\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, softdep, "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test0");
    // No modules should be ready due to dependency loop.
    EXPECT_TRUE(graph.PopReadyModules().empty());
}

TEST(ModuleDependencyGraphTest, HandlesLoopAliasedSoftAndHarddep) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n";
    const std::string softdep = "softdep test0 pre: test_one_some_random_id\n";
    const std::string aliases = "alias test_one_* test1";
    TemporaryDir dir;
    WriteModuleConfigs(dir, aliases, deps, softdep, "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test0");
    // No modules should be ready due to dependency loop.
    EXPECT_TRUE(graph.PopReadyModules().empty());
}

TEST(ModuleDependencyGraphTest, BlocklistHarddep) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n"
            "test2.ko: test1.ko\n";
    const std::string blocklist = "blocklist test1\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, "", "", "", blocklist);

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test0");
    graph.AddModule("test1");

    const auto& m = LoadAllModules(graph);
    EXPECT_THAT(m, UnorderedElementsAre(std::string(dir.path) + "/test0.ko"));
}

TEST(ModuleDependencyGraphTest, BlocklistSoftdep) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko:\n"
            "test2.ko:\n";
    const std::string softdep =
            "softdep test0 pre: test1\n"
            "softdep test0 post: test2\n";
    const std::string blocklist = "blocklist test1\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, softdep, "", "", blocklist);

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test0");

    const auto& m = LoadAllModules(graph);
    EXPECT_TRUE(m.empty());
}

TEST(ModuleDependencyGraphTest, AddModuleAfterLoad) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n"
            "test2.ko: test1.ko\n"
            "test3.ko: test1.ko\n"
            "test4.ko: test3.ko\n";
    TemporaryDir dir;
    WriteModuleConfigs(dir, "", deps, "", "", "", "");

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));
    graph.AddModule("test2");

    const auto& m1 = LoadAllModules(graph);
    EXPECT_THAT(m1, UnorderedElementsAre(std::string(dir.path) + "/test0.ko",
                                         std::string(dir.path) + "/test1.ko",
                                         std::string(dir.path) + "/test2.ko"));

    graph.AddModule("test4");

    const auto& m2 = LoadAllModules(graph);
    EXPECT_THAT(m2, UnorderedElementsAre(std::string(dir.path) + "/test3.ko",
                                         std::string(dir.path) + "/test4.ko"));
}

TEST(ModuleDependencyGraphTest, MixedDependencies) {
    const std::string deps =
            "test0.ko:\n"
            "test1.ko: test0.ko\n"
            "test2.ko: test1.ko\n"
            "test3.ko:\n"
            "test4.ko:\n"
            "test5.ko:\n"
            "test6.ko:\n";
    const std::string aliases =
            "alias test_one_* test1\n"
            "alias test_three_* test3\n"
            "alias test_five_* test5\n"
            "alias test_six_* test6\n";
    const std::string softdep =
            "softdep test0 pre: test_three_some_random_id\n"
            "softdep test2 pre: test4\n"
            "softdep test1 post: test_five_some_random_id test_six_some_random_id\n";
    const std::string blocklist = "blocklist test2\n";

    TemporaryDir dir;
    WriteModuleConfigs(dir, aliases, deps, softdep, "", "", blocklist);

    ModuleDependencyGraph graph(ModuleConfig::Parse({dir.path}));

    graph.AddModule("test0");
    graph.AddModule("test_one_some_random_id");
    graph.AddModule("test2");

    const auto& m1 = graph.PopReadyModules();
    EXPECT_THAT(m1, UnorderedElementsAre(std::string(dir.path) + "/test3.ko"));

    graph.MarkModuleLoadFailed(std::string(dir.path) + "/test3.ko");
    const auto& m2 = graph.PopReadyModules();
    EXPECT_THAT(m2, UnorderedElementsAre(std::string(dir.path) + "/test0.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test0.ko");
    const auto& m3 = graph.PopReadyModules();
    EXPECT_THAT(m3, UnorderedElementsAre(std::string(dir.path) + "/test1.ko"));

    graph.MarkModuleLoaded(std::string(dir.path) + "/test1.ko");
    const auto& m4 = graph.PopReadyModules();
    EXPECT_THAT(m4, UnorderedElementsAre(std::string(dir.path) + "/test5.ko",
                                         std::string(dir.path) + "/test6.ko"));

    // No more dependency free modules because test2 is blocklisted
    graph.MarkModuleLoaded(std::string(dir.path) + "/test5.ko");
    const auto& m5 = graph.PopReadyModules();
    EXPECT_TRUE(m5.empty());

    graph.MarkModuleLoaded(std::string(dir.path) + "/test6.ko");
    const auto& m6 = graph.PopReadyModules();
    EXPECT_TRUE(m6.empty());
}

}  // namespace modprobe
}  // namespace android
