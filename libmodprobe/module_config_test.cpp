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

#include <modprobe/module_config.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "unistd.h"

#include "module_config_test.h"

using testing::Pair;
using testing::UnorderedElementsAre;

// Used by module_config_ext_test to fake a kernel commandline
std::string kernel_cmdline;

void WriteModuleConfigs(const TemporaryDir& dir, const std::string& modules_alias,
                        const std::string& modules_dep, const std::string& modules_softdep,
                        const std::string& modules_options, const std::string& modules_load,
                        const std::string& modules_blocklist) {
    ASSERT_TRUE(android::base::WriteStringToFile(
            modules_alias, std::string(dir.path) + "/modules.alias", 0600, getuid(), getgid()));

    ASSERT_TRUE(android::base::WriteStringToFile(
            modules_dep, std::string(dir.path) + "/modules.dep", 0600, getuid(), getgid()));
    ASSERT_TRUE(android::base::WriteStringToFile(
            modules_softdep, std::string(dir.path) + "/modules.softdep", 0600, getuid(), getgid()));
    ASSERT_TRUE(android::base::WriteStringToFile(
            modules_options, std::string(dir.path) + "/modules.options", 0600, getuid(), getgid()));
    ASSERT_TRUE(android::base::WriteStringToFile(
            modules_load, std::string(dir.path) + "/modules.load", 0600, getuid(), getgid()));
    ASSERT_TRUE(android::base::WriteStringToFile(modules_blocklist,
                                                 std::string(dir.path) + "/modules.blocklist", 0600,
                                                 getuid(), getgid()));
}

TEST(module_config, ParsingConfigWorks) {
    kernel_cmdline =
            "flag1 flag2 test1.option1=50 test4.option3=\"set x\" test1.option2=60 "
            "test8. test5.option1= test10.option1=1";

    const std::string modules_dep =
            "test1.ko:\n"
            "test2.ko:\n"
            "test3.ko:\n"
            "test4.ko: test3.ko\n"
            "test5.ko: test2.ko test6.ko\n"
            "test6.ko:\n"
            "test7.ko:\n"
            "test8.ko:\n"
            "test9.ko:\n"
            "test10.ko:\n"
            "test11.ko:\n"
            "test12.ko:\n"
            "test13.ko:\n"
            "test14.ko:\n"
            "test15.ko:\n";

    const std::string modules_softdep =
            "softdep test7 pre: test8\n"
            "softdep test9 post: test10\n"
            "softdep test11 pre: test12 post: test13\n"
            "softdep test3 pre: test141516\n";

    const std::string modules_alias =
            "# Aliases extracted from modules themselves.\n"
            "\n"
            "alias test141516 test14\n"
            "alias test141516 test15\n"
            "alias test141516 test16\n";

    const std::string modules_options =
            "options test7.ko param1=4\n"
            "options test9.ko param_x=1 param_y=2 param_z=3\n"
            "options test100.ko param_1=1\n"
            "options test12 softdep pre: test14\n";

    const std::string modules_blocklist =
            "blocklist test9.ko\n"
            "blocklist test3.ko\n";

    const std::string modules_load =
            "test4.ko\n"
            "test1.ko\n"
            "test3.ko\n"
            "test5.ko\n"
            "test7.ko\n"
            "test9.ko\n"
            "test11.ko\n";

    TemporaryDir dir;
    WriteModuleConfigs(dir, modules_alias, modules_dep, modules_softdep, modules_options,
                       modules_load, modules_blocklist);

    ModuleConfig config = ModuleConfig::Parse({dir.path});

    EXPECT_THAT(
            config.module_deps,
            UnorderedElementsAre(
                    Pair("test1", UnorderedElementsAre(std::string(dir.path) + "/test1.ko")),
                    Pair("test2", UnorderedElementsAre(std::string(dir.path) + "/test2.ko")),
                    Pair("test3", UnorderedElementsAre(std::string(dir.path) + "/test3.ko")),
                    Pair("test4", UnorderedElementsAre(std::string(dir.path) + "/test4.ko",
                                                       std::string(dir.path) + "/test3.ko")),
                    Pair("test5", UnorderedElementsAre(std::string(dir.path) + "/test5.ko",
                                                       std::string(dir.path) + "/test2.ko",
                                                       std::string(dir.path) + "/test6.ko")),
                    Pair("test6", UnorderedElementsAre(std::string(dir.path) + "/test6.ko")),
                    Pair("test7", UnorderedElementsAre(std::string(dir.path) + "/test7.ko")),
                    Pair("test8", UnorderedElementsAre(std::string(dir.path) + "/test8.ko")),
                    Pair("test9", UnorderedElementsAre(std::string(dir.path) + "/test9.ko")),
                    Pair("test10", UnorderedElementsAre(std::string(dir.path) + "/test10.ko")),
                    Pair("test11", UnorderedElementsAre(std::string(dir.path) + "/test11.ko")),
                    Pair("test12", UnorderedElementsAre(std::string(dir.path) + "/test12.ko")),
                    Pair("test13", UnorderedElementsAre(std::string(dir.path) + "/test13.ko")),
                    Pair("test14", UnorderedElementsAre(std::string(dir.path) + "/test14.ko")),
                    Pair("test15", UnorderedElementsAre(std::string(dir.path) + "/test15.ko"))));

    EXPECT_THAT(config.module_aliases,
                UnorderedElementsAre(Pair("test141516", "test14"), Pair("test141516", "test15"),
                                     Pair("test141516", "test16")));

    EXPECT_THAT(config.module_pre_softdep,
                UnorderedElementsAre(Pair("test7", "test8"), Pair("test11", "test12"),
                                     Pair("test3", "test141516"), Pair("test12", "test14")));

    EXPECT_THAT(config.module_post_softdep,
                UnorderedElementsAre(Pair("test9", "test10"), Pair("test11", "test13")));

    EXPECT_THAT(config.module_load, UnorderedElementsAre("test4", "test1", "test3", "test5",
                                                         "test7", "test9", "test11"));

    EXPECT_THAT(config.module_options,
                UnorderedElementsAre(Pair("test1", "option1=50 option2=60"),
                                     Pair("test4", "option3=\"set x\""), Pair("test5", "option1="),
                                     Pair("test7", "param1=4"),
                                     Pair("test9", "param_x=1 param_y=2 param_z=3"),
                                     Pair("test10", "option1=1"), Pair("test100", "param_1=1")));

    EXPECT_THAT(config.module_blocklist, UnorderedElementsAre("test9", "test3"));
}
