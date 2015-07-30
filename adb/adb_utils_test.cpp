/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "adb_utils.h"

#include <gtest/gtest.h>

#include <stdlib.h>
#include <string.h>

#include "sysdeps.h"

#include <base/test_utils.h>

TEST(adb_utils, directory_exists) {
  ASSERT_TRUE(directory_exists("/proc"));
  ASSERT_FALSE(directory_exists("/proc/self")); // Symbolic link.
  ASSERT_FALSE(directory_exists("/proc/does-not-exist"));
}

TEST(adb_utils, escape_arg) {
  ASSERT_EQ(R"('')", escape_arg(""));

  ASSERT_EQ(R"('abc')", escape_arg("abc"));

  ASSERT_EQ(R"(' abc')", escape_arg(" abc"));
  ASSERT_EQ(R"(''\''abc')", escape_arg("'abc"));
  ASSERT_EQ(R"('"abc')", escape_arg("\"abc"));
  ASSERT_EQ(R"('\abc')", escape_arg("\\abc"));
  ASSERT_EQ(R"('(abc')", escape_arg("(abc"));
  ASSERT_EQ(R"(')abc')", escape_arg(")abc"));

  ASSERT_EQ(R"('abc abc')", escape_arg("abc abc"));
  ASSERT_EQ(R"('abc'\''abc')", escape_arg("abc'abc"));
  ASSERT_EQ(R"('abc"abc')", escape_arg("abc\"abc"));
  ASSERT_EQ(R"('abc\abc')", escape_arg("abc\\abc"));
  ASSERT_EQ(R"('abc(abc')", escape_arg("abc(abc"));
  ASSERT_EQ(R"('abc)abc')", escape_arg("abc)abc"));

  ASSERT_EQ(R"('abc ')", escape_arg("abc "));
  ASSERT_EQ(R"('abc'\''')", escape_arg("abc'"));
  ASSERT_EQ(R"('abc"')", escape_arg("abc\""));
  ASSERT_EQ(R"('abc\')", escape_arg("abc\\"));
  ASSERT_EQ(R"('abc(')", escape_arg("abc("));
  ASSERT_EQ(R"('abc)')", escape_arg("abc)"));
}

TEST(adb_utils, parse_host_and_port) {
  std::string canonical_address;
  std::string host;
  int port;
  std::string error;

  // Name, default port.
  port = 123;
  ASSERT_TRUE(parse_host_and_port("www.google.com", &canonical_address, &host, &port, &error));
  ASSERT_EQ("www.google.com:123", canonical_address);
  ASSERT_EQ("www.google.com", host);
  ASSERT_EQ(123, port);

  // Name, explicit port.
  ASSERT_TRUE(parse_host_and_port("www.google.com:666", &canonical_address, &host, &port, &error));
  ASSERT_EQ("www.google.com:666", canonical_address);
  ASSERT_EQ("www.google.com", host);
  ASSERT_EQ(666, port);

  // IPv4, default port.
  port = 123;
  ASSERT_TRUE(parse_host_and_port("1.2.3.4", &canonical_address, &host, &port, &error));
  ASSERT_EQ("1.2.3.4:123", canonical_address);
  ASSERT_EQ("1.2.3.4", host);
  ASSERT_EQ(123, port);

  // IPv4, explicit port.
  ASSERT_TRUE(parse_host_and_port("1.2.3.4:666", &canonical_address, &host, &port, &error));
  ASSERT_EQ("1.2.3.4:666", canonical_address);
  ASSERT_EQ("1.2.3.4", host);
  ASSERT_EQ(666, port);

  // Simple IPv6, default port.
  port = 123;
  ASSERT_TRUE(parse_host_and_port("::1", &canonical_address, &host, &port, &error));
  ASSERT_EQ("[::1]:123", canonical_address);
  ASSERT_EQ("::1", host);
  ASSERT_EQ(123, port);

  // Simple IPv6, explicit port.
  ASSERT_TRUE(parse_host_and_port("[::1]:666", &canonical_address, &host, &port, &error));
  ASSERT_EQ("[::1]:666", canonical_address);
  ASSERT_EQ("::1", host);
  ASSERT_EQ(666, port);

  // Hairy IPv6, default port.
  port = 123;
  ASSERT_TRUE(parse_host_and_port("fe80::200:5aee:feaa:20a2", &canonical_address, &host, &port, &error));
  ASSERT_EQ("[fe80::200:5aee:feaa:20a2]:123", canonical_address);
  ASSERT_EQ("fe80::200:5aee:feaa:20a2", host);
  ASSERT_EQ(123, port);

  // Simple IPv6, explicit port.
  ASSERT_TRUE(parse_host_and_port("[fe80::200:5aee:feaa:20a2]:666", &canonical_address, &host, &port, &error));
  ASSERT_EQ("[fe80::200:5aee:feaa:20a2]:666", canonical_address);
  ASSERT_EQ("fe80::200:5aee:feaa:20a2", host);
  ASSERT_EQ(666, port);

  // Invalid IPv4.
  EXPECT_FALSE(parse_host_and_port("1.2.3.4:", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("1.2.3.4::", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("1.2.3.4:hello", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port(":123", &canonical_address, &host, &port, &error));

  // Invalid IPv6.
  EXPECT_FALSE(parse_host_and_port(":1", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("::::::::1", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("[::1", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("[::1]", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("[::1]:", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("[::1]::", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("[::1]:hello", &canonical_address, &host, &port, &error));

  // Invalid ports.
  EXPECT_FALSE(parse_host_and_port("[::1]:-1", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("[::1]:0", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("[::1]:65536", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("1.2.3.4:-1", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("1.2.3.4:0", &canonical_address, &host, &port, &error));
  EXPECT_FALSE(parse_host_and_port("1.2.3.4:65536", &canonical_address, &host, &port, &error));
}

TEST(adb_utils, mkdirs) {
  TemporaryDir td;
  EXPECT_TRUE(mkdirs(std::string(td.path) + "/dir/subdir/file"));
  std::string file = std::string(td.path) + "/file";
  adb_creat(file.c_str(), 0600);
  EXPECT_FALSE(mkdirs(file + "/subdir/"));
}
