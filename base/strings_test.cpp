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

#include "base/strings.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

TEST(strings, split_empty) {
  std::vector<std::string> parts;
  android::base::Split("", '\0', &parts);
  ASSERT_EQ(0U, parts.size());
}

TEST(strings, split_single) {
  std::vector<std::string> parts;
  android::base::Split("foo", ',', &parts);
  ASSERT_EQ(1U, parts.size());
  ASSERT_EQ("foo", parts[0]);
}

TEST(strings, split_simple) {
  std::vector<std::string> parts;
  android::base::Split("foo,bar,baz", ',', &parts);
  ASSERT_EQ(3U, parts.size());
  ASSERT_EQ("foo", parts[0]);
  ASSERT_EQ("bar", parts[1]);
  ASSERT_EQ("baz", parts[2]);
}

TEST(strings, split_with_empty_part) {
  std::vector<std::string> parts;
  android::base::Split("foo,,bar", ',', &parts);
  ASSERT_EQ(2U, parts.size());
  ASSERT_EQ("foo", parts[0]);
  ASSERT_EQ("bar", parts[1]);
}

TEST(strings, trim_empty) {
  ASSERT_EQ("", android::base::Trim(""));
}

TEST(strings, trim_already_trimmed) {
  ASSERT_EQ("foo", android::base::Trim("foo"));
}

TEST(strings, trim_left) {
  ASSERT_EQ("foo", android::base::Trim(" foo"));
}

TEST(strings, trim_right) {
  ASSERT_EQ("foo", android::base::Trim("foo "));
}

TEST(strings, trim_both) {
  ASSERT_EQ("foo", android::base::Trim(" foo "));
}

TEST(strings, trim_no_trim_middle) {
  ASSERT_EQ("foo bar", android::base::Trim("foo bar"));
}

TEST(strings, trim_other_whitespace) {
  ASSERT_EQ("foo", android::base::Trim("\v\tfoo\n\f"));
}

TEST(strings, join_nothing) {
  std::vector<std::string> list = {};
  ASSERT_EQ("", android::base::Join(list, ','));
}

TEST(strings, join_single) {
  std::vector<std::string> list = {"foo"};
  ASSERT_EQ("foo", android::base::Join(list, ','));
}

TEST(strings, join_simple) {
  std::vector<std::string> list = {"foo", "bar", "baz"};
  ASSERT_EQ("foo,bar,baz", android::base::Join(list, ','));
}

TEST(strings, join_separator_in_vector) {
  std::vector<std::string> list = {",", ","};
  ASSERT_EQ(",,,", android::base::Join(list, ','));
}

TEST(strings, startswith_empty) {
  ASSERT_FALSE(android::base::StartsWith("", "foo"));
  ASSERT_TRUE(android::base::StartsWith("", ""));
}

TEST(strings, startswith_simple) {
  ASSERT_TRUE(android::base::StartsWith("foo", ""));
  ASSERT_TRUE(android::base::StartsWith("foo", "f"));
  ASSERT_TRUE(android::base::StartsWith("foo", "fo"));
  ASSERT_TRUE(android::base::StartsWith("foo", "foo"));
}

TEST(strings, startswith_prefix_too_long) {
  ASSERT_FALSE(android::base::StartsWith("foo", "foobar"));
}

TEST(strings, startswith_contains_prefix) {
  ASSERT_FALSE(android::base::StartsWith("foobar", "oba"));
  ASSERT_FALSE(android::base::StartsWith("foobar", "bar"));
}

TEST(strings, endswith_empty) {
  ASSERT_FALSE(android::base::EndsWith("", "foo"));
  ASSERT_TRUE(android::base::EndsWith("", ""));
}

TEST(strings, endswith_simple) {
  ASSERT_TRUE(android::base::EndsWith("foo", ""));
  ASSERT_TRUE(android::base::EndsWith("foo", "o"));
  ASSERT_TRUE(android::base::EndsWith("foo", "oo"));
  ASSERT_TRUE(android::base::EndsWith("foo", "foo"));
}

TEST(strings, endswith_prefix_too_long) {
  ASSERT_FALSE(android::base::EndsWith("foo", "foobar"));
}

TEST(strings, endswith_contains_prefix) {
  ASSERT_FALSE(android::base::EndsWith("foobar", "oba"));
  ASSERT_FALSE(android::base::EndsWith("foobar", "foo"));
}
