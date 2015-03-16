/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include "base/file.h"

#include <gtest/gtest.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <string>

class TemporaryFile {
 public:
  TemporaryFile() {
    init("/data/local/tmp");
    if (fd == -1) {
      init("/tmp");
    }
  }

  ~TemporaryFile() {
    close(fd);
    unlink(filename);
  }

  int fd;
  char filename[1024];

 private:
  void init(const char* tmp_dir) {
    snprintf(filename, sizeof(filename), "%s/TemporaryFile-XXXXXX", tmp_dir);
    fd = mkstemp(filename);
  }
};

TEST(file, ReadFileToString_ENOENT) {
  std::string s("hello");
  errno = 0;
  ASSERT_FALSE(android::base::ReadFileToString("/proc/does-not-exist", &s));
  EXPECT_EQ(ENOENT, errno);
  EXPECT_EQ("", s);  // s was cleared.
}

TEST(file, ReadFileToString_success) {
  std::string s("hello");
  ASSERT_TRUE(android::base::ReadFileToString("/proc/version", &s)) << errno;
  EXPECT_GT(s.length(), 6U);
  EXPECT_EQ('\n', s[s.length() - 1]);
  s[5] = 0;
  EXPECT_STREQ("Linux", s.c_str());
}

TEST(file, WriteStringToFile) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);
  ASSERT_TRUE(android::base::WriteStringToFile("abc", tf.filename)) << errno;
  std::string s;
  ASSERT_TRUE(android::base::ReadFileToString(tf.filename, &s)) << errno;
  EXPECT_EQ("abc", s);
}

TEST(file, WriteStringToFile2) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);
  ASSERT_TRUE(android::base::WriteStringToFile("abc", tf.filename, 0660,
                                               getuid(), getgid()))
      << errno;
  struct stat sb;
  ASSERT_EQ(0, stat(tf.filename, &sb));
  ASSERT_EQ(0660U, (sb.st_mode & ~S_IFMT));
  ASSERT_EQ(getuid(), sb.st_uid);
  ASSERT_EQ(getgid(), sb.st_gid);
  std::string s;
  ASSERT_TRUE(android::base::ReadFileToString(tf.filename, &s)) << errno;
  EXPECT_EQ("abc", s);
}

TEST(file, WriteStringToFd) {
  TemporaryFile tf;
  ASSERT_TRUE(tf.fd != -1);
  ASSERT_TRUE(android::base::WriteStringToFd("abc", tf.fd));

  ASSERT_EQ(0, lseek(tf.fd, 0, SEEK_SET)) << errno;

  std::string s;
  ASSERT_TRUE(android::base::ReadFdToString(tf.fd, &s)) << errno;
  EXPECT_EQ("abc", s);
}
