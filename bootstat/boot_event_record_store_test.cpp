/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "boot_event_record_store.h"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdint>
#include <cstdlib>
#include <android-base/file.h>
#include <android-base/test_utils.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

using testing::UnorderedElementsAreArray;

namespace {

// Returns true if the time difference between |a| and |b| is no larger
// than 10 seconds.  This allow for a relatively large fuzz when comparing
// two timestamps taken back-to-back.
bool FuzzUptimeEquals(int32_t a, int32_t b) {
  const int32_t FUZZ_SECONDS = 10;
  return (abs(a - b) <= FUZZ_SECONDS);
}

// Returns the uptime as read from /proc/uptime, rounded down to an integer.
int32_t ReadUptime() {
  std::string uptime_str;
  if (!android::base::ReadFileToString("/proc/uptime", &uptime_str)) {
    return -1;
  }

  // Cast to int to round down.
  return static_cast<int32_t>(strtod(uptime_str.c_str(), NULL));
}

// Recursively deletes the directory at |path|.
void DeleteDirectory(const std::string& path) {
  typedef std::unique_ptr<DIR, decltype(&closedir)> ScopedDIR;
  ScopedDIR dir(opendir(path.c_str()), closedir);
  ASSERT_NE(nullptr, dir.get());

  struct dirent* entry;
  while ((entry = readdir(dir.get())) != NULL) {
    const std::string entry_name(entry->d_name);
    if (entry_name == "." || entry_name == "..") {
      continue;
    }

    const std::string entry_path = path + "/" + entry_name;
    if (entry->d_type == DT_DIR) {
      DeleteDirectory(entry_path);
    } else {
      unlink(entry_path.c_str());
    }
  }

  rmdir(path.c_str());
}

class BootEventRecordStoreTest : public ::testing::Test {
 public:
  BootEventRecordStoreTest() {
    store_path_ = std::string(store_dir_.path) + "/";
  }

  const std::string& GetStorePathForTesting() const {
    return store_path_;
  }

 private:
  void TearDown() {
    // This removes the record store temporary directory even though
    // TemporaryDir should already take care of it, but this method cleans up
    // the test files added to the directory which prevent TemporaryDir from
    // being able to remove the directory.
    DeleteDirectory(store_path_);
  }

  // A scoped temporary directory. Using this abstraction provides creation of
  // the directory and the path to the directory, which is stored in
  // |store_path_|.
  TemporaryDir store_dir_;

  // The path to the temporary directory used by the BootEventRecordStore to
  // persist records.  The directory is created and destroyed for each test.
  std::string store_path_;

  DISALLOW_COPY_AND_ASSIGN(BootEventRecordStoreTest);
};

}  // namespace

TEST_F(BootEventRecordStoreTest, AddSingleBootEvent) {
  BootEventRecordStore store;
  store.SetStorePath(GetStorePathForTesting());

  int32_t uptime = ReadUptime();
  ASSERT_NE(-1, uptime);

  store.AddBootEvent("cenozoic");

  auto events = store.GetAllBootEvents();
  ASSERT_EQ(1U, events.size());
  EXPECT_EQ("cenozoic", events[0].first);
  EXPECT_TRUE(FuzzUptimeEquals(uptime, events[0].second));
}

TEST_F(BootEventRecordStoreTest, AddMultipleBootEvents) {
  BootEventRecordStore store;
  store.SetStorePath(GetStorePathForTesting());

  int32_t uptime = ReadUptime();
  ASSERT_NE(-1, uptime);

  store.AddBootEvent("cretaceous");
  store.AddBootEvent("jurassic");
  store.AddBootEvent("triassic");

  const std::string EXPECTED_NAMES[] = {
    "cretaceous",
    "jurassic",
    "triassic",
  };

  auto events = store.GetAllBootEvents();
  ASSERT_EQ(3U, events.size());

  std::vector<std::string> names;
  std::vector<int32_t> timestamps;
  for (auto i = events.begin(); i != events.end(); ++i) {
    names.push_back(i->first);
    timestamps.push_back(i->second);
  }

  EXPECT_THAT(names, UnorderedElementsAreArray(EXPECTED_NAMES));

  for (auto i = timestamps.cbegin(); i != timestamps.cend(); ++i) {
    EXPECT_TRUE(FuzzUptimeEquals(uptime, *i));
  }
}

TEST_F(BootEventRecordStoreTest, AddBootEventWithValue) {
  BootEventRecordStore store;
  store.SetStorePath(GetStorePathForTesting());

  store.AddBootEventWithValue("permian", 42);

  auto events = store.GetAllBootEvents();
  ASSERT_EQ(1U, events.size());
  EXPECT_EQ("permian", events[0].first);
  EXPECT_EQ(42, events[0].second);
}

TEST_F(BootEventRecordStoreTest, GetBootEvent) {
  BootEventRecordStore store;
  store.SetStorePath(GetStorePathForTesting());

  // Event does not exist.
  BootEventRecordStore::BootEventRecord record;
  bool result = store.GetBootEvent("nonexistent", &record);
  EXPECT_EQ(false, result);

  // Empty path.
  EXPECT_DEATH(store.GetBootEvent(std::string(), &record), std::string());

  // Success case.
  store.AddBootEventWithValue("carboniferous", 314);
  result = store.GetBootEvent("carboniferous", &record);
  EXPECT_EQ(true, result);
  EXPECT_EQ("carboniferous", record.first);
  EXPECT_EQ(314, record.second);

  // Null |record|.
  EXPECT_DEATH(store.GetBootEvent("carboniferous", nullptr), std::string());
}