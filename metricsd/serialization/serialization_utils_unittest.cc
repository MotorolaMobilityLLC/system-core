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

#include "serialization/serialization_utils.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "serialization/metric_sample.h"

namespace metrics {
namespace {

class SerializationUtilsTest : public testing::Test {
 protected:
  SerializationUtilsTest() {
    bool success = temporary_dir.CreateUniqueTempDir();
    if (success) {
      base::FilePath dir_path = temporary_dir.path();
      filename = dir_path.value() + "chromeossampletest";
      filepath = base::FilePath(filename);
    }
  }

  void SetUp() override { base::DeleteFile(filepath, false); }

  void TestSerialization(MetricSample* sample) {
    std::string serialized(sample->ToString());
    ASSERT_EQ('\0', serialized[serialized.length() - 1]);
    scoped_ptr<MetricSample> deserialized =
        SerializationUtils::ParseSample(serialized);
    ASSERT_TRUE(deserialized);
    EXPECT_TRUE(sample->IsEqual(*deserialized.get()));
  }

  std::string filename;
  base::ScopedTempDir temporary_dir;
  base::FilePath filepath;
};

TEST_F(SerializationUtilsTest, CrashSerializeTest) {
  TestSerialization(MetricSample::CrashSample("test").get());
}

TEST_F(SerializationUtilsTest, HistogramSerializeTest) {
  TestSerialization(
      MetricSample::HistogramSample("myhist", 13, 1, 100, 10).get());
}

TEST_F(SerializationUtilsTest, LinearSerializeTest) {
  TestSerialization(
      MetricSample::LinearHistogramSample("linearhist", 12, 30).get());
}

TEST_F(SerializationUtilsTest, SparseSerializeTest) {
  TestSerialization(MetricSample::SparseHistogramSample("mysparse", 30).get());
}

TEST_F(SerializationUtilsTest, UserActionSerializeTest) {
  TestSerialization(MetricSample::UserActionSample("myaction").get());
}

TEST_F(SerializationUtilsTest, IllegalNameAreFilteredTest) {
  scoped_ptr<MetricSample> sample1 =
      MetricSample::SparseHistogramSample("no space", 10);
  scoped_ptr<MetricSample> sample2 = MetricSample::LinearHistogramSample(
      base::StringPrintf("here%cbhe", '\0'), 1, 3);

  EXPECT_FALSE(SerializationUtils::WriteMetricToFile(*sample1.get(), filename));
  EXPECT_FALSE(SerializationUtils::WriteMetricToFile(*sample2.get(), filename));
  int64 size = 0;

  ASSERT_TRUE(!PathExists(filepath) || base::GetFileSize(filepath, &size));

  EXPECT_EQ(0, size);
}

TEST_F(SerializationUtilsTest, BadInputIsCaughtTest) {
  std::string input(
      base::StringPrintf("sparsehistogram%cname foo%c", '\0', '\0'));
  EXPECT_EQ(NULL, MetricSample::ParseSparseHistogram(input).get());
}

TEST_F(SerializationUtilsTest, MessageSeparatedByZero) {
  scoped_ptr<MetricSample> crash = MetricSample::CrashSample("mycrash");

  SerializationUtils::WriteMetricToFile(*crash.get(), filename);
  int64 size = 0;
  ASSERT_TRUE(base::GetFileSize(filepath, &size));
  // 4 bytes for the size
  // 5 bytes for crash
  // 7 bytes for mycrash
  // 2 bytes for the \0
  // -> total of 18
  EXPECT_EQ(size, 18);
}

TEST_F(SerializationUtilsTest, MessagesTooLongAreDiscardedTest) {
  // Creates a message that is bigger than the maximum allowed size.
  // As we are adding extra character (crash, \0s, etc), if the name is
  // kMessageMaxLength long, it will be too long.
  std::string name(SerializationUtils::kMessageMaxLength, 'c');

  scoped_ptr<MetricSample> crash = MetricSample::CrashSample(name);
  EXPECT_FALSE(SerializationUtils::WriteMetricToFile(*crash.get(), filename));
  int64 size = 0;
  ASSERT_TRUE(base::GetFileSize(filepath, &size));
  EXPECT_EQ(0, size);
}

TEST_F(SerializationUtilsTest, ReadLongMessageTest) {
  base::File test_file(filepath,
                       base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_APPEND);
  std::string message(SerializationUtils::kMessageMaxLength + 1, 'c');

  int32 message_size = message.length() + sizeof(int32);
  test_file.WriteAtCurrentPos(reinterpret_cast<const char*>(&message_size),
                              sizeof(message_size));
  test_file.WriteAtCurrentPos(message.c_str(), message.length());
  test_file.Close();

  scoped_ptr<MetricSample> crash = MetricSample::CrashSample("test");
  SerializationUtils::WriteMetricToFile(*crash.get(), filename);

  ScopedVector<MetricSample> samples;
  SerializationUtils::ReadAndTruncateMetricsFromFile(filename, &samples);
  ASSERT_EQ(size_t(1), samples.size());
  ASSERT_TRUE(samples[0] != NULL);
  EXPECT_TRUE(crash->IsEqual(*samples[0]));
}

TEST_F(SerializationUtilsTest, WriteReadTest) {
  scoped_ptr<MetricSample> hist =
      MetricSample::HistogramSample("myhist", 1, 2, 3, 4);
  scoped_ptr<MetricSample> crash = MetricSample::CrashSample("mycrash");
  scoped_ptr<MetricSample> lhist =
      MetricSample::LinearHistogramSample("linear", 1, 10);
  scoped_ptr<MetricSample> shist =
      MetricSample::SparseHistogramSample("mysparse", 30);
  scoped_ptr<MetricSample> action = MetricSample::UserActionSample("myaction");

  SerializationUtils::WriteMetricToFile(*hist.get(), filename);
  SerializationUtils::WriteMetricToFile(*crash.get(), filename);
  SerializationUtils::WriteMetricToFile(*lhist.get(), filename);
  SerializationUtils::WriteMetricToFile(*shist.get(), filename);
  SerializationUtils::WriteMetricToFile(*action.get(), filename);
  ScopedVector<MetricSample> vect;
  SerializationUtils::ReadAndTruncateMetricsFromFile(filename, &vect);
  ASSERT_EQ(vect.size(), size_t(5));
  for (int i = 0; i < 5; i++) {
    ASSERT_TRUE(vect[0] != NULL);
  }
  EXPECT_TRUE(hist->IsEqual(*vect[0]));
  EXPECT_TRUE(crash->IsEqual(*vect[1]));
  EXPECT_TRUE(lhist->IsEqual(*vect[2]));
  EXPECT_TRUE(shist->IsEqual(*vect[3]));
  EXPECT_TRUE(action->IsEqual(*vect[4]));

  int64 size = 0;
  ASSERT_TRUE(base::GetFileSize(filepath, &size));
  ASSERT_EQ(0, size);
}

}  // namespace
}  // namespace metrics
