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

#include <vector>

#include <base/at_exit.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/flag_helper.h>
#include <gtest/gtest.h>

#include "constants.h"
#include "metrics_daemon.h"
#include "metrics/metrics_library_mock.h"
#include "persistent_integer_mock.h"

using base::FilePath;
using base::TimeDelta;
using std::string;
using std::vector;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::Return;
using ::testing::StrictMock;
using chromeos_metrics::PersistentIntegerMock;


class MetricsDaemonTest : public testing::Test {
 protected:
  virtual void SetUp() {
    chromeos::FlagHelper::Init(0, nullptr, "");
    EXPECT_TRUE(temp_dir_.CreateUniqueTempDir());
    scaling_max_freq_path_ = temp_dir_.path().Append("scaling_max");
    cpu_max_freq_path_ = temp_dir_.path().Append("cpu_freq_max");

    CreateUint64ValueFile(cpu_max_freq_path_, 10000000);
    CreateUint64ValueFile(scaling_max_freq_path_, 10000000);

    chromeos_metrics::PersistentInteger::SetMetricsDirectory(
        temp_dir_.path().value());
    daemon_.Init(true,
                 false,
                 true,
                 &metrics_lib_,
                 "",
                 scaling_max_freq_path_.value(),
                 cpu_max_freq_path_.value(),
                 base::TimeDelta::FromMinutes(30),
                 metrics::kMetricsServer,
                 temp_dir_.path());
  }

  // Adds a metrics library mock expectation that the specified metric
  // will be generated.
  void ExpectSample(const std::string& name, int sample) {
    EXPECT_CALL(metrics_lib_, SendToUMA(name, sample, _, _, _))
        .Times(1)
        .WillOnce(Return(true))
        .RetiresOnSaturation();
  }

  // Creates a new DBus signal message with zero or more string arguments.
  // The message can be deallocated through DeleteDBusMessage.
  //
  // |path| is the object emitting the signal.
  // |interface| is the interface the signal is emitted from.
  // |name| is the name of the signal.
  // |arg_values| contains the values of the string arguments.
  DBusMessage* NewDBusSignalString(const string& path,
                                   const string& interface,
                                   const string& name,
                                   const vector<string>& arg_values) {
    DBusMessage* msg = dbus_message_new_signal(path.c_str(),
                                               interface.c_str(),
                                               name.c_str());
    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);
    for (vector<string>::const_iterator it = arg_values.begin();
         it != arg_values.end(); ++it) {
      const char* str_value = it->c_str();
      dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &str_value);
    }
    return msg;
  }

  // Deallocates the DBus message |msg| previously allocated through
  // dbus_message_new*.
  void DeleteDBusMessage(DBusMessage* msg) {
    dbus_message_unref(msg);
  }


  // Creates or overwrites the file in |path| so that it contains the printable
  // representation of |value|.
  void CreateUint64ValueFile(const base::FilePath& path, uint64_t value) {
    std::string value_string = base::Uint64ToString(value);
    ASSERT_EQ(value_string.length(),
              base::WriteFile(path, value_string.c_str(),
                              value_string.length()));
  }

  // The MetricsDaemon under test.
  MetricsDaemon daemon_;

  // Temporary directory used for tests.
  base::ScopedTempDir temp_dir_;

  // Path for the fake files.
  base::FilePath scaling_max_freq_path_;
  base::FilePath cpu_max_freq_path_;

  // Mocks. They are strict mock so that all unexpected
  // calls are marked as failures.
  StrictMock<MetricsLibraryMock> metrics_lib_;
};

TEST_F(MetricsDaemonTest, MessageFilter) {
  // Ignore calls to SendToUMA.
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _)).Times(AnyNumber());

  DBusMessage* msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
  DBusHandlerResult res =
      MetricsDaemon::MessageFilter(/* connection */ nullptr, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_NOT_YET_HANDLED, res);
  DeleteDBusMessage(msg);

  vector<string> signal_args;
  msg = NewDBusSignalString("/",
                            "org.chromium.CrashReporter",
                            "UserCrash",
                            signal_args);
  res = MetricsDaemon::MessageFilter(/* connection */ nullptr, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  signal_args.clear();
  signal_args.push_back("randomstate");
  signal_args.push_back("bob");  // arbitrary username
  msg = NewDBusSignalString("/",
                            "org.chromium.UnknownService.Manager",
                            "StateChanged",
                            signal_args);
  res = MetricsDaemon::MessageFilter(/* connection */ nullptr, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_NOT_YET_HANDLED, res);
  DeleteDBusMessage(msg);
}

TEST_F(MetricsDaemonTest, SendSample) {
  ExpectSample("Dummy.Metric", 3);
  daemon_.SendSample("Dummy.Metric", /* sample */ 3,
                     /* min */ 1, /* max */ 100, /* buckets */ 50);
}

TEST_F(MetricsDaemonTest, ProcessMeminfo) {
  string meminfo =
      "MemTotal:        2000000 kB\nMemFree:          500000 kB\n"
      "Buffers:         1000000 kB\nCached:           213652 kB\n"
      "SwapCached:            0 kB\nActive:           133400 kB\n"
      "Inactive:         183396 kB\nActive(anon):      92984 kB\n"
      "Inactive(anon):    58860 kB\nActive(file):      40416 kB\n"
      "Inactive(file):   124536 kB\nUnevictable:           0 kB\n"
      "Mlocked:               0 kB\nSwapTotal:             0 kB\n"
      "SwapFree:              0 kB\nDirty:                40 kB\n"
      "Writeback:             0 kB\nAnonPages:         92652 kB\n"
      "Mapped:            59716 kB\nShmem:             59196 kB\n"
      "Slab:              16656 kB\nSReclaimable:       6132 kB\n"
      "SUnreclaim:        10524 kB\nKernelStack:        1648 kB\n"
      "PageTables:         2780 kB\nNFS_Unstable:          0 kB\n"
      "Bounce:                0 kB\nWritebackTmp:          0 kB\n"
      "CommitLimit:      970656 kB\nCommitted_AS:    1260528 kB\n"
      "VmallocTotal:     122880 kB\nVmallocUsed:       12144 kB\n"
      "VmallocChunk:     103824 kB\nDirectMap4k:        9636 kB\n"
      "DirectMap2M:     1955840 kB\n";

  // All enum calls must report percents.
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, _, 100)).Times(AtLeast(1));
  // Check that MemFree is correctly computed at 25%.
  EXPECT_CALL(metrics_lib_, SendEnumToUMA("Platform.MeminfoMemFree", 25, 100))
      .Times(AtLeast(1));
  // Check that we call SendToUma at least once (log histogram).
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _))
      .Times(AtLeast(1));
  // Make sure we don't report fields not in the list.
  EXPECT_CALL(metrics_lib_, SendToUMA("Platform.MeminfoMlocked", _, _, _, _))
      .Times(0);
  EXPECT_CALL(metrics_lib_, SendEnumToUMA("Platform.MeminfoMlocked", _, _))
      .Times(0);
  EXPECT_TRUE(daemon_.ProcessMeminfo(meminfo));
}

TEST_F(MetricsDaemonTest, ProcessMeminfo2) {
  string meminfo = "MemTotal:        2000000 kB\nMemFree:         1000000 kB\n";
  // Not enough fields.
  EXPECT_FALSE(daemon_.ProcessMeminfo(meminfo));
}

TEST_F(MetricsDaemonTest, ReadFreqToInt) {
  const int fake_scaled_freq = 1666999;
  const int fake_max_freq = 2000000;
  int scaled_freq = 0;
  int max_freq = 0;
  CreateUint64ValueFile(scaling_max_freq_path_, fake_scaled_freq);
  CreateUint64ValueFile(cpu_max_freq_path_, fake_max_freq);
  EXPECT_TRUE(daemon_.testing_);
  EXPECT_TRUE(daemon_.ReadFreqToInt(scaling_max_freq_path_.value(),
                                    &scaled_freq));
  EXPECT_TRUE(daemon_.ReadFreqToInt(cpu_max_freq_path_.value(), &max_freq));
  EXPECT_EQ(fake_scaled_freq, scaled_freq);
  EXPECT_EQ(fake_max_freq, max_freq);
}

TEST_F(MetricsDaemonTest, SendCpuThrottleMetrics) {
  CreateUint64ValueFile(cpu_max_freq_path_, 2001000);
  // Test the 101% and 100% cases.
  CreateUint64ValueFile(scaling_max_freq_path_, 2001000);
  EXPECT_TRUE(daemon_.testing_);
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, 101, 101));
  daemon_.SendCpuThrottleMetrics();
  CreateUint64ValueFile(scaling_max_freq_path_, 2000000);
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, 100, 101));
  daemon_.SendCpuThrottleMetrics();
}

TEST_F(MetricsDaemonTest, SendZramMetrics) {
  EXPECT_TRUE(daemon_.testing_);

  // |compr_data_size| is the size in bytes of compressed data.
  const uint64_t compr_data_size = 50 * 1000 * 1000;
  // The constant '3' is a realistic but random choice.
  // |orig_data_size| does not include zero pages.
  const uint64_t orig_data_size = compr_data_size * 3;
  const uint64_t page_size = 4096;
  const uint64_t zero_pages = 10 * 1000 * 1000 / page_size;

  CreateUint64ValueFile(
      temp_dir_.path().Append(MetricsDaemon::kComprDataSizeName),
      compr_data_size);
  CreateUint64ValueFile(
      temp_dir_.path().Append(MetricsDaemon::kOrigDataSizeName),
      orig_data_size);
  CreateUint64ValueFile(
      temp_dir_.path().Append(MetricsDaemon::kZeroPagesName), zero_pages);

  const uint64_t real_orig_size = orig_data_size + zero_pages * page_size;
  const uint64_t zero_ratio_percent =
      zero_pages * page_size * 100 / real_orig_size;
  // Ratio samples are in percents.
  const uint64_t actual_ratio_sample = real_orig_size * 100 / compr_data_size;

  EXPECT_CALL(metrics_lib_, SendToUMA(_, compr_data_size >> 20, _, _, _));
  EXPECT_CALL(metrics_lib_,
              SendToUMA(_, (real_orig_size - compr_data_size) >> 20, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, actual_ratio_sample, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, zero_pages, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, zero_ratio_percent, _, _, _));

  EXPECT_TRUE(daemon_.ReportZram(temp_dir_.path()));
}
