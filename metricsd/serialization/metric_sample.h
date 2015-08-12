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

#ifndef METRICS_SERIALIZATION_METRIC_SAMPLE_H_
#define METRICS_SERIALIZATION_METRIC_SAMPLE_H_

#include <string>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/scoped_ptr.h"

namespace metrics {

// This class is used by libmetrics (ChromeOS) to serialize
// and deserialize measurements to send them to a metrics sending service.
// It is meant to be a simple container with serialization functions.
class MetricSample {
 public:
  // Types of metric sample used.
  enum SampleType {
    CRASH,
    HISTOGRAM,
    LINEAR_HISTOGRAM,
    SPARSE_HISTOGRAM,
    USER_ACTION
  };

  ~MetricSample();

  // Returns true if the sample is valid (can be serialized without ambiguity).
  //
  // This function should be used to filter bad samples before serializing them.
  bool IsValid() const;

  // Getters for type and name. All types of metrics have these so we do not
  // need to check the type.
  SampleType type() const { return type_; }
  const std::string& name() const { return name_; }

  // Getters for sample, min, max, bucket_count.
  // Check the metric type to make sure the request make sense. (ex: a crash
  // sample does not have a bucket_count so we crash if we call bucket_count()
  // on it.)
  int sample() const;
  int min() const;
  int max() const;
  int bucket_count() const;

  // Returns a serialized version of the sample.
  //
  // The serialized message for each type is:
  // crash: crash\0|name_|\0
  // user action: useraction\0|name_|\0
  // histogram: histogram\0|name_| |sample_| |min_| |max_| |bucket_count_|\0
  // sparsehistogram: sparsehistogram\0|name_| |sample_|\0
  // linearhistogram: linearhistogram\0|name_| |sample_| |max_|\0
  std::string ToString() const;

  // Builds a crash sample.
  static scoped_ptr<MetricSample> CrashSample(const std::string& crash_name);

  // Builds a histogram sample.
  static scoped_ptr<MetricSample> HistogramSample(
      const std::string& histogram_name,
      int sample,
      int min,
      int max,
      int bucket_count);
  // Deserializes a histogram sample.
  static scoped_ptr<MetricSample> ParseHistogram(const std::string& serialized);

  // Builds a sparse histogram sample.
  static scoped_ptr<MetricSample> SparseHistogramSample(
      const std::string& histogram_name,
      int sample);
  // Deserializes a sparse histogram sample.
  static scoped_ptr<MetricSample> ParseSparseHistogram(
      const std::string& serialized);

  // Builds a linear histogram sample.
  static scoped_ptr<MetricSample> LinearHistogramSample(
      const std::string& histogram_name,
      int sample,
      int max);
  // Deserializes a linear histogram sample.
  static scoped_ptr<MetricSample> ParseLinearHistogram(
      const std::string& serialized);

  // Builds a user action sample.
  static scoped_ptr<MetricSample> UserActionSample(
      const std::string& action_name);

  // Returns true if sample and this object represent the same sample (type,
  // name, sample, min, max, bucket_count match).
  bool IsEqual(const MetricSample& sample);

 private:
  MetricSample(SampleType sample_type,
               const std::string& metric_name,
               const int sample,
               const int min,
               const int max,
               const int bucket_count);

  const SampleType type_;
  const std::string name_;
  const int sample_;
  const int min_;
  const int max_;
  const int bucket_count_;

  DISALLOW_COPY_AND_ASSIGN(MetricSample);
};

}  // namespace metrics

#endif  // METRICS_SERIALIZATION_METRIC_SAMPLE_H_
