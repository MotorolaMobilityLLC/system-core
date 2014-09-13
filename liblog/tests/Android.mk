#
# Copyright (C) 2013-2014 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(call my-dir)

# -----------------------------------------------------------------------------
# Benchmarks.
# -----------------------------------------------------------------------------

test_module_prefix := liblog-
test_tags := tests

benchmark_c_flags := \
    -Ibionic/tests \
    -Wall -Wextra \
    -Werror \
    -fno-builtin \
    -std=gnu++11

benchmark_src_files := \
    benchmark_main.cpp \
    liblog_benchmark.cpp

# Build benchmarks for the device. Run with:
#   adb shell liblog-benchmarks
include $(CLEAR_VARS)
LOCAL_MODULE := $(test_module_prefix)benchmarks
LOCAL_MODULE_TAGS := $(test_tags)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CFLAGS += $(benchmark_c_flags)
LOCAL_SHARED_LIBRARIES += liblog libm
LOCAL_SRC_FILES := $(benchmark_src_files)
ifndef LOCAL_SDK_VERSION
LOCAL_C_INCLUDES += bionic bionic/libstdc++/include external/stlport/stlport
LOCAL_SHARED_LIBRARIES += libstlport
endif
LOCAL_MODULE_PATH := $(TARGET_OUT_DATA_NATIVE_TESTS)/$(LOCAL_MODULE)
include $(BUILD_EXECUTABLE)

# -----------------------------------------------------------------------------
# Unit tests.
# -----------------------------------------------------------------------------

test_c_flags := \
    -fstack-protector-all \
    -g \
    -Wall -Wextra \
    -Werror \
    -fno-builtin \
    -std=gnu++11

test_src_files := \
    liblog_test.cpp

# to prevent breaking the build if bionic not relatively visible to us
ifneq ($(wildcard $(LOCAL_PATH)/../../../../bionic/libc/bionic/libc_logging.cpp),)

test_src_files += \
    libc_test.cpp

ifneq ($(TARGET_USES_LOGD),false)
test_c_flags += -DTARGET_USES_LOGD
endif

endif

# Build tests for the device (with .so). Run with:
#   adb shell /data/nativetest/liblog-unit-tests/liblog-unit-tests
include $(CLEAR_VARS)
LOCAL_MODULE := $(test_module_prefix)unit-tests
LOCAL_MODULE_TAGS := $(test_tags)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CFLAGS += $(test_c_flags)
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_SRC_FILES := $(test_src_files)
include $(BUILD_NATIVE_TEST)
