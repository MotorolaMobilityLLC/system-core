#
# Copyright (C) 2015 The Android Open Source Project
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

libbase_src_files := \
    file.cpp \
    logging.cpp \
    stringprintf.cpp \
    strings.cpp \
    test_utils.cpp \

libbase_test_src_files := \
    file_test.cpp \
    logging_test.cpp \
    parseint_test.cpp \
    stringprintf_test.cpp \
    strings_test.cpp \
    test_main.cpp \

libbase_cppflags := \
    -Wall \
    -Wextra \
    -Werror \

# Device
# ------------------------------------------------------------------------------
include $(CLEAR_VARS)
LOCAL_MODULE := libbase
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(libbase_src_files)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CPPFLAGS := $(libbase_cppflags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_STATIC_LIBRARIES := libcutils
LOCAL_MULTILIB := both
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libbase
LOCAL_CLANG := true
LOCAL_WHOLE_STATIC_LIBRARIES := libbase
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_SHARED_LIBRARIES := libcutils
LOCAL_MULTILIB := both
include $(BUILD_SHARED_LIBRARY)

# Host
# ------------------------------------------------------------------------------
include $(CLEAR_VARS)
LOCAL_MODULE := libbase
LOCAL_SRC_FILES := $(libbase_src_files)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CPPFLAGS := $(libbase_cppflags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_STATIC_LIBRARIES := libcutils
LOCAL_MULTILIB := both
LOCAL_MODULE_HOST_OS := darwin linux windows
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libbase
LOCAL_WHOLE_STATIC_LIBRARIES := libbase
LOCAL_SHARED_LIBRARIES := liblog
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_STATIC_LIBRARIES := libcutils
LOCAL_MULTILIB := both
LOCAL_MODULE_HOST_OS := darwin linux windows
include $(BUILD_HOST_SHARED_LIBRARY)

# Tests
# ------------------------------------------------------------------------------
include $(CLEAR_VARS)
LOCAL_MODULE := libbase_test
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(libbase_test_src_files)
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CPPFLAGS := $(libbase_cppflags)
LOCAL_SHARED_LIBRARIES := libbase
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_MODULE := libbase_test
LOCAL_SRC_FILES := $(libbase_test_src_files)
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CPPFLAGS := $(libbase_cppflags)
LOCAL_SHARED_LIBRARIES := libbase
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
include $(BUILD_HOST_NATIVE_TEST)
