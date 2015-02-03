#
# Copyright (C) 2014 The Android Open Source Project
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

# Build the unit tests.
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_MODULE := libutils_tests

LOCAL_SRC_FILES := \
    BasicHashtable_test.cpp \
    BlobCache_test.cpp \
    BitSet_test.cpp \
    file_test.cpp \
    Looper_test.cpp \
    LruCache_test.cpp \
    String8_test.cpp \
    stringprintf_test.cpp \
    Unicode_test.cpp \
    Vector_test.cpp \

LOCAL_SHARED_LIBRARIES := \
    libz \
    liblog \
    libcutils \
    libutils \

include $(BUILD_NATIVE_TEST)
