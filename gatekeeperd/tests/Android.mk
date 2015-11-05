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

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := gatekeeperd-unit-tests
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CFLAGS += -g -Wall -Werror -std=gnu++11 -Wno-missing-field-initializers
LOCAL_SHARED_LIBRARIES := libgatekeeper libcrypto libbase
LOCAL_STATIC_LIBRARIES := libscrypt_static
LOCAL_C_INCLUDES := external/scrypt/lib/crypto
LOCAL_SRC_FILES := \
	gatekeeper_test.cpp
include $(BUILD_NATIVE_TEST)

