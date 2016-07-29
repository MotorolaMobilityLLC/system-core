#
# Copyright (C) 2016 The Android Open-Source Project
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

# nvram.trusty is the Trusty NVRAM HAL module.
include $(CLEAR_VARS)
LOCAL_MODULE := nvram.trusty
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_SRC_FILES := \
	module.c \
	trusty_nvram_device.cpp \
	trusty_nvram_implementation.cpp
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Wall -Werror -Wextra -fvisibility=hidden
LOCAL_STATIC_LIBRARIES := libnvram-hal
LOCAL_SHARED_LIBRARIES := libtrusty libnvram-messages liblog
include $(BUILD_SHARED_LIBRARY)

# nvram-wipe is a helper tool for clearing NVRAM state.
include $(CLEAR_VARS)
LOCAL_MODULE := nvram-wipe
LOCAL_SRC_FILES := \
	nvram_wipe.cpp \
	trusty_nvram_implementation.cpp
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Wall -Werror -Wextra -fvisibility=hidden
LOCAL_STATIC_LIBRARIES := libnvram-hal
LOCAL_SHARED_LIBRARIES := libtrusty libnvram-messages liblog
include $(BUILD_EXECUTABLE)
