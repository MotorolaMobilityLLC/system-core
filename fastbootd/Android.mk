# Copyright (C) 2013 Google Inc.
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

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    config.c \
    commands.c \
    fastbootd.c \
    protocol.c \
    transport.c \
    usb_linux_client.c

LOCAL_MODULE := fastbootd
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter

LOCAL_STATIC_LIBRARIES := \
    libsparse_static \
    libc \
    libcutils

LOCAL_FORCE_STATIC_EXECUTABLE := true

include $(BUILD_EXECUTABLE)
