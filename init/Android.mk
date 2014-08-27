# Copyright 2005 The Android Open Source Project
#
# This file was modified by Dolby Laboratories, Inc. The portions of the
# code that are surrounded by "DOLBY..." are copyrighted and
# licensed separately, as follows:
#
#  (C) 2012 Dolby Laboratories, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH:= $(call my-dir)

# --

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
init_options += -DALLOW_LOCAL_PROP_OVERRIDE=1 -DALLOW_DISABLE_SELINUX=1
init_options += -DALLOW_CAMERA_DEBUG
else
init_options += -DALLOW_LOCAL_PROP_OVERRIDE=0
ifeq ($(RADIO_SECURE),1)
init_options += -DALLOW_DISABLE_SELINUX=0
else
init_options += -DALLOW_DISABLE_SELINUX=1
endif
endif

init_options += -DLOG_UEVENTS=0

ifeq ($(strip $(TARGET_USE_MOT_NEW_COM)),true)
init_options += -DMOTO_NEW_CHARGE_ONLY_MODE
endif

init_cflags += \
    $(init_options) \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Werror \

init_clang := true

# --

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    init_parser.cpp \
    log.cpp \
    parser.cpp \
    util.cpp \

LOCAL_STATIC_LIBRARIES := libbase
LOCAL_MODULE := libinit
LOCAL_CLANG := $(init_clang)
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    bootchart.cpp \
    builtins.cpp \
    devices.cpp \
    init.cpp \
    keychords.cpp \
    property_service.cpp \
    signal_handler.cpp \
    ueventd.cpp \
    ueventd_parser.cpp \
    watchdogd.cpp \

ifeq ($(TARGET_HAVE_VMWARE),true)
LOCAL_CFLAGS += -DSUPPORT_VMW
endif

ifdef DOLBY_DAP
LOCAL_CFLAGS += -DDOLBY_DAP
endif #DOLBY_DAP
LOCAL_MODULE:= init
LOCAL_C_INCLUDES += \
    system/extras/ext4_utils \
    system/core/mkbootimg

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES := \
    libinit \
    libfs_mgr \
    libsquashfs_utils \
    liblogwrap \
    libcutils \
    libbase \
    libext4_utils_static \
    libutils \
    liblog \
    libc \
    libselinux \
    libmincrypt \
    libc++_static \
    libdl \
    libsparse_static \
    libz

# Create symlinks
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT)/sbin; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/ueventd; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/watchdogd

LOCAL_CLANG := $(init_clang)
include $(BUILD_EXECUTABLE)




include $(CLEAR_VARS)
LOCAL_MODULE := init_tests
LOCAL_SRC_FILES := \
    init_parser_test.cpp \
    util_test.cpp \

LOCAL_SHARED_LIBRARIES += \
    libcutils \
    libbase \

LOCAL_STATIC_LIBRARIES := libinit
LOCAL_CLANG := $(init_clang)
include $(BUILD_NATIVE_TEST)
