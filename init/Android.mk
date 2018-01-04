# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

# --

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
init_options += \
    -DALLOW_LOCAL_PROP_OVERRIDE=1 \
    -DALLOW_PERMISSIVE_SELINUX=1 \
    -DREBOOT_BOOTLOADER_ON_PANIC=1 \
    -DDUMP_ON_UMOUNT_FAILURE=1
else
init_options += \
    -DALLOW_LOCAL_PROP_OVERRIDE=0 \
    -DREBOOT_BOOTLOADER_ON_PANIC=0 \
    -DDUMP_ON_UMOUNT_FAILURE=0

ifeq ($(RADIO_SECURE),1)
init_options += -DALLOW_PERMISSIVE_SELINUX=0
else
init_options += -DALLOW_PERMISSIVE_SELINUX=1
endif
endif

ifneq (,$(filter eng,$(TARGET_BUILD_VARIANT)))
init_options += \
    -DSHUTDOWN_ZERO_TIMEOUT=1
else
init_options += \
    -DSHUTDOWN_ZERO_TIMEOUT=0
endif

init_options += -DLOG_UEVENTS=0

ifeq ($(strip $(TARGET_USE_MOT_NEW_COM)),true)
init_options += -DMOTO_NEW_CHARGE_ONLY_MODE
endif

ifeq ($(TARGET_USER_MODE_LINUX), true)
    init_cflags += -DUSER_MODE_LINUX
endif

ifeq ($(BOARD_HAS_AUDIO_DSP_XMCS),true)
init_options += -DMOTO_AOV_WITH_XMCS
endif

ifeq ($(BOARD_HAS_GREYBUS_INTERFACE),true)
init_options += -DMOTO_GREYBUS_FIRMWARE
endif

init_cflags += \
    $(init_options) \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Werror \
    -std=gnu++1z \

# --

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    bootchart.cpp \
    builtins.cpp \
    hw_mappings.cpp \
    init.cpp \
    init_first_stage.cpp \
    keychords.cpp \
    property_service.cpp \
    reboot.cpp \
    signal_handler.cpp \
    ueventd.cpp \
    watchdogd.cpp \

LOCAL_MODULE:= init
LOCAL_C_INCLUDES += \
    system/core/mkbootimg \
    external/expat/lib

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES := \
    libinit \
    libbootloader_message \
    libfs_mgr \
    libfec \
    libfec_rs \
    libsquashfs_utils \
    liblogwrap \
    libext4_utils \
    libcutils \
    libbase \
    libc \
    libselinux \
    liblog \
    libcrypto_utils \
    libcrypto \
    libc++_static \
    libdl \
    libexpat \
    libsparse \
    libz \
    libprocessgroup \
    libavb \
    libkeyutils \

LOCAL_REQUIRED_MODULES := \
    e2fsdroid \
    mke2fs \

# Create symlinks.
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT)/sbin; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/ueventd; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/watchdogd

LOCAL_SANITIZE := signed-integer-overflow
LOCAL_CLANG := true
include $(BUILD_EXECUTABLE)
