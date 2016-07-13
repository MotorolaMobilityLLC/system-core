LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := sdcard.cpp fuse.c
LOCAL_MODULE := sdcard
LOCAL_CFLAGS := -Wall -Wno-unused-parameter -Werror
LOCAL_SHARED_LIBRARIES := liblog libcutils libpackagelistparser

LOCAL_SANITIZE := integer
LOCAL_CLANG := true

include $(BUILD_EXECUTABLE)
