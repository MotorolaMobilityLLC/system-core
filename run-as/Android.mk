LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS := -Werror
LOCAL_MODULE := run-as
LOCAL_SHARED_LIBRARIES := libselinux libpackagelistparser
LOCAL_SRC_FILES := run-as.cpp
include $(BUILD_EXECUTABLE)
