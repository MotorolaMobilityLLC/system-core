LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
    arm64_diassembler_test.cpp \
    ../../../codeflinger/Arm64Disassembler.cpp

LOCAL_SHARED_LIBRARIES :=

LOCAL_C_INCLUDES := \
    system/core/libpixelflinger/codeflinger

LOCAL_MODULE:= test-pixelflinger-arm64-disassembler-test

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)
