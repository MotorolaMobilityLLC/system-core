# Build the unit tests.
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# Build the unit tests.
test_src_files := \
    InvalidCharsNativeBridge_test.cpp \
    ReSetupNativeBridge_test.cpp \
    UnavailableNativeBridge_test.cpp \
    ValidNameNativeBridge_test.cpp

shared_libraries := \
    liblog \
    libnativebridge

$(foreach file,$(test_src_files), \
    $(eval include $(CLEAR_VARS)) \
    $(eval LOCAL_CLANG := true) \
    $(eval LOCAL_CPPFLAGS := -std=gnu++11) \
    $(eval LOCAL_SHARED_LIBRARIES := $(shared_libraries)) \
    $(eval LOCAL_SRC_FILES := $(file)) \
    $(eval LOCAL_MODULE := $(notdir $(file:%.cpp=%))) \
    $(eval include $(BUILD_NATIVE_TEST)) \
)

$(foreach file,$(test_src_files), \
    $(eval include $(CLEAR_VARS)) \
    $(eval LOCAL_CLANG := true) \
    $(eval LOCAL_CPPFLAGS := -std=gnu++11) \
    $(eval LOCAL_SHARED_LIBRARIES := $(shared_libraries)) \
    $(eval LOCAL_SRC_FILES := $(file)) \
    $(eval LOCAL_MODULE := $(notdir $(file:%.cpp=%))) \
    $(eval include $(BUILD_HOST_NATIVE_TEST)) \
)