LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#
# C/C++ and ARMv5 objects
#

include $(CLEAR_VARS)
PIXELFLINGER_SRC_FILES:= \
    codeflinger/ARMAssemblerInterface.cpp \
    codeflinger/ARMAssemblerProxy.cpp \
    codeflinger/ARMAssembler.cpp \
    codeflinger/CodeCache.cpp \
    codeflinger/GGLAssembler.cpp \
    codeflinger/load_store.cpp \
    codeflinger/blending.cpp \
    codeflinger/texturing.cpp \
    codeflinger/disassem.c \
	codeflinger/tinyutils/SharedBuffer.cpp \
	codeflinger/tinyutils/VectorImpl.cpp \
	fixed.cpp.arm \
	picker.cpp.arm \
	pixelflinger.cpp.arm \
	trap.cpp.arm \
	scanline.cpp.arm \
	format.cpp \
	clear.cpp \
	raster.cpp \
	buffer.cpp

ifeq ($(TARGET_ARCH),arm)
ifeq ($(TARGET_ARCH_VERSION),armv7-a)
PIXELFLINGER_SRC_FILES += col32cb16blend_neon.S
PIXELFLINGER_SRC_FILES += col32cb16blend.S
else
PIXELFLINGER_SRC_FILES += t32cb16blend.S
PIXELFLINGER_SRC_FILES += col32cb16blend.S
endif
endif

ifeq ($(TARGET_ARCH),arm)
# special optimization flags for pixelflinger
PIXELFLINGER_CFLAGS += -fstrict-aliasing -fomit-frame-pointer
endif

ifeq ($(TARGET_ARCH),mips)
PIXELFLINGER_SRC_FILES += codeflinger/MIPSAssembler.cpp
PIXELFLINGER_SRC_FILES += codeflinger/mips_disassem.c
PIXELFLINGER_SRC_FILES += arch-mips/t32cb16blend.S
PIXELFLINGER_CFLAGS += -fstrict-aliasing -fomit-frame-pointer
endif

LOCAL_SHARED_LIBRARIES := libcutils

#
# Shared library
#

LOCAL_MODULE:= libpixelflinger
LOCAL_SRC_FILES := $(PIXELFLINGER_SRC_FILES)
LOCAL_CFLAGS := $(PIXELFLINGER_CFLAGS)

ifneq ($(BUILD_TINY_ANDROID),true)
# Really this should go away entirely or at least not depend on
# libhardware, but this at least gets us built.
LOCAL_SHARED_LIBRARIES += libhardware_legacy
LOCAL_CFLAGS += -DWITH_LIB_HARDWARE
endif
include $(BUILD_SHARED_LIBRARY)

#
# Static library version
#

include $(CLEAR_VARS)
LOCAL_MODULE:= libpixelflinger_static
LOCAL_SRC_FILES := $(PIXELFLINGER_SRC_FILES)
LOCAL_CFLAGS := $(PIXELFLINGER_CFLAGS) 
include $(BUILD_STATIC_LIBRARY)


include $(call all-makefiles-under,$(LOCAL_PATH))
