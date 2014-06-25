/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SYSTEM_CORE_INCLUDE_ANDROID_GRAPHICS_H
#define SYSTEM_CORE_INCLUDE_ANDROID_GRAPHICS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * If the HAL needs to create service threads to handle graphics related
 * tasks, these threads need to run at HAL_PRIORITY_URGENT_DISPLAY priority
 * if they can block the main rendering thread in any way.
 *
 * the priority of the current thread can be set with:
 *
 *      #include <sys/resource.h>
 *      setpriority(PRIO_PROCESS, 0, HAL_PRIORITY_URGENT_DISPLAY);
 *
 */

#define HAL_PRIORITY_URGENT_DISPLAY     (-8)

/**
 * pixel format definitions
 */

enum {
    /*
     * "linear" color pixel formats:
     *
     * The pixel formats below contain sRGB data but are otherwise treated
     * as linear formats, i.e.: no special operation is performed when
     * reading or writing into a buffer in one of these formats
     */
    HAL_PIXEL_FORMAT_RGBA_8888          = 1,
    HAL_PIXEL_FORMAT_RGBX_8888          = 2,
    HAL_PIXEL_FORMAT_RGB_888            = 3,
    HAL_PIXEL_FORMAT_RGB_565            = 4,
    HAL_PIXEL_FORMAT_BGRA_8888          = 5,

    /*
     * sRGB color pixel formats:
     *
     * The red, green and blue components are stored in sRGB space, and converted
     * to linear space when read, using the standard sRGB to linear equation:
     *
     * Clinear = Csrgb / 12.92                  for Csrgb <= 0.04045
     *         = (Csrgb + 0.055 / 1.055)^2.4    for Csrgb >  0.04045
     *
     * When written the inverse transformation is performed:
     *
     * Csrgb = 12.92 * Clinear                  for Clinear <= 0.0031308
     *       = 1.055 * Clinear^(1/2.4) - 0.055  for Clinear >  0.0031308
     *
     *
     *  The alpha component, if present, is always stored in linear space and
     *  is left unmodified when read or written.
     *
     */
    HAL_PIXEL_FORMAT_sRGB_A_8888        = 0xC,
    HAL_PIXEL_FORMAT_sRGB_X_8888        = 0xD,

    /*
     * 0x100 - 0x1FF
     *
     * This range is reserved for pixel formats that are specific to the HAL
     * implementation.  Implementations can use any value in this range to
     * communicate video pixel formats between their HAL modules.  These formats
     * must not have an alpha channel.  Additionally, an EGLimage created from a
     * gralloc buffer of one of these formats must be supported for use with the
     * GL_OES_EGL_image_external OpenGL ES extension.
     */

    /*
     * Android YUV format:
     *
     * This format is exposed outside of the HAL to software decoders and
     * applications.  EGLImageKHR must support it in conjunction with the
     * OES_EGL_image_external extension.
     *
     * YV12 is a 4:2:0 YCrCb planar format comprised of a WxH Y plane followed
     * by (W/2) x (H/2) Cr and Cb planes.
     *
     * This format assumes
     * - an even width
     * - an even height
     * - a horizontal stride multiple of 16 pixels
     * - a vertical stride equal to the height
     *
     *   y_size = stride * height
     *   c_stride = ALIGN(stride/2, 16)
     *   c_size = c_stride * height/2
     *   size = y_size + c_size * 2
     *   cr_offset = y_size
     *   cb_offset = y_size + c_size
     *
     */
    HAL_PIXEL_FORMAT_YV12   = 0x32315659, // YCrCb 4:2:0 Planar


    /*
     * Android Y8 format:
     *
     * This format is exposed outside of the HAL to the framework.
     * The expected gralloc usage flags are SW_* and HW_CAMERA_*,
     * and no other HW_ flags will be used.
     *
     * Y8 is a YUV planar format comprised of a WxH Y plane,
     * with each pixel being represented by 8 bits.
     *
     * It is equivalent to just the Y plane from YV12.
     *
     * This format assumes
     * - an even width
     * - an even height
     * - a horizontal stride multiple of 16 pixels
     * - a vertical stride equal to the height
     *
     *   size = stride * height
     *
     */
    HAL_PIXEL_FORMAT_Y8     = 0x20203859,

    /*
     * Android Y16 format:
     *
     * This format is exposed outside of the HAL to the framework.
     * The expected gralloc usage flags are SW_* and HW_CAMERA_*,
     * and no other HW_ flags will be used.
     *
     * Y16 is a YUV planar format comprised of a WxH Y plane,
     * with each pixel being represented by 16 bits.
     *
     * It is just like Y8, but has double the bits per pixel (little endian).
     *
     * This format assumes
     * - an even width
     * - an even height
     * - a horizontal stride multiple of 16 pixels
     * - a vertical stride equal to the height
     * - strides are specified in pixels, not in bytes
     *
     *   size = stride * height * 2
     *
     */
    HAL_PIXEL_FORMAT_Y16    = 0x20363159,

    /*
     * Android RAW sensor format:
     *
     * This format is exposed outside of the camera HAL to applications.
     *
     * RAW_SENSOR is a single-channel, 16-bit, little endian  format, typically
     * representing raw Bayer-pattern images from an image sensor, with minimal
     * processing.
     *
     * The exact pixel layout of the data in the buffer is sensor-dependent, and
     * needs to be queried from the camera device.
     *
     * Generally, not all 16 bits are used; more common values are 10 or 12
     * bits. If not all bits are used, the lower-order bits are filled first.
     * All parameters to interpret the raw data (black and white points,
     * color space, etc) must be queried from the camera device.
     *
     * This format assumes
     * - an even width
     * - an even height
     * - a horizontal stride multiple of 16 pixels
     * - a vertical stride equal to the height
     * - strides are specified in pixels, not in bytes
     *
     *   size = stride * height * 2
     *
     * This format must be accepted by the gralloc module when used with the
     * following usage flags:
     *    - GRALLOC_USAGE_HW_CAMERA_*
     *    - GRALLOC_USAGE_SW_*
     *    - GRALLOC_USAGE_RENDERSCRIPT
     */
    HAL_PIXEL_FORMAT_RAW16 = 0x20,
    HAL_PIXEL_FORMAT_RAW_SENSOR = 0x20, // TODO(rubenbrunk): Remove RAW_SENSOR.

    /*
     * Android RAW10 format:
     *
     * This format is exposed outside of the camera HAL to applications.
     *
     * RAW10 is a single-channel, 10-bit per pixel, densely packed, unprocessed
     * format, representing raw Bayer-pattern images coming from an image sensor.
     *
     * In an image buffer with this format, starting from the first pixel, each 4
     * consecutive pixels are packed into 5 bytes (40 bits). Each one of the first
     * 4 bytes contains the top 8 bits of each pixel, The fifth byte contains the
     * 2 least significant bits of the 4 pixels, the exact layout data for each 4
     * consecutive pixels is illustrated below (Pi[j] stands for the jth bit of
     * the ith pixel):
     *
     *          bit 7                                     bit 0
     *          =====|=====|=====|=====|=====|=====|=====|=====|
     * Byte 0: |P0[9]|P0[8]|P0[7]|P0[6]|P0[5]|P0[4]|P0[3]|P0[2]|
     *         |-----|-----|-----|-----|-----|-----|-----|-----|
     * Byte 1: |P1[9]|P1[8]|P1[7]|P1[6]|P1[5]|P1[4]|P1[3]|P1[2]|
     *         |-----|-----|-----|-----|-----|-----|-----|-----|
     * Byte 2: |P2[9]|P2[8]|P2[7]|P2[6]|P2[5]|P2[4]|P2[3]|P2[2]|
     *         |-----|-----|-----|-----|-----|-----|-----|-----|
     * Byte 3: |P3[9]|P3[8]|P3[7]|P3[6]|P3[5]|P3[4]|P3[3]|P3[2]|
     *         |-----|-----|-----|-----|-----|-----|-----|-----|
     * Byte 4: |P3[1]|P3[0]|P2[1]|P2[0]|P1[1]|P1[0]|P0[1]|P0[0]|
     *          ===============================================
     *
     * This format assumes
     * - a width multiple of 4 pixels
     * - an even height
     * - a horizontal stride equal to the width
     * - a vertical stride equal to the height
     * - strides are specified in pixels, not in bytes
     *
     *   size = stride * height * 10 / 8
     *
     * This format must be accepted by the gralloc module when used with the
     * following usage flags:
     *    - GRALLOC_USAGE_HW_CAMERA_*
     *    - GRALLOC_USAGE_SW_*
     *    - GRALLOC_USAGE_RENDERSCRIPT
     */
    HAL_PIXEL_FORMAT_RAW10 = 0x25,

    /*
     * Android opaque RAW format:
     *
     * This format is exposed outside of the camera HAL to applications.
     *
     * RAW_OPAQUE is a format for unprocessed raw image buffers coming from an
     * image sensor. The actual structure of buffers of this format is
     * implementation-dependent.
     *
     * This format must be accepted by the gralloc module when used with the
     * following usage flags:
     *    - GRALLOC_USAGE_HW_CAMERA_*
     *    - GRALLOC_USAGE_SW_*
     *    - GRALLOC_USAGE_RENDERSCRIPT
     */
    HAL_PIXEL_FORMAT_RAW_OPAQUE = 0x24,

    /*
     * Android binary blob graphics buffer format:
     *
     * This format is used to carry task-specific data which does not have a
     * standard image structure. The details of the format are left to the two
     * endpoints.
     *
     * A typical use case is for transporting JPEG-compressed images from the
     * Camera HAL to the framework or to applications.
     *
     * Buffers of this format must have a height of 1, and width equal to their
     * size in bytes.
     */
    HAL_PIXEL_FORMAT_BLOB = 0x21,

    /*
     * Android format indicating that the choice of format is entirely up to the
     * device-specific Gralloc implementation.
     *
     * The Gralloc implementation should examine the usage bits passed in when
     * allocating a buffer with this format, and it should derive the pixel
     * format from those usage flags.  This format will never be used with any
     * of the GRALLOC_USAGE_SW_* usage flags.
     *
     * If a buffer of this format is to be used as an OpenGL ES texture, the
     * framework will assume that sampling the texture will always return an
     * alpha value of 1.0 (i.e. the buffer contains only opaque pixel values).
     *
     */
    HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED = 0x22,

    /*
     * Android flexible YCbCr formats
     *
     * This format allows platforms to use an efficient YCbCr/YCrCb buffer
     * layout, while still describing the buffer layout in a way accessible to
     * the CPU in a device-independent manner.  While called YCbCr, it can be
     * used to describe formats with either chromatic ordering, as well as
     * whole planar or semiplanar layouts.
     *
     * struct android_ycbcr (below) is the the struct used to describe it.
     *
     * This format must be accepted by the gralloc module when
     * USAGE_HW_CAMERA_WRITE and USAGE_SW_READ_* are set.
     *
     * This format is locked for use by gralloc's (*lock_ycbcr) method, and
     * locking with the (*lock) method will return an error.
     */
    HAL_PIXEL_FORMAT_YCbCr_420_888 = 0x23,

    /* Legacy formats (deprecated), used by ImageFormat.java */
    HAL_PIXEL_FORMAT_YCbCr_422_SP       = 0x10, // NV16
    HAL_PIXEL_FORMAT_YCrCb_420_SP       = 0x11, // NV21
    HAL_PIXEL_FORMAT_YCbCr_422_I        = 0x14, // YUY2
};

/*
 * Structure for describing YCbCr formats for consumption by applications.
 * This is used with HAL_PIXEL_FORMAT_YCbCr_*_888.
 *
 * Buffer chroma subsampling is defined in the format.
 * e.g. HAL_PIXEL_FORMAT_YCbCr_420_888 has subsampling 4:2:0.
 *
 * Buffers must have a 8 bit depth.
 *
 * @y, @cb, and @cr point to the first byte of their respective planes.
 *
 * Stride describes the distance in bytes from the first value of one row of
 * the image to the first value of the next row.  It includes the width of the
 * image plus padding.
 * @ystride is the stride of the luma plane.
 * @cstride is the stride of the chroma planes.
 *
 * @chroma_step is the distance in bytes from one chroma pixel value to the
 * next.  This is 2 bytes for semiplanar (because chroma values are interleaved
 * and each chroma value is one byte) and 1 for planar.
 */

struct android_ycbcr {
    void *y;
    void *cb;
    void *cr;
    size_t ystride;
    size_t cstride;
    size_t chroma_step;

    /** reserved for future use, set to 0 by gralloc's (*lock_ycbcr)() */
    uint32_t reserved[8];
};

/**
 * Transformation definitions
 *
 * IMPORTANT NOTE:
 * HAL_TRANSFORM_ROT_90 is applied CLOCKWISE and AFTER HAL_TRANSFORM_FLIP_{H|V}.
 *
 */

enum {
    /* flip source image horizontally (around the vertical axis) */
    HAL_TRANSFORM_FLIP_H    = 0x01,
    /* flip source image vertically (around the horizontal axis)*/
    HAL_TRANSFORM_FLIP_V    = 0x02,
    /* rotate source image 90 degrees clockwise */
    HAL_TRANSFORM_ROT_90    = 0x04,
    /* rotate source image 180 degrees */
    HAL_TRANSFORM_ROT_180   = 0x03,
    /* rotate source image 270 degrees clockwise */
    HAL_TRANSFORM_ROT_270   = 0x07,
    /* don't use. see system/window.h */
    HAL_TRANSFORM_RESERVED  = 0x08,
};

/**
 * Colorspace Definitions
 * ======================
 *
 * Colorspace is the definition of how pixel values should be interpreted.
 * It includes primaries (including white point) and the transfer
 * characteristic function, which describes both gamma curve and numeric
 * range (within the bit depth).
 */

enum {
    /*
     * Arbitrary colorspace with manually defined characteristics.
     * Colorspace definition must be communicated separately.
     *
     * This is used when specifying primaries, transfer characteristics,
     * etc. separately.
     *
     * A typical use case is in video encoding parameters (e.g. for H.264),
     * where a colorspace can have separately defined primaries, transfer
     * characteristics, etc.
     */
    HAL_COLORSPACE_ARBITRARY = 0x1,

    /*
     * YCbCr Colorspaces
     * -----------------
     *
     * Primaries are given using (x,y) coordinates in the CIE 1931 definition
     * of x and y specified by ISO 11664-1.
     *
     * Transfer characteristics are the opto-electronic transfer characteristic
     * at the source as a function of linear optical intensity (luminance).
     */

    /*
     * JPEG File Interchange Format (JFIF)
     *
     * Same model as BT.601-625, but all values (Y, Cb, Cr) range from 0 to 255
     *
     * Transfer characteristic curve:
     *  E = 1.099 * L ^ 0.45 - 0.099, 1.00 >= L >= 0.018
     *  E = 4.500 L, 0.018 > L >= 0
     *      L - luminance of image 0 <= L <= 1 for conventional colorimetry
     *      E - corresponding electrical signal
     *
     * Primaries:       x       y
     *  green           0.290   0.600
     *  blue            0.150   0.060
     *  red             0.640   0.330
     *  white (D65)     0.3127  0.3290
     */
    HAL_COLORSPACE_JFIF = 0x101,

    /*
     * ITU-R Recommendation 601 (BT.601) - 625-line
     *
     * Standard-definition television, 625 Lines (PAL)
     *
     * For 8-bit-depth formats:
     * Luma (Y) samples should range from 16 to 235, inclusive
     * Chroma (Cb, Cr) samples should range from 16 to 240, inclusive
     *
     * For 10-bit-depth formats:
     * Luma (Y) samples should range from 64 to 940, inclusive
     * Chroma (Cb, Cr) samples should range from 64 to 960, inclusive
     *
     * Transfer characteristic curve:
     *  E = 1.099 * L ^ 0.45 - 0.099, 1.00 >= L >= 0.018
     *  E = 4.500 L, 0.018 > L >= 0
     *      L - luminance of image 0 <= L <= 1 for conventional colorimetry
     *      E - corresponding electrical signal
     *
     * Primaries:       x       y
     *  green           0.290   0.600
     *  blue            0.150   0.060
     *  red             0.640   0.330
     *  white (D65)     0.3127  0.3290
     */
    HAL_COLORSPACE_BT601_625 = 0x102,

    /*
     * ITU-R Recommendation 601 (BT.601) - 525-line
     *
     * Standard-definition television, 525 Lines (NTSC)
     *
     * For 8-bit-depth formats:
     * Luma (Y) samples should range from 16 to 235, inclusive
     * Chroma (Cb, Cr) samples should range from 16 to 240, inclusive
     *
     * For 10-bit-depth formats:
     * Luma (Y) samples should range from 64 to 940, inclusive
     * Chroma (Cb, Cr) samples should range from 64 to 960, inclusive
     *
     * Transfer characteristic curve:
     *  E = 1.099 * L ^ 0.45 - 0.099, 1.00 >= L >= 0.018
     *  E = 4.500 L, 0.018 > L >= 0
     *      L - luminance of image 0 <= L <= 1 for conventional colorimetry
     *      E - corresponding electrical signal
     *
     * Primaries:       x       y
     *  green           0.310   0.595
     *  blue            0.155   0.070
     *  red             0.630   0.340
     *  white (D65)     0.3127  0.3290
     */
    HAL_COLORSPACE_BT601_525 = 0x103,

    /*
     * ITU-R Recommendation 709 (BT.709)
     *
     * High-definition television
     *
     * For 8-bit-depth formats:
     * Luma (Y) samples should range from 16 to 235, inclusive
     * Chroma (Cb, Cr) samples should range from 16 to 240, inclusive
     *
     * For 10-bit-depth formats:
     * Luma (Y) samples should range from 64 to 940, inclusive
     * Chroma (Cb, Cr) samples should range from 64 to 960, inclusive
     *
     * Primaries:       x       y
     *  green           0.300   0.600
     *  blue            0.150   0.060
     *  red             0.640   0.330
     *  white (D65)     0.3127  0.3290
     */
    HAL_COLORSPACE_BT709 = 0x104,
};

#ifdef __cplusplus
}
#endif

#endif /* SYSTEM_CORE_INCLUDE_ANDROID_GRAPHICS_H */
