// This file is autogenerated by hidl-gen. Do not edit manually.
// Source: android.hardware.graphics.common@1.1
// Root: android.hardware:hardware/interfaces

#ifndef HIDL_GENERATED_ANDROID_HARDWARE_GRAPHICS_COMMON_V1_1_EXPORTED_CONSTANTS_H_
#define HIDL_GENERATED_ANDROID_HARDWARE_GRAPHICS_COMMON_V1_1_EXPORTED_CONSTANTS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HAL_PIXEL_FORMAT_DEPTH_16 = 48,
    HAL_PIXEL_FORMAT_DEPTH_24 = 49,
    HAL_PIXEL_FORMAT_DEPTH_24_STENCIL_8 = 50,
    HAL_PIXEL_FORMAT_DEPTH_32F = 51,
    HAL_PIXEL_FORMAT_DEPTH_32F_STENCIL_8 = 52,
    HAL_PIXEL_FORMAT_STENCIL_8 = 53,
    HAL_PIXEL_FORMAT_YCBCR_P010 = 54,
} android_pixel_format_v1_1_t;

typedef enum {
    HAL_DATASPACE_BT2020_ITU =
        281411584,  // ((STANDARD_BT2020 | TRANSFER_SMPTE_170M) | RANGE_LIMITED)
    HAL_DATASPACE_BT2020_ITU_PQ =
        298188800,  // ((STANDARD_BT2020 | TRANSFER_ST2084) | RANGE_LIMITED)
} android_dataspace_v1_1_t;

#ifdef __cplusplus
}
#endif

#endif  // HIDL_GENERATED_ANDROID_HARDWARE_GRAPHICS_COMMON_V1_1_EXPORTED_CONSTANTS_H_
