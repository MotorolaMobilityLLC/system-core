/*
 * Copyright (c) 2012 Linux Foundation. All rights reserved.
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

#ifndef SYSTEM_CORE_INCLUDE_ANDROID_GESTURES_H
#define SYSTEM_CORE_INCLUDE_ANDROID_GESTURES_H

__BEGIN_DECLS


/** msgType in notifyCallback and dataCallback functions */
enum {
    GESTURE_MSG_ERROR = 0x0001,            // notifyCallback
    GESTURE_MSG_RESULT = 0x0002,           // dataCallback
    GESTURE_MSG_ALL_MSGS = 0xFFFF
};

/** gesture device fatal errors */
enum {
    GESTURE_ERROR_UNKNOWN = 1,
    GESTURE_ERROR_SERVER_DIED = 100
};

/** 3D vector, z = 0 for 2D, values from -1.0 to 1.0.
 *  normalized to maximum image axis.
 */
typedef struct {
    float x;
    float y;
    float z;
    float error;
} gesture_vector_t;

/** 3D region of interest, z = 0 for 2D
 */
typedef struct {
    int32_t           num_of_points;
    gesture_vector_t* pPoints ;
} gesture_roi_t;

/** Extended result, byte buffer
 */
typedef struct {
    int32_t  len;  // in bytes
    void*    buf;  // byte array
} gesture_extended_result_t;

/** gesture event, includes poses as well as motion gestures.*/
typedef struct {
    /** outcome struct version, initially 0 */
    int version;

    /** gesture type, defined externally as engagement, hand
     *  pose, swipe, etc. */
    int type;

    /** gesture subtype, value depends on type */
    int subtype;

    /** detection camera frame time in microseconds */
    uint64_t timestamp;

    /** identifies this outcome as the same object over time */
    int id;

    /** confidence: 1.0 = 100% */
    float confidence;

    /** velocity of gesture */
    float velocity;

    /** region for pose, start position for motion */
    gesture_roi_t location;

    /** extended information for later expansion */
    gesture_extended_result_t extendinfo;
} gesture_event_t;

typedef struct gesture_result {
    /**
     * The number of detected faces in the frame.
     */
    int32_t number_of_events;

    /**
     * An array of the gesture events. The length is
     * number_of_events.
     */
    gesture_event_t* events;
} gesture_result_t;

__END_DECLS

#endif /* SYSTEM_CORE_INCLUDE_ANDROID_GESTURES_H */
