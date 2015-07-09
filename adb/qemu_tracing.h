/*
 * Copyright (C) 2015 The Android Open Source Project
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

/*
 * Implements ADB tracing inside the emulator.
 */

#ifndef __QEMU_TRACING_H
#define __QEMU_TRACING_H

#include "base/macros.h"

/* Initializes connection with the adb-debug qemud service in the emulator. */
int adb_qemu_trace_init(void);
void adb_qemu_trace(const char* fmt, ...) ATTRIBUTE_FORMAT(1, 2);

#endif /* __QEMU_TRACING_H */
