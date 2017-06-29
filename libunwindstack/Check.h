/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _LIBUNWINDSTACK_ERROR_H
#define _LIBUNWINDSTACK_ERROR_H

#include <stdlib.h>

#include "Log.h"

#define CHECK(assertion)                                   \
  if (__builtin_expect(!(assertion), false)) {             \
    log(0, "%s:%d: %s\n", __FILE__, __LINE__, #assertion); \
    abort();                                               \
  }

#endif  // _LIBUNWINDSTACK_ERROR_H
