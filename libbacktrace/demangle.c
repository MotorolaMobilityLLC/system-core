/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <sys/types.h>

#include "demangle.h"

extern char* __cxa_demangle (const char* mangled, char* buf, size_t* len,
                             int* status);

char* demangle_symbol_name(const char* name) {
#if defined(__APPLE__)
  // Mac OS' __cxa_demangle demangles "f" as "float"; last tested on 10.7.
  if (name != NULL && name[0] != '_') {
    return NULL;
  }
#endif
  // __cxa_demangle handles NULL by returning NULL
  return __cxa_demangle(name, 0, 0, 0);
}
