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

#ifndef __ADB_LISTENERS_H
#define __ADB_LISTENERS_H

#include "adb.h"

#ifdef __cplusplus
extern "C" {
#endif

// error/status codes for install_listener.
typedef enum {
  INSTALL_STATUS_OK = 0,
  INSTALL_STATUS_INTERNAL_ERROR = -1,
  INSTALL_STATUS_CANNOT_BIND = -2,
  INSTALL_STATUS_CANNOT_REBIND = -3,
} install_status_t;

extern alistener listener_list;

void listener_disconnect(void*  _l, atransport*  t);
void listener_event_func(int _fd, unsigned ev, void *_l);
void ss_listener_event_func(int _fd, unsigned ev, void *_l);

install_status_t install_listener(const char *local_name,
                                  const char *connect_to,
                                  atransport* transport,
                                  int no_rebind);

int format_listeners(char* buf, size_t buflen);

int remove_listener(const char *local_name, atransport* transport);
void remove_all_listeners(void);

#ifdef __cplusplus
}
#endif

#endif /* __ADB_LISTENERS_H */
