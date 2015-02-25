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

#ifndef ADB_IO_H
#define ADB_IO_H

#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Reads exactly len bytes from fd into buf.
 *
 * Returns false if there is an error or if EOF was reached before len bytes
 * were read. If EOF was found, errno will be set to 0.
 *
 * If this function fails, the contents of buf are undefined.
 */
bool ReadFdExactly(int fd, void *buf, size_t len);

/*
 * Writes exactly len bytes from buf to fd.
 *
 * Returns false if there is an error or if the fd was closed before the write
 * completed. If the other end of the fd (such as in a socket, pipe, or fifo),
 * is closed, errno will be set to 0.
 */
bool WriteFdExactly(int fd, const void *buf, size_t len);

/* Same as WriteFdExactly, but with an implicit len = strlen(buf). */
bool WriteStringFully(int fd, const char* str);

#ifdef __cplusplus
}
#endif

#endif /* ADB_IO_H */
