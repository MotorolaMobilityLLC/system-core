/* system/core/include/logwrap/logwrap.h
 *
 * Copyright 2013, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __LIBS_LOGWRAP_H
#define __LIBS_LOGWRAP_H

#include <stdbool.h>

__BEGIN_DECLS

/*
 * Run a command while logging its stdout and stderr
 *
 * WARNING: while this function is running it will clear all SIGCHLD handlers
 * if you rely on SIGCHLD in the caller there is a chance zombies will be
 * created if you're not calling waitpid after calling this. This function will
 * log a warning when it clears SIGCHLD for processes other than the child it
 * created.
 *
 * Arguments:
 *   argc:   the number of elements in argv
 *   argv:   an array of strings containing the command to be executed and its
 *           arguments as separate strings. argv does not need to be
 *           NULL-terminated
 *   status: the equivalent child status as populated by wait(status). This
 *           value is only valid when logwrap successfully completes. If NULL
 *           the return value of the child will be the function's return value.
 *   ignore_int_quit: set to true if you want to completely ignore SIGINT and
 *           SIGQUIT while logwrap is running. This may force the end-user to
 *           send a signal twice to signal the caller (once for the child, and
 *           once for the caller)
 *   logwrap: when true, log messages from the child
 *
 * Return value:
 *   0 when logwrap successfully run the child process and captured its status
 *   -1 when an internal error occurred
 *   -ECHILD if status is NULL and the child didn't exit properly
 *   the return value of the child if it exited properly and status is NULL
 *
 */
int android_fork_execvp(int argc, char* argv[], int *status, bool ignore_int_quit,
        bool logwrap);

__END_DECLS

#endif /* __LIBS_LOGWRAP_H */
