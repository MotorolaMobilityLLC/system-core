/*
 * Copyright (C) 2005-2017 The Android Open Source Project
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

#ifndef _LIBS_LOGCAT_H /* header boilerplate */
#define _LIBS_LOGCAT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE
#ifndef __ANDROID_API__
#define __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE 1
#elif __ANDROID_API__ > 24 /* > Nougat */
#define __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE 1
#else
#define __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE 0
#endif
#endif

#if __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE

/* For managing an in-process logcat function, rather than forking/execing
 *
 * It also serves as the basis for the logcat command.
 *
 * The following C API allows a logcat instance to be created, run
 * to completion, and then release all the associated resources.
 */

/*
 * The opaque context
 */
#ifndef __android_logcat_context_defined /* typedef boilerplate */
#define __android_logcat_context_defined
typedef struct android_logcat_context_internal* android_logcat_context;
#endif

/* Creates a context associated with this logcat instance
 *
 * Returns a pointer to the context, or a NULL on error.
 */
android_logcat_context create_android_logcat();

/* Collects and outputs the logcat data to output and error file descriptors
 *
 * Will block, performed in-thread and in-process
 *
 * The output file descriptor variable, if greater than or equal to 0, is
 * where the output (ie: stdout) will be sent. The file descriptor is closed
 * on android_logcat_destroy which terminates the instance, or when an -f flag
 * (output redirect to a file) is present in the command.  The error file
 * descriptor variable, if greater than or equal to 0, is where the error
 * stream (ie: stderr) will be sent, also closed on android_logcat_destroy.
 * The error file descriptor can be set to equal to the output file descriptor,
 * which will mix output and error stream content, and will defer closure of
 * the file descriptor on -f flag redirection.  Negative values for the file
 * descriptors will use stdout and stderr FILE references respectively
 * internally, and will not close the references as noted above.
 *
 * Return value is 0 for success, non-zero for errors.
 */
int android_logcat_run_command(android_logcat_context ctx, int output, int error,
                               int argc, char* const* argv, char* const* envp);

/* Finished with context
 *
 * Free up all associated resources.
 *
 * Return value is the result of the android_logcat_run_command, or
 * non-zero for any errors.
 */
int android_logcat_destroy(android_logcat_context* ctx);

#endif /* __ANDROID_USE_LIBLOG_LOGCAT_INTERFACE */

#ifdef __cplusplus
}
#endif

#endif /* _LIBS_LOGCAT_H */
