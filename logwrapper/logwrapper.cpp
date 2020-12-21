/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cutils/klog.h>
#include <log/log.h>
#include <logwrap/logwrap.h>

void fatal(const char* msg) {
    fprintf(stderr, "%s", msg);
    ALOG(LOG_ERROR, "logwrapper", "%s", msg);
    exit(-1);
}

void usage() {
    fatal("Usage: logwrapper [-a] [-d] [-k] BINARY [ARGS ...]\n"
          "\n"
          "Forks and executes BINARY ARGS, redirecting stdout and stderr to\n"
          "the Android logging system. Tag is set to BINARY, priority is\n"
          "always LOG_INFO.\n"
          "\n"
          "-a: Causes logwrapper to do abbreviated logging.\n"
          "    This logs up to the first 4K and last 4K of the command\n"
          "    being run, and logs the output when the command exits\n"
          "-d: Causes logwrapper to SIGSEGV when BINARY terminates\n"
          "    fault address is set to the status of wait()\n"
          "-k: Causes logwrapper to log to the kernel log instead of\n"
          "    the Android system log\n");
}
#if defined(JOURNEY_DEBUG_ENHANCED) || defined (JOURNEY_FEATURE_LOG_SYSTEM)
extern char *log_tag;
#endif
int main(int argc, char* argv[]) {
    int seg_fault_on_exit = 0;
    int log_target = LOG_ALOG;
    bool abbreviated = false;
    int ch;
    int status = 0xAAAA;
    int rc;

#if defined(JOURNEY_DEBUG_ENHANCED) || defined (JOURNEY_FEATURE_LOG_SYSTEM)
    while ((ch = getopt(argc, argv, "adkt:")) != -1) {
#else
    while ((ch = getopt(argc, argv, "adk")) != -1) {
#endif
        switch (ch) {
            case 'a':
                abbreviated = true;
                break;
            case 'd':
                seg_fault_on_exit = 1;
                break;
            case 'k':
                log_target = LOG_KLOG;
                klog_set_level(6);
                break;
#if defined(JOURNEY_DEBUG_ENHANCED) || defined (JOURNEY_FEATURE_LOG_SYSTEM)
            case 't':
                log_tag = optarg;
                break;
#endif

            case '?':
            default:
                usage();
        }
    }
    argc -= optind;
    argv += optind;

    if (argc < 1) {
        usage();
    }

    rc = logwrap_fork_execvp(argc, &argv[0], &status, true, log_target, abbreviated, nullptr);
    if (!rc) {
        if (WIFEXITED(status))
            rc = WEXITSTATUS(status);
        else
            rc = -ECHILD;
    }

    if (seg_fault_on_exit) {
        uintptr_t fault_address = (uintptr_t)status;
        *(int*)fault_address = 0;  // causes SIGSEGV with fault_address = status
    }

    return rc;
}
