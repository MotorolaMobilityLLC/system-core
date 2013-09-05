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

#include <stdio.h>
#include <unistd.h>
#include <cutils/klog.h>
#include <getopt.h>
#include <stdlib.h>

#include "debug.h"
#include "trigger.h"
#include "socket_client.h"

unsigned int debug_level = DEBUG;

void commands_init();
void usb_init();
void config_init();
int transport_socket_init();

int main(int argc, char **argv)
{
    int socket_client = 0;
    int c;

    klog_init();
    klog_set_level(6);

    const struct option longopts[] = {
        {"socket", no_argument, 0, 'S'},
        {0, 0, 0, 0}
    };

    while (1) {
        c = getopt_long(argc, argv, "S", longopts, NULL);
        /* Alphabetical cases */
        if (c < 0)
            break;
        switch (c) {
        case 'S':
            socket_client = 1;
            break;
        case '?':
            return 1;
        default:
            return 0;
        }
    }

    (void)argc;
    (void)argv;

    klog_init();
    klog_set_level(6);

    if (socket_client) {
        run_socket_client();
    }
    else {
        config_init();
        load_trigger();
        commands_init();
        usb_init();
        if (!transport_socket_init())
            exit(1);
        while (1) {
            sleep(1);
        }
    }
    return 0;
}
