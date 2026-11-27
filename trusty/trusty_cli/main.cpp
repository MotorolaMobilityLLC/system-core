/*
 * Copyright (C) 2025 The Android Open Source Project
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
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include <trusty/tipc.h>

#include "interface/trusty_cli/trusty_cli-str.h"
#include "interface/trusty_cli/trusty_cli.h"
// #include "trusty_cli.h"

// Trusty ipc device mapped to linux
#define TRUSTY_IPC_DEVNAME "/dev/trusty-ipc-dev0"

struct trusty_cli_params {
    char command[TRUSTY_CLI_MAX_SIZE];
};

static const char* usage =
        "Usage: %s [options] [commands]\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -c, --cmd             command to execute.\n"
        "\n"
        "commands: [optional] strings to pass to the cli service. "
        "  If empty, shell starts in the interactive mode\n"
        "\n";

static const char* _sopts = "hc:";
// clang-format off
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"cmd", required_argument, 0, 'c'},
        {0, 0, 0, 0},
};
// clang-format on

static void print_usage_and_exit(const char* prog, int code) {
    fprintf(stderr, usage, prog);
    exit(code);
}

int parse_options(int argc, char* argv[], struct trusty_cli_params* params) {
    if (argc < 2) {
        return 0;
    }

    int c;
    for (;;) {
        c = getopt_long(argc, argv, _sopts, _lopts, NULL);
        if (c == -1) break; /* done */

        switch (c) {
            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS);
                break;
            case 'c':
                strncpy(params->command, optarg, sizeof(params->command));
                break;
            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE);
                break;
        }
    }

    int oidx = optind;
    size_t cmd_len = strlen(params->command);
    if (cmd_len) {
        return argc - oidx;
    }

    // cat the rest of args to the command string:
    for (; oidx < argc; ++oidx) {
        if (cmd_len) {
            params->command[cmd_len] = ' ';
            ++cmd_len;
        }

        size_t to_copy = strlen(argv[oidx]);
        size_t buf_size = sizeof(params->command) - cmd_len - 1;
        if (buf_size < to_copy) {
            to_copy = buf_size;
        }

        memcpy(params->command + cmd_len, argv[oidx], to_copy);
        cmd_len += to_copy;
        if (cmd_len >= sizeof(params->command) - 1) {
            break;
        }
    }

    params->command[cmd_len] = 0;
    return argc - oidx;
}

void print_trusty_cli_message(struct trusty_cli_message_header* msg, char* buffer) {
    printf("{");
    printf("type: %s; ", (msg->cmd) ? "response" : "request");
    printf("cmd: %s (%u); ", trusty_cli_cmd_to_str(static_cast<trusty_cli_cmd_id_t>(msg->cmd)),
           msg->cmd);
    printf("status: %s (%u); ",
           trusty_cli_status_to_str(static_cast<trusty_cli_status_t>(msg->status)), msg->status);
    printf("payload: %s;", msg->payload_size ? buffer : "[none]");
    printf("}");
}

int send_request(int fd, enum trusty_cli_cmd cmd, char* arg) {
    // Fill in a request
    size_t arg_len = arg ? strlen(arg) : 0;
    struct trusty_cli_message_header req = {
            .cmd = cmd,
            .status = TRUSTY_CLI_STATUS_REQUEST,
            .payload_size = (uint16_t)arg_len,
    };
    struct iovec req_iovs[2] = {
            {
                    .iov_base = &req,
                    .iov_len = sizeof(req),
            },
            {
                    .iov_base = arg,
                    .iov_len = arg_len,
            },
    };

    printf("===== Sending request: ");
    print_trusty_cli_message(&req, arg);
    printf(" =====\n");

    // send message
    int rc = tipc_send(fd, req_iovs, 2, NULL, 0);
    if (rc != sizeof(req) + arg_len) {
        printf("failed to send tipc request: %d\n", rc);
        return rc < 0 ? rc : -1;
    }

    return 0;
}

/**
 * @return negative error code in case of errors or command execution status otherwise
 */
int process_command(int fd, enum trusty_cli_cmd cmd, char* arg) {
    int rc = send_request(fd, cmd, arg);
    if (rc < 0) {
        return rc;
    }

    // create response structs:
    struct trusty_cli_message_header resp = {0};
    char buffer[TRUSTY_CLI_MAX_SIZE] = {0};
    struct iovec resp_iovs[2] = {
            {
                    .iov_base = &resp,
                    .iov_len = sizeof(resp),
            },
            {
                    .iov_base = buffer,
                    .iov_len = sizeof(buffer) - 1,
            },
    };

    for (;;) {
        rc = readv(fd, resp_iovs, 2);
        if (rc < 0) {
            printf("Failed to read response from trusty cli: %d (errno = %s)\n", rc,
                   strerror(errno));
            return rc;
        }

        int bytes_read = rc - sizeof(resp);
        if (bytes_read < 0 || bytes_read > sizeof(buffer) - 1) {
            printf("invalid number of bytes read: %d\n", rc);
            return -1;
        }

        buffer[bytes_read] = 0;

        if (resp.cmd != cmd) {
            printf("received a response to cmd different to request: %s [%d] <> %s [%d]\n",
                   trusty_cli_cmd_to_str(cmd), cmd,
                   trusty_cli_cmd_to_str(static_cast<trusty_cli_cmd_id_t>(resp.cmd)), resp.cmd);
            return -1;
        }

        if (resp.status == TRUSTY_CLI_STATUS_INTERIM) {
            // received a frame with payload with more messages that will follow:
            printf("%s", buffer);
            continue;
        }

        // received a response message with non-interim status.
        printf("===== Received a final response: %s [%d] =====\n",
               trusty_cli_status_to_str(static_cast<trusty_cli_status_t>(resp.status)),
               resp.status);
        if (bytes_read) {
            printf("===== \t%s =====\n", buffer);
        }

        return (int)resp.status;
    }
}

int main(int argc, char* argv[]) {
    int rc = 0;
    bool loop = true;
    int fd = -1;

    struct trusty_cli_params params = {};

    rc = parse_options(argc, argv, &params);
    if (rc < 0) {
        printf("Failed to parse options: %d\n", rc);
        exit(EXIT_FAILURE);
    }

    if (rc > 0) {
        printf("Too many options provided: %d\n", rc);
        printf("Following options did not fit:");
        int i;
        for (i = rc; i < argc; ++i) {
            printf(" %s", argv[i]);
        }

        printf("\n");
        exit(EXIT_FAILURE);
    }

    // connect to trusty cli service
    fd = tipc_connect(TRUSTY_IPC_DEVNAME, TRUSTY_CLI_PORT);
    if (fd < 0) {
        printf("failed to connect to '%s' app: %s\n", TRUSTY_CLI_PORT, strerror(-fd));
        return fd;
    }

    if (params.command[0] != 0) {
        loop = false;
    }

    do {
        if (loop) {
            // get command to process:
            size_t size = sizeof(params.command);
            char* ptr = params.command;
            printf("> ");
            rc = getline(&ptr, &size, stdin);
            if (rc < 0) {
                printf("Failed to get line from the input (errno = %s), terminating...\n",
                       strerror(errno));
                goto err;
            }

            if (strncmp(params.command, "stop", 4) == 0 ||
                strncmp(params.command, "quit", 4) == 0) {
                loop = false;
                break;
            }

            while (rc && (params.command[rc - 1] == '\n' || params.command[rc - 1] == '\t' ||
                          params.command[rc - 1] == '\r' || params.command[rc - 1] == ' ')) {
                --rc;
                params.command[rc] = 0;
            }

            if (rc == 0) {
                continue;
            }
        }

        // exec command:
        rc = process_command(fd, TRUSTY_CLI_CMD_EXEC_CONSOLE, params.command);
        if (rc < 0) {
            goto err;
        }
    } while (loop);

err:
    tipc_close(fd);

    return rc >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}