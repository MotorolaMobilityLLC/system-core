/*
 * Copyright (c) 2012-2017 Motorola Mobility LLC.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vector>

#include "fastboot_driver.h"
#include "util.h"

using namespace fastboot;

#define MAX_FILE_NAME_LENGTH	36
#define DEFAULT_FILE_EXTENTION	".img"

static std::string next_arg(std::vector<std::string>* args) {
    if (args->empty()) die("expected argument");
    std::string result = args->front();
    args->erase(args->begin());
    return result;
}

RetCode oem_partition_handler(fastboot::FastBootDriver* fb, const std::string& cmd, std::vector<std::string>* args)
{
    RetCode ret;
    int is_dump = 0;

    if (!fb) die("FastBootDriver is required");
    if (args->empty()) die("empty oem command");

    if (args->size() >= 2 && (args->at(1) == std::string("dump") || args->at(1) == std::string("moto-dump"))) {
        if (args->size() < 3) die("Invalid command: fastboot oem partition dump <partition> [size] [offset]");
        /* translate "dump" to "moto-dump" */
        args->at(1) = std::string("moto-dump");
        is_dump = 1;
    }

    std::string command(cmd);
    std::string partition;
    if (is_dump)
        partition = args->at(2);
    while (!args->empty()) {
        command += " " + next_arg(args);
    }

    ret = fb->RawCommand(command, "Sending \"partition\" command");
    if (!ret && is_dump) {
        char *file_name = (char *)calloc(MAX_FILE_NAME_LENGTH, sizeof(char));
        if (!file_name) die("no memory");

        strncpy(file_name, partition.c_str(), MAX_FILE_NAME_LENGTH - strlen(DEFAULT_FILE_EXTENTION) - 1);
        strcat(file_name, DEFAULT_FILE_EXTENTION);
        fprintf(stderr, "Dumping partition %s to %s", partition.c_str(), file_name);

        ret = fb->Dump(reinterpret_cast<const char *>(file_name));
    }

    return ret;
}

RetCode oem_ramdump_handler(fastboot::FastBootDriver* fb, const std::string& cmd, std::vector<std::string>* args)
{
    RetCode ret;
    int is_pull = 0;

    if (!fb) die("FastBootDriver is required");
    if (args->empty()) die("empty oem command");

    if (args->size() >= 2 && (args->at(1) == std::string("pull") || args->at(1) == std::string("moto-pull"))) {
        /* translate "pull" to "moto-pull" */
        args->at(1) = std::string("moto-pull");
        is_pull = 1;
    }

    std::string command(cmd);
    while (!args->empty()) {
        command += " " + next_arg(args);
    }

    ret = fb->RawCommand(command, "Sending \"ramdump\" command");
    if (!ret && is_pull) {
        fprintf(stderr, "Ready to receive ramdumps");

        ret = fb->RamDump();
    }

    return ret;
}
