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

#include "fastboot.h"

static std::string next_arg(std::vector<std::string>* args) {
    if (args->empty()) die("expected argument");
    std::string result = args->front();
    args->erase(args->begin());
    return result;
}

int oem_dump_handler(const std::string& cmd, std::vector<std::string>* args)
{
    if (args->empty()) die("empty oem command");
    if (args->size() < 2) die("Invalid command: fastboot oem dump <partition> [size] [offset]");

    std::string command(cmd);
    std::string partition = args->at(1);
    while (!args->empty()) {
        command += " " + next_arg(args);
    }

    fb_queue_command(command.c_str(), "Sending command");
    fb_queue_dump(partition);

    return 0;
}

int oem_ramdump_handler(const std::string& cmd, std::vector<std::string>* args)
{
    if (args->empty()) die("empty oem command");

    int is_pull = 0;

    if (args->size() >= 2 && (args->at(1) == std::string("pull") || args->at(1) == std::string("moto-pull"))) {
        /* translate "pull" to "moto-pull" */
        args->at(1) = std::string("moto-pull");
        is_pull = 1;
    }

    std::string command(cmd);
    while (!args->empty()) {
        command += " " + next_arg(args);
    }

    fb_queue_command(command.c_str(),"Sending command");
    if (is_pull) {
        fb_queue_ramdump();
    }

    return 0;
}
