/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _DEBUGGERD_OPEN_FILES_LIST_H
#define _DEBUGGERD_OPEN_FILES_LIST_H

#include <sys/types.h>

#include <string>
#include <utility>
#include <vector>

#include "utility.h"

typedef std::vector<std::pair<int, std::string>> OpenFilesList;

/* Populates the given list with open files for the given process. */
void populate_open_files_list(pid_t pid, OpenFilesList* list);

/* Dumps the open files list to the log. */
void dump_open_files_list_to_log(const OpenFilesList& files, log_t* log, const char* prefix);

#endif // _DEBUGGERD_OPEN_FILES_LIST_H
