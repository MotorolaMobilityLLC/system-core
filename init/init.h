/*
 * Copyright (C) 2007 The Android Open Source Project
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

#pragma once

#include <sys/types.h>

#include <string>

#include "action.h"
#include "action_manager.h"
#include "parser.h"
#include "service_list.h"

namespace android {
namespace init {

Parser CreateParser(ActionManager& action_manager, ServiceList& service_list);
Parser CreateServiceOnlyParser(ServiceList& service_list, bool from_apex);

bool start_waiting_for_property(const char *name, const char *value);

void DumpState();

void ResetWaitForProp();

void SendLoadPersistentPropertiesMessage();
void SendStopSendingMessagesMessage();
void SendStartSendingMessagesMessage();

void PropertyChanged(const std::string& name, const std::string& value);
bool HandleControlMessage(const std::string& msg, const std::string& name, pid_t from_pid);

int SecondStageMain(int argc, char** argv);

}  // namespace init
}  // namespace android
