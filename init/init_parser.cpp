/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#include "action.h"
#include "init_parser.h"
#include "log.h"
#include "parser.h"
#include "service.h"
#include "util.h"

#include <android-base/stringprintf.h>

Parser::Parser() {
}

Parser& Parser::GetInstance() {
    static Parser instance;
    return instance;
}

void Parser::AddSectionParser(const std::string& name,
                              std::unique_ptr<SectionParser> parser) {
    section_parsers_[name] = std::move(parser);
}

void Parser::ParseData(const std::string& filename, const std::string& data) {
    //TODO: Use a parser with const input and remove this copy
    std::vector<char> data_copy(data.begin(), data.end());
    data_copy.push_back('\0');

    parse_state state;
    state.filename = filename.c_str();
    state.line = 0;
    state.ptr = &data_copy[0];
    state.nexttoken = 0;

    SectionParser* section_parser = nullptr;
    std::vector<std::string> args;

    for (;;) {
        switch (next_token(&state)) {
        case T_EOF:
            if (section_parser) {
                section_parser->EndSection();
            }
            return;
        case T_NEWLINE:
            state.line++;
            if (args.empty()) {
                break;
            }
            if (section_parsers_.count(args[0])) {
                if (section_parser) {
                    section_parser->EndSection();
                }
                section_parser = section_parsers_[args[0]].get();
                std::string ret_err;
                if (!section_parser->ParseSection(args, &ret_err)) {
                    parse_error(&state, "%s\n", ret_err.c_str());
                    section_parser = nullptr;
                }
            } else if (section_parser) {
                std::string ret_err;
                if (!section_parser->ParseLineSection(args, state.filename,
                                                      state.line, &ret_err)) {
                    parse_error(&state, "%s\n", ret_err.c_str());
                }
            }
            args.clear();
            break;
        case T_TEXT:
            args.emplace_back(state.text);
            break;
        }
    }
}

bool Parser::ParseConfigFile(const std::string& path) {
    LOG(INFO) << "Parsing file " << path << "...";
    Timer t;
    std::string data;
    if (!read_file(path.c_str(), &data)) {
        return false;
    }

    data.push_back('\n'); // TODO: fix parse_config.
    ParseData(path, data);
    for (const auto& sp : section_parsers_) {
        sp.second->EndFile(path);
    }

    // Turning this on and letting the INFO logging be discarded adds 0.2s to
    // Nexus 9 boot time, so it's disabled by default.
    if (false) DumpState();

    LOG(VERBOSE) << "(Parsing " << path << " took " << t.duration() << "s.)";
    return true;
}

bool Parser::ParseConfigDir(const std::string& path) {
    LOG(INFO) << "Parsing directory " << path << "...";
    std::unique_ptr<DIR, int(*)(DIR*)> config_dir(opendir(path.c_str()), closedir);
    if (!config_dir) {
        PLOG(ERROR) << "Could not import directory '" << path << "'";
        return false;
    }
    dirent* current_file;
    while ((current_file = readdir(config_dir.get()))) {
        std::string current_path =
            android::base::StringPrintf("%s/%s", path.c_str(), current_file->d_name);
        // Ignore directories and only process regular files.
        if (current_file->d_type == DT_REG) {
            if (!ParseConfigFile(current_path)) {
                LOG(ERROR) << "could not import file '" << current_path << "'";
            }
        }
    }
    return true;
}

bool Parser::ParseConfig(const std::string& path) {
    if (is_dir(path.c_str())) {
        return ParseConfigDir(path);
    }
    return ParseConfigFile(path);
}

void Parser::DumpState() const {
    ServiceManager::GetInstance().DumpState();
    ActionManager::GetInstance().DumpState();
}
