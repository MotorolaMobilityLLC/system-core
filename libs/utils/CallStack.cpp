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

#define LOG_TAG "CallStack"

#include <string.h>

#include <utils/Log.h>
#include <utils/Errors.h>
#include <utils/CallStack.h>
#include <corkscrew/backtrace.h>

/*****************************************************************************/
namespace android {

CallStack::CallStack() :
        mCount(0) {
}

CallStack::CallStack(const CallStack& rhs) :
        mCount(rhs.mCount) {
    if (mCount) {
        memcpy(mStack, rhs.mStack, mCount * sizeof(backtrace_frame_t));
    }
}

CallStack::~CallStack() {
}

CallStack& CallStack::operator = (const CallStack& rhs) {
    mCount = rhs.mCount;
    if (mCount) {
        memcpy(mStack, rhs.mStack, mCount * sizeof(backtrace_frame_t));
    }
    return *this;
}

bool CallStack::operator == (const CallStack& rhs) const {
    if (mCount != rhs.mCount)
        return false;
    return !mCount || memcmp(mStack, rhs.mStack, mCount * sizeof(backtrace_frame_t)) == 0;
}

bool CallStack::operator != (const CallStack& rhs) const {
    return !operator == (rhs);
}

bool CallStack::operator < (const CallStack& rhs) const {
    if (mCount != rhs.mCount)
        return mCount < rhs.mCount;
    return memcmp(mStack, rhs.mStack, mCount * sizeof(backtrace_frame_t)) < 0;
}

bool CallStack::operator >= (const CallStack& rhs) const {
    return !operator < (rhs);
}

bool CallStack::operator > (const CallStack& rhs) const {
    if (mCount != rhs.mCount)
        return mCount > rhs.mCount;
    return memcmp(mStack, rhs.mStack, mCount * sizeof(backtrace_frame_t)) > 0;
}

bool CallStack::operator <= (const CallStack& rhs) const {
    return !operator > (rhs);
}

const void* CallStack::operator [] (int index) const {
    if (index >= int(mCount))
        return 0;
    return reinterpret_cast<const void*>(mStack[index].absolute_pc);
}

void CallStack::clear() {
    mCount = 0;
}

void CallStack::update(int32_t ignoreDepth, int32_t maxDepth) {
    if (maxDepth > MAX_DEPTH) {
        maxDepth = MAX_DEPTH;
    }
    ssize_t count = unwind_backtrace(mStack, ignoreDepth + 1, maxDepth);
    mCount = count > 0 ? count : 0;
}

void CallStack::dump(const char* prefix) const {
    backtrace_symbol_t symbols[mCount];

    get_backtrace_symbols(mStack, mCount, symbols);
    for (size_t i = 0; i < mCount; i++) {
        const backtrace_frame_t& frame = mStack[i];
        const backtrace_symbol_t& symbol = symbols[i];
        const char* mapName = symbol.map_info ? symbol.map_info->name : "<unknown>";
        const char* symbolName = symbol.demangled_name ? symbol.demangled_name : symbol.name;
        if (symbolName) {
            LOGD("%s#%02d  pc %08x  %s (%s)\n", prefix,
                    int(i), uint32_t(symbol.relative_pc), mapName, symbolName);
        } else {
            LOGD("%s#%02d  pc %08x  %s\n", prefix,
                    int(i), uint32_t(symbol.relative_pc), mapName);
        }
    }
    free_backtrace_symbols(symbols, mCount);
}

String8 CallStack::toString(const char* prefix) const {
    String8 str;
    backtrace_symbol_t symbols[mCount];

    get_backtrace_symbols(mStack, mCount, symbols);
    for (size_t i = 0; i < mCount; i++) {
        const backtrace_frame_t& frame = mStack[i];
        const backtrace_symbol_t& symbol = symbols[i];
        const char* mapName = symbol.map_info ? symbol.map_info->name : "<unknown>";
        const char* symbolName = symbol.demangled_name ? symbol.demangled_name : symbol.name;
        if (symbolName) {
            str.appendFormat("%s#%02d  pc %08x  %s (%s)\n", prefix,
                    int(i), uint32_t(symbol.relative_pc), mapName, symbolName);
        } else {
            str.appendFormat("%s#%02d  pc %08x  %s\n", prefix,
                    int(i), uint32_t(symbol.relative_pc), mapName);
        }
    }
    free_backtrace_symbols(symbols, mCount);
    return str;
}

}; // namespace android
