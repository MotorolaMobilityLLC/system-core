/*
 * Copyright (C) 2017 The Android Open Source Project
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

namespace android {
namespace init {

static constexpr const char kInitContext[] = "u:r:init:s0";
static constexpr const char kVendorContext[] = "u:r:vendor_init:s0";
static constexpr const char kTestContext[] = "test-test-test";

}  // namespace init
}  // namespace android

#ifndef MICRODROID
#include "subcontext_android.h"
#else
#include "subcontext_microdroid.h"
#endif
