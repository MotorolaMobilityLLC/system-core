/*
 * Copyright 2024, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "libdebuggerd/utility_host.h"

#include <ctype.h>
#include <sys/prctl.h>

#include <charconv>
#include <limits>
#include <string>

#include <android-base/stringprintf.h>

using android::base::StringPrintf;

#ifndef PR_MTE_TAG_SHIFT
#define PR_MTE_TAG_SHIFT 3
#endif

#ifndef PR_MTE_TAG_MASK
#define PR_MTE_TAG_MASK (0xffffUL << PR_MTE_TAG_SHIFT)
#endif

#ifndef PR_MTE_TCF_ASYNC
#define PR_MTE_TCF_ASYNC (1UL << 2)
#endif

#ifndef PR_MTE_TCF_SYNC
#define PR_MTE_TCF_SYNC (1UL << 1)
#endif

#ifndef PR_PAC_APIAKEY
#define PR_PAC_APIAKEY (1UL << 0)
#endif

#ifndef PR_PAC_APIBKEY
#define PR_PAC_APIBKEY (1UL << 1)
#endif

#ifndef PR_PAC_APDAKEY
#define PR_PAC_APDAKEY (1UL << 2)
#endif

#ifndef PR_PAC_APDBKEY
#define PR_PAC_APDBKEY (1UL << 3)
#endif

#ifndef PR_PAC_APGAKEY
#define PR_PAC_APGAKEY (1UL << 4)
#endif

#ifndef PR_TAGGED_ADDR_ENABLE
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
#endif

#define DESCRIBE_FLAG(flag) \
  if (value & flag) {       \
    desc += ", ";           \
    desc += #flag;          \
    value &= ~flag;         \
  }

static std::string describe_end(long value, std::string& desc) {
  if (value) {
    desc += StringPrintf(", unknown 0x%lx", value);
  }
  return desc.empty() ? "" : " (" + desc.substr(2) + ")";
}

std::string describe_tagged_addr_ctrl(long value) {
  std::string desc;
  DESCRIBE_FLAG(PR_TAGGED_ADDR_ENABLE);
  DESCRIBE_FLAG(PR_MTE_TCF_SYNC);
  DESCRIBE_FLAG(PR_MTE_TCF_ASYNC);
  if (value & PR_MTE_TAG_MASK) {
    desc += StringPrintf(", mask 0x%04lx", (value & PR_MTE_TAG_MASK) >> PR_MTE_TAG_SHIFT);
    value &= ~PR_MTE_TAG_MASK;
  }
  return describe_end(value, desc);
}

std::string describe_pac_enabled_keys(long value) {
  std::string desc;
  DESCRIBE_FLAG(PR_PAC_APIAKEY);
  DESCRIBE_FLAG(PR_PAC_APIBKEY);
  DESCRIBE_FLAG(PR_PAC_APDAKEY);
  DESCRIBE_FLAG(PR_PAC_APDBKEY);
  DESCRIBE_FLAG(PR_PAC_APGAKEY);
  return describe_end(value, desc);
}

static std::string describe_ec(uint8_t ec) {
  // ESR exception encodings:
  //   https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-
  //   https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/ESR-EL2--Exception-Syndrome-Register--EL2-
  //   https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/ESR-EL3--Exception-Syndrome-Register--EL3-
  // Kernel header:
  //    https://android.googlesource.com/kernel/common/+/android-mainline/arch/arm64/include/asm/esr.h
  switch (ec) {
    case 0x00:
      return "Unknown";
    case 0x01:
      return "WFx";
    case 0x03:
      return "MCR/MRC";
    case 0x04:
      return "MCRR/MRRC";
    case 0x05:
      return "MCR/MRC";
    case 0x06:
      return "LDC/STC";
    case 0x07:
      return "SIMD/SME/SVE";
    case 0x08:  // EL2 only
      return "VMRS";
    case 0x09:  // EL2 and above
    case 0x1C:  // EL1 and above
      return "PAC";
    case 0x0C:
      return "MRRC";
    case 0x0D:
      return "BTI";
    case 0x0E:
      return "Illegal Instruction";
    case 0x11:
      return "SVC32";
    case 0x12:  // EL2 only
      return "HVC32";
    case 0x13:  // EL2 and above
      return "SMC32";
    case 0x15:
      return "SVC64";
    case 0x16:  // EL2 and above
      return "HVC64";
    case 0x17:  // EL2 and above
      return "SMC64";
    case 0x18:
      return "SYS64";
    case 0x19:
      return "SVE";
    case 0x1A:  // EL2 only
      return "ERET";
    case 0x1D:
      return "SME";
    case 0x1F:  // EL3 only
      return "Implementation Defined";
    case 0x20:
    case 0x21:
      return "Instruction Abort";
    case 0x22:
      return "PC Alignment";
    case 0x24:
    case 0x25:
      return "Data Abort";
    case 0x26:
      return "SP Alignment";
    case 0x27:
      return "MOPS";
    case 0x28:
    case 0x2C:
      return "FP Exception";
    case 0x2D:
      return "GCS";
    case 0x2F:
      return "SERROR";
    case 0x30:
    case 0x31:
    case 0x38:
      return "BKPT";
    case 0x32:
    case 0x33:
      return "SW Step";
    case 0x34:
    case 0x35:
      return "Watchpoint";
    case 0x3A:  // EL2 only
      return "Vector Catch";
    case 0x3C:
      return "BRK";
    default:
      return "Unrecognized";
  }
}

std::string describe_esr(uint64_t value) {
  // EC part of the esr.
  uint8_t ec = (value >> 26) & 0x3f;
  return android::base::StringPrintf("(%s Exception 0x%02x)", describe_ec(ec).c_str(), ec);
}

static std::string oct_encode(const std::string& data, bool (*should_encode_func)(int)) {
  std::string oct_encoded;
  oct_encoded.reserve(data.size());

  // N.B. the unsigned here is very important, otherwise e.g. \255 would render as
  // \-123 (and overflow our buffer).
  for (unsigned char c : data) {
    if (should_encode_func(c)) {
      std::string oct_digits("\\\0\0\0", 4);
      // char is encodable in 3 oct digits
      static_assert(std::numeric_limits<unsigned char>::max() <= 8 * 8 * 8);
      auto [ptr, ec] = std::to_chars(oct_digits.data() + 1, oct_digits.data() + 4, c, 8);
      oct_digits.resize(ptr - oct_digits.data());
      oct_encoded += oct_digits;
    } else {
      oct_encoded += c;
    }
  }
  return oct_encoded;
}

std::string oct_encode_non_ascii_printable(const std::string& data) {
  return oct_encode(data, [](int c) { return !isgraph(c) && !isspace(c); });
}

std::string oct_encode_non_printable(const std::string& data) {
  return oct_encode(data, [](int c) { return !isprint(c); });
}
