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

#ifndef UTILS_BITSET_H
#define UTILS_BITSET_H

#include <stdint.h>
#include <utils/TypeHelpers.h>

/*
 * Contains some bit manipulation helpers.
 */

namespace android {

// A simple set of 32 bits that can be individually marked or cleared.
struct BitSet32 {
    uint32_t value;

    inline BitSet32() : value(0) { }
    explicit inline BitSet32(uint32_t value) : value(value) { }

    // Gets the value associated with a particular bit index.
    static inline uint32_t valueForBit(uint32_t n) { return 0x80000000 >> n; }

    // Clears the bit set.
    inline void clear() { value = 0; }

    // Returns the number of marked bits in the set.
    inline uint32_t count() const { return __builtin_popcount(value); }

    // Returns true if the bit set does not contain any marked bits.
    inline bool isEmpty() const { return ! value; }

    // Returns true if the bit set does not contain any unmarked bits.
    inline bool isFull() const { return value == 0xffffffff; }

    // Returns true if the specified bit is marked.
    inline bool hasBit(uint32_t n) const { return value & valueForBit(n); }

    // Marks the specified bit.
    inline void markBit(uint32_t n) { value |= valueForBit(n); }

    // Clears the specified bit.
    inline void clearBit(uint32_t n) { value &= ~ valueForBit(n); }

    // Finds the first marked bit in the set.
    // Result is undefined if all bits are unmarked.
    inline uint32_t firstMarkedBit() const { return __builtin_clz(value); }

    // Finds the first unmarked bit in the set.
    // Result is undefined if all bits are marked.
    inline uint32_t firstUnmarkedBit() const { return __builtin_clz(~ value); }

    // Finds the last marked bit in the set.
    // Result is undefined if all bits are unmarked.
    inline uint32_t lastMarkedBit() const { return 31 - __builtin_ctz(value); }

    // Finds the first marked bit in the set and clears it.  Returns the bit index.
    // Result is undefined if all bits are unmarked.
    inline uint32_t clearFirstMarkedBit() {
        uint32_t n = firstMarkedBit();
        clearBit(n);
        return n;
    }

    // Finds the first unmarked bit in the set and marks it.  Returns the bit index.
    // Result is undefined if all bits are marked.
    inline uint32_t markFirstUnmarkedBit() {
        uint32_t n = firstUnmarkedBit();
        markBit(n);
        return n;
    }

    // Finds the last marked bit in the set and clears it.  Returns the bit index.
    // Result is undefined if all bits are unmarked.
    inline uint32_t clearLastMarkedBit() {
        uint32_t n = lastMarkedBit();
        clearBit(n);
        return n;
    }

    // Gets the index of the specified bit in the set, which is the number of
    // marked bits that appear before the specified bit.
    inline uint32_t getIndexOfBit(uint32_t n) const {
        return __builtin_popcount(value & ~(0xffffffffUL >> n));
    }

    inline bool operator== (const BitSet32& other) const { return value == other.value; }
    inline bool operator!= (const BitSet32& other) const { return value != other.value; }
};

ANDROID_BASIC_TYPES_TRAITS(BitSet32)

} // namespace android

#endif // UTILS_BITSET_H
