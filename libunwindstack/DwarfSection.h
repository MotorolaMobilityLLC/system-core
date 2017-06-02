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

#ifndef _LIBUNWINDSTACK_DWARF_SECTION_H
#define _LIBUNWINDSTACK_DWARF_SECTION_H

#include <stdint.h>

#include <iterator>
#include <unordered_map>

#include "DwarfError.h"
#include "DwarfLocation.h"
#include "DwarfMemory.h"
#include "DwarfStructs.h"

// Forward declarations.
class Memory;
class Regs;

class DwarfSection {
 public:
  DwarfSection(Memory* memory) : memory_(memory) {}
  virtual ~DwarfSection() = default;

  class iterator : public std::iterator<std::bidirectional_iterator_tag, DwarfFde*> {
   public:
    iterator(DwarfSection* section, size_t index) : section_(section), index_(index) {}

    iterator& operator++() {
      index_++;
      return *this;
    }
    iterator& operator++(int increment) {
      index_ += increment;
      return *this;
    }
    iterator& operator--() {
      index_--;
      return *this;
    }
    iterator& operator--(int decrement) {
      index_ -= decrement;
      return *this;
    }

    bool operator==(const iterator& rhs) { return this->index_ == rhs.index_; }
    bool operator!=(const iterator& rhs) { return this->index_ != rhs.index_; }

    const DwarfFde* operator*() { return section_->GetFdeFromIndex(index_); }

   private:
    DwarfSection* section_ = nullptr;
    size_t index_ = 0;
  };

  iterator begin() { return iterator(this, 0); }
  iterator end() { return iterator(this, fde_count_); }

  DwarfError last_error() { return last_error_; }

  virtual bool Init(uint64_t offset, uint64_t size) = 0;

  virtual bool Eval(const DwarfCie*, Memory*, const dwarf_loc_regs_t&, Regs*) = 0;

  virtual bool GetFdeOffsetFromPc(uint64_t pc, uint64_t* fde_offset) = 0;

  virtual bool Log(uint8_t indent, uint64_t pc, uint64_t load_bias, const DwarfFde* fde) = 0;

  virtual const DwarfFde* GetFdeFromIndex(size_t index) = 0;

  const DwarfFde* GetFdeFromPc(uint64_t pc);

  virtual const DwarfFde* GetFdeFromOffset(uint64_t fde_offset) = 0;

  virtual bool GetCfaLocationInfo(uint64_t pc, const DwarfFde* fde, dwarf_loc_regs_t* loc_regs) = 0;

  virtual bool IsCie32(uint32_t value32) = 0;

  virtual bool IsCie64(uint64_t value64) = 0;

  virtual uint64_t GetCieOffsetFromFde32(uint32_t pointer) = 0;

  virtual uint64_t GetCieOffsetFromFde64(uint64_t pointer) = 0;

  virtual uint64_t AdjustPcFromFde(uint64_t pc) = 0;

  bool Step(uint64_t pc, Regs* regs, Memory* process_memory);

 protected:
  DwarfMemory memory_;
  DwarfError last_error_ = DWARF_ERROR_NONE;

  uint64_t fde_count_;
  std::unordered_map<uint64_t, DwarfFde> fde_entries_;
  std::unordered_map<uint64_t, DwarfCie> cie_entries_;
  std::unordered_map<uint64_t, dwarf_loc_regs_t> cie_loc_regs_;
};

template <typename AddressType>
class DwarfSectionImpl : public DwarfSection {
 public:
  DwarfSectionImpl(Memory* memory) : DwarfSection(memory) {}
  virtual ~DwarfSectionImpl() = default;

  bool Eval(const DwarfCie* cie, Memory* regular_memory, const dwarf_loc_regs_t& loc_regs,
            Regs* regs) override;

  const DwarfCie* GetCie(uint64_t offset);
  bool FillInCie(DwarfCie* cie);

  const DwarfFde* GetFdeFromOffset(uint64_t offset) override;
  bool FillInFde(DwarfFde* fde);

  bool GetCfaLocationInfo(uint64_t pc, const DwarfFde* fde, dwarf_loc_regs_t* loc_regs) override;

  bool Log(uint8_t indent, uint64_t pc, uint64_t load_bias, const DwarfFde* fde) override;

 protected:
  bool EvalExpression(const DwarfLocation& loc, uint8_t version, Memory* regular_memory,
                      AddressType* value);
};

#endif  // _LIBUNWINDSTACK_DWARF_SECTION_H
